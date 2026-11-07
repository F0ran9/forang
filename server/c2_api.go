package server

// c2_api.go — C2 指挥台 REST（UI 直连版，复用 c2client 包对接 goc2-server）：
//   GET  /api/tools/c2/status              可达性 + 当前配置（token 脱敏）
//   GET  /api/tools/c2/clients             beacon 会话列表（透传）
//   POST /api/tools/c2/exec                下发命令 → 返回 task_id（前端轮询）
//   GET  /api/tools/c2/tasks?session_id=   任务与结果查询
//   GET  /api/tools/c2/listeners           监听器列表
// 与 agent 工具 c2_beacons/c2_exec 同一内核。

import (
	"time"
	"path/filepath"
	"os"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/c2client"
)

func c2Client() *c2client.Client { return c2client.New(c2client.CurrentOrDefault()) }

// GET /api/tools/c2/status
func (s *Server) c2StatusAPI(w http.ResponseWriter, r *http.Request) {
	cfg := c2client.CurrentOrDefault()
	cli := c2Client()
	clients, err := cli.ListClients(r.Context(), nil)
	masked := ""
	if len(cfg.Token) > 6 {
		masked = cfg.Token[:6] + "…"
	} else if cfg.Token != "" {
		masked = "已设置"
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"url": cfg.BaseURL, "token_masked": masked,
		"reachable": err == nil, "beacons": len(clients),
		"error": errString(err),
	}})
}

// GET /api/tools/c2/clients
func (s *Server) c2ClientsAPI(w http.ResponseWriter, r *http.Request) {
	clients, err := c2Client().ListClients(r.Context(), nil)
	if err != nil {
		writeErr(w, 502, "goc2 不可达: "+err.Error())
		return
	}
	go s.c2CheckNewSessions(clients) // 新 beacon 上线 → 钉钉/飞书推送
	writeJSON(w, 200, map[string]any{"data": clients})
}

// POST /api/tools/c2/exec {session_id, cmd} → {task_id}
func (s *Server) c2ExecAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		Cmd       string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.SessionID) == "" || strings.TrimSpace(b.Cmd) == "" {
		writeErr(w, 400, "session_id 与 cmd 必填")
		return
	}
	taskID, err := c2Client().EnqueueTask(r.Context(), b.SessionID, "exec", map[string]any{"cmd": b.Cmd})
	if err != nil {
		writeErr(w, 502, "任务下发失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"task_id": taskID}})
}

// GET /api/tools/c2/tasks?session_id=&task_id= — 任务列表/单任务结果。
func (s *Server) c2TasksAPI(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	params := url.Values{}
	if tid := r.URL.Query().Get("task_id"); tid != "" {
		params.Set("taskId", tid)
	}
	tasks, err := c2Client().ListTasks(r.Context(), sid, params)
	if err != nil {
		writeErr(w, 502, "查询失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": tasks})
}

// GET /api/tools/c2/listeners
func (s *Server) c2ListenersAPI(w http.ResponseWriter, r *http.Request) {
	listeners, err := c2Client().ListListeners(r.Context())
	if err != nil {
		writeErr(w, 502, "goc2 不可达: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": listeners})
}

// c2PayloadFormats 支持的载荷格式 → 文件扩展（与 goc2 /generate 对齐）。
var c2PayloadFormats = map[string]string{
	"amd64_exe": "exe", "x86_exe": "exe", "amd64_exe_g": "exe",
	"amd64_dll": "dll", "linux_elf": "bin", "linux_elf_g": "bin",
	"linux_arm64": "bin", "darwin_amd64": "bin", "darwin_arm64": "bin",
	"shellcode": "bin",
}

// c2DownloadGet GET /api/tools/c2/download/{name} — 载荷直链下载。
// 企业管理浏览器忽略 blob URL 的 download 属性（文件名变 UUID）——直链由服务端
// 发 Content-Disposition，浏览器原生处理文件名，万无一失。文件来自生成时落盘
// 的 evidence/c2-payload/（生成端点写），10 分钟后自动过期（TTL 清理）。
func (s *Server) c2DownloadGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.PathValue("name"), "/")
	if name == "" || strings.Contains(name, "..") || strings.Contains(name, "/") {
		writeErr(w, 400, "bad name")
		return
	}
	p := filepath.Join(s.m.dir, "evidence", "c2-payload", name)
	st, err := os.Stat(p)
	if err != nil {
		writeErr(w, 404, "文件不存在或已过期（10 分钟 TTL），请重新生成")
		return
	}
	// TTL：10 分钟
	if time.Since(st.ModTime()) > 10*time.Minute {
		_ = os.Remove(p)
		writeErr(w, 410, "文件已过期（10 分钟 TTL），请重新生成")
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write(data)
}

// saveC2Payload 生成产物落盘（供直链下载）。
func (s *Server) saveC2Payload(name string, data []byte) string {
	dir := filepath.Join(s.m.dir, "evidence", "c2-payload")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
	return name
}

// POST /api/tools/c2/generate — CS/vshell 风格一键载荷：真实 beacon 二进制，
// 连接参数编译时内嵌，下载即部署（不再只出配置 JSON 让用户自己编译）。
func (s *Server) c2GenerateAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ListenerID string `json:"listener_id"`
		Format     string `json:"format"`
		Server     string `json:"server"` // 可选：回连地址覆盖（跨网段部署时指定 LAN/公网地址）
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	// server 缺省时取请求 Host（用户访问平台的 IP——物理机可达）。
	// goc2 默认用请求来源 IP（FORANG 服务器的 Docker 网桥 172.25.0.1）做 trailer，
	// 物理机不可达——必须显式传。
	if strings.TrimSpace(b.Server) == "" {
		if h := strings.SplitN(r.Host, ":", 2)[0]; h != "" && h != "0.0.0.0" {
			b.Server = h
		}
	}
	if strings.TrimSpace(b.ListenerID) == "" {
		writeErr(w, 400, "listener_id 必填")
		return
	}
	ext, ok := c2PayloadFormats[b.Format]
	if !ok {
		writeErr(w, 400, "format 非法（支持 amd64_exe/x86_exe/amd64_exe_g/amd64_dll/linux_elf/linux_elf_g/linux_arm64/darwin_amd64/darwin_arm64/shellcode）")
		return
	}
	raw, meta, err := c2Client().GeneratePayload(r.Context(), b.ListenerID, b.Format, b.Server)
	if err != nil {
		writeErr(w, 502, "goc2 生成失败: "+err.Error())
		return
	}
	name, _ := meta["filename"].(string)
	if name == "" {
		short := strings.TrimPrefix(b.ListenerID, "ls_")
		if len(short) > 8 {
			short = short[:8]
		}
		name = "agent_" + short + "." + ext
	}
	if srv, _ := meta["server"].(string); srv != "" {
		w.Header().Set("X-Agent-Server", srv) // 前端展示内嵌回连地址
	}
	// 落盘供直链下载（企业管理浏览器 blob download 属性失效的兜底）
	_ = s.saveC2Payload(name, raw)
	w.Header().Set("X-Download-Url", "/api/tools/c2/download/"+name) // 前端直链
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write(raw)
}

// PUT /api/tools/c2/clients/{id}/notes — 会话备注（CS 备注）。
func (s *Server) c2NotesAPI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "bad id")
		return
	}
	var b struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if err := c2Client().UpdateNotes(r.Context(), id, truncateStr(b.Notes, 500)); err != nil {
		writeErr(w, 502, "更新备注失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/tools/c2/task — 通用任务下发（CS 功能面）：body {session_id, type, args}。
// type: exec / download / upload / sleep / 自定义；args 原样透传 goc2。
func (s *Server) c2TaskAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string         `json:"session_id"`
		Type      string         `json:"type"`
		Args      map[string]any `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.SessionID == "" || b.Type == "" {
		writeErr(w, 400, "session_id 与 type 必填")
		return
	}
	payload, err := c2Client().Request(r.Context(), "POST",
		"/clients/"+b.SessionID+"/tasks", nil,
		map[string]any{"type": b.Type, "args": b.Args})
	if err != nil {
		writeErr(w, 502, "任务下发失败: "+err.Error())
		return
	}
	var id string
	if d, ok := payload["data"].(map[string]any); ok {
		id, _ = d["taskId"].(string)
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"task_id": id}})
}

// DELETE /api/tools/c2/clients/{id} — 下线会话（CS Remove）。
func (s *Server) c2RemoveAPI(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, 400, "bad id")
		return
	}
	if err := c2Client().DeleteClient(r.Context(), id); err != nil {
		writeErr(w, 502, "下线失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
