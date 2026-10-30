package server

// c2_api.go — C2 指挥台 REST（UI 直连版，复用 c2client 包对接 goc2-server）：
//   GET  /api/tools/c2/status              可达性 + 当前配置（token 脱敏）
//   GET  /api/tools/c2/clients             beacon 会话列表（透传）
//   POST /api/tools/c2/exec                下发命令 → 返回 task_id（前端轮询）
//   GET  /api/tools/c2/tasks?session_id=   任务与结果查询
//   GET  /api/tools/c2/listeners           监听器列表
// 与 agent 工具 c2_beacons/c2_exec 同一内核。

import (
	"encoding/json"
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
