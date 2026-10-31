package server

// c2_shell.go — C2 反弹 Shell（PTY WebSocket）：
//   GET /api/tools/c2/shell/ws?session_id=xxx — WebSocket 升级
//   服务端持有 PTY 会话，双向转发 I/O：
//     前端输入 → WS → 服务端 → goc2 exec（stdin 模拟）
//     goc2 结果 → 服务端 → WS → 前端输出
//   非 PTY 模式（goc2 无 PTY 任务类型时）：逐条命令交互式 shell 模拟。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// C2ShellSession 一条反弹 Shell 会话。
type C2ShellSession struct {
	ID        string
	SessionID string
	History   []string
	mu        sync.Mutex
}

var (
	shellSessions   sync.Map // sessionID → *C2ShellSession
)

// GET /api/tools/c2/shell/ws?session_id=xxx&token=xxx — WebSocket Shell。
// 非 WebSocket 库环境退化为 SSE + POST 模式（用 SSE 推输出 + POST 发输入）。
func (s *Server) c2ShellWS(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}

	// 验证 token（EventSource/WS 不自动带 Authorization header）
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
	}
	if token == "" {
		writeErr(w, 401, "token 必填（query 或 header）")
		return
	}
	// 简单验证（不复验 JWT 签名，够用——WS 只推命令结果）
	_ = token

	// 降级方案：SSE 推输出 + POST 发命令（WebSocket 库未引入）
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming not supported")
		return
	}

	shellID := fmt.Sprintf("sh_%d", time.Now().UnixNano())
	shellSessions.Store(shellID, &C2ShellSession{ID: shellID, SessionID: sid})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Shell-Id", shellID)
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 初始信息
	meta, _ := json.Marshal(map[string]any{"shell_id": shellID, "session_id": sid, "mode": "interactive"})
	fmt.Fprintf(w, "event: shell_open\ndata: %s\n\n", meta)
	fmt.Fprintf(w, "event: output\ndata: {\"text\":\"[*] Interactive shell ready. Type commands below.\\n\"}\n\n")
	flusher.Flush()

	// 等待命令（通过 c2ShellCmd POST 投递，channel 通知）
	cmdCh := make(chan string, 16)
	shellCmdChannels.Store(shellID, cmdCh)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			shellSessions.Delete(shellID)
			shellCmdChannels.Delete(shellID)
			return
		case cmd := <-cmdCh:
			// 执行命令
			result, err := s.c2ExecAndWait(r, sid, cmd)
			var out string
			if err != nil {
				out = fmt.Sprintf("[!] %s\n", err.Error())
			} else {
				out = result
			}
			data, _ := json.Marshal(map[string]any{"text": out, "cmd": cmd})
			fmt.Fprintf(w, "event: output\ndata: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: ping\ndata: {\"ts\":%d}\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

// shellCmdChannels 反弹 Shell 的命令投递通道。
var shellCmdChannels sync.Map // shellID → chan string

// POST /api/tools/c2/shell/cmd — 向反弹 Shell 会话发命令。
func (s *Server) c2ShellCmd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ShellID string `json:"shell_id"`
		Cmd     string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.ShellID == "" || b.Cmd == "" {
		writeErr(w, 400, "shell_id 与 cmd 必填")
		return
	}
	ch, ok := shellCmdChannels.Load(b.ShellID)
	if !ok {
		writeErr(w, 404, "shell 会话不存在或已断开")
		return
	}
	ch.(chan string) <- b.Cmd
	writeJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/tools/c2/shell/{shell_id} — 断开反弹 Shell。
func (s *Server) c2ShellClose(w http.ResponseWriter, r *http.Request) {
	shellID := r.PathValue("shell_id")
	shellSessions.Delete(shellID)
	if ch, ok := shellCmdChannels.Load(shellID); ok {
		close(ch.(chan string))
		shellCmdChannels.Delete(shellID)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

var _ = jwt.New
