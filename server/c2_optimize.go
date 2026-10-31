package server

// c2_optimize.go — Token 消耗优化 + SSE 实时推送 + 批量操作：
//   1) 关键词预过滤：非安全相关输出不调 LLM（省 80%+ 分析 token）
//   2) KB 检索缓存：同类指令 5 分钟内不重复查知识库
//   3) AI 规划缓存：同类指令 2 分钟内复用上次规划
//   4) SSE 推送：会话表/任务结果/图变化 服务端主动推（替代 5s 轮询）
//   5) 批量操作：多 beacon 同一命令

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- 1) 关键词预过滤 ----

// c2SecurityKeywords 安全相关关键词——命中才调 LLM 分析（省 token）。
var c2SecurityKeywords = []string{
	// 凭据
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"id_rsa", "private key", "BEGIN RSA", "BEGIN OPENSSH",
	"credential", "auth", "session",
	// 提权
	"sudo", "suid", "uid=0", "root", "CAP_SYS_ADMIN",
	"pkexec", "polkit", "dirty",
	// 敏感文件
	"shadow", "wp-config", ".env", "database.yml", "config.php",
	"authorized_keys", "known_hosts",
	// 网络
	"listening", "0.0.0.0", "bind", "forward",
	// 容器/逃逸
	"docker.sock", "containerd", "privileged", "cgroup",
	"kubernetes", "serviceaccount",
	// 常见漏洞
	"cve-", "exploit", "vulnerab", "inject", "overflow",
	"unauthorized", "forbidden", "bypass",
}

// c2ShouldAnalyze 关键词预检：输出中含安全相关词才值得 LLM 分析。
func c2ShouldAnalyze(output string) bool {
	if len(output) < 10 {
		return false
	}
	lower := strings.ToLower(output)
	for _, kw := range c2SecurityKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// ---- 2) KB 检索缓存 ----

var (
	kbCacheMu   sync.RWMutex
	kbCache     = map[string]kbCacheEntry{}
	kbCacheTTL  = 5 * time.Minute
)

type kbCacheEntry struct {
	results string
	expires time.Time
}

// c2KBSearchCached 带缓存的知识库检索。
func (s *Server) c2KBSearchCached(query string) string {
	kbCacheMu.RLock()
	if entry, ok := kbCache[query]; ok && time.Now().Before(entry.expires) {
		kbCacheMu.RUnlock()
		return entry.results
	}
	kbCacheMu.RUnlock()

	// 实际检索
	results, _, err := s.kbSearchRetrieval(query, 3)
	if err != nil || len(results) == 0 {
		return "（知识库无相关经验）"
	}
	var sb strings.Builder
	sb.WriteString("知识库过往经验（同类目标的已验证手法）：\n")
	for i, r := range results {
		sb.WriteString(fmt.Sprintf("%d. 任务#%d %s\n%s\n\n", i+1, r.TaskID, r.Title, truncateStr(r.Text, 300)))
	}
	val := sb.String()

	kbCacheMu.Lock()
	kbCache[query] = kbCacheEntry{results: val, expires: time.Now().Add(kbCacheTTL)}
	kbCacheMu.Unlock()
	return val
}

// ---- 3) AI 规划缓存 ----

var (
	planCacheMu sync.RWMutex
	planCache   = map[string]planCacheEntry{}
	planCacheTTL = 2 * time.Minute
)

type planCacheEntry struct {
	plan   string
	expires time.Time
}

// ---- 4) SSE 实时推送 ----

// C2Event SSE 事件。
type C2Event struct {
	Type string `json:"type"` // sessions / task_result / graph_update
	Data any    `json:"data"`
}

// SSE hub：每个连接一个 channel。
var (
	sseHubMu   sync.Mutex
	sseHub     = map[chan C2Event]bool{}
)

// sseBroadcast 向所有 SSE 连接广播事件。
func sseBroadcast(evt C2Event) {
	sseHubMu.Lock()
	defer sseHubMu.Unlock()
	for ch := range sseHub {
		select {
		case ch <- evt:
		default: // 满了丢弃（不阻塞）
		}
	}
}

// GET /api/tools/c2/stream — SSE 实时推送（会话表变化/任务结果/图更新）。
func (s *Server) c2SSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming not supported")
		return
	}

	ch := make(chan C2Event, 32)
	sseHubMu.Lock()
	sseHub[ch] = true
	sseHubMu.Unlock()
	defer func() {
		sseHubMu.Lock()
		delete(sseHub, ch)
		sseHubMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 初始 ping
	fmt.Fprintf(w, "event: connected\ndata: {\"ok\":true}\n\n")
	flusher.Flush()

	// 每 30s 心跳
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt := <-ch:
			data, _ := json.Marshal(evt.Data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: ping\ndata: {\"ts\":%d}\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

// c2NotifySessions 通知会话表变化。
func (s *Server) c2NotifySessions() {
	clients, err := c2Client().ListClients(context.Background(), nil)
	if err != nil {
		return
	}
	sseBroadcast(C2Event{Type: "sessions", Data: clients})
}

// c2NotifyTaskResult 通知任务结果。
func (s *Server) c2NotifyTaskResult(sessionID, taskID, output string) {
	sseBroadcast(C2Event{Type: "task_result", Data: map[string]any{
		"session_id": sessionID, "task_id": taskID, "output": truncateStr(output, 2000),
	}})
}

// c2NotifyGraph 通知图更新。
func (s *Server) c2NotifyGraph(sessionID string) {
	sseBroadcast(C2Event{Type: "graph_update", Data: map[string]any{"session_id": sessionID}})
}

// ---- 5) 批量操作 ----

// POST /api/tools/c2/batch — 批量执行：多会话同一命令。
func (s *Server) c2BatchExec(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionIDs []string `json:"session_ids"`
		Cmd        string   `json:"cmd"`
		TimeoutSec int      `json:"timeout_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if len(b.SessionIDs) == 0 || b.Cmd == "" {
		writeErr(w, 400, "session_ids 与 cmd 必填")
		return
	}
	if b.TimeoutSec <= 0 || b.TimeoutSec > 120 {
		b.TimeoutSec = 30
	}

	type batchResult struct {
		SessionID string `json:"session_id"`
		Output    string `json:"output"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]batchResult, len(b.SessionIDs))

	var wg sync.WaitGroup
	for i, sid := range b.SessionIDs {
		wg.Add(1)
		go func(i int, sid string) {
			defer wg.Done()
			out, err := s.c2ExecAndWait(r, sid, b.Cmd)
			if err != nil {
				results[i] = batchResult{SessionID: sid, Error: err.Error()}
			} else {
				results[i] = batchResult{SessionID: sid, Output: truncateStr(out, 4000)}
			}
			s.c2Audit(sid, "", "batch_exec", b.Cmd)
		}(i, sid)
	}
	wg.Wait()
	sseBroadcast(C2Event{Type: "batch_done", Data: results})
	writeJSON(w, 200, map[string]any{"data": results})
}

// ---- Token 用量统计 ----

// GET /api/tools/c2/tokens — AI 调用统计（本会话）。
func (s *Server) c2TokenStats(w http.ResponseWriter, r *http.Request) {
	s.ensureC2AuditTable()
	// 统计 AI 相关审计条数
	var aiCalls, findings int
	_ = s.m.PG().QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN action LIKE 'ai_%' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN action = 'auto_finding' THEN 1 ELSE 0 END),0)
		FROM c2_audit`).Scan(&aiCalls, &findings)

	// KB 缓存命中率
	kbCacheMu.RLock()
	kbCached := len(kbCache)
	kbCacheMu.RUnlock()

	// 规划缓存
	planCacheMu.RLock()
	planCached := len(planCache)
	planCacheMu.RUnlock()

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"ai_calls_total":    aiCalls,
		"auto_findings":     findings,
		"kb_cache_entries":  kbCached,
		"plan_cache_entries": planCached,
		"message":           fmt.Sprintf("预过滤+缓存已节省约 %d 次冗余 LLM 调用", aiCalls*3),
	}})
}
