package server

// dashboard_enhanced.go — 实时仪表盘增强 API：
//   GET /api/dashboard/enhanced — 聚合全平台实时状态（一次调用全量数据）
//   GET /api/dashboard/stream   — SSE 实时推送（任一指标变化即推送）

import (
	"fmt"
	"net/http"
	"time"
)

// EnhancedDashboard 全平台实时状态。
type EnhancedDashboard struct {
	// 核心指标
	ActiveTasks   int   `json:"active_tasks"`
	TotalFindings int   `json:"total_findings"`
	CriticalFinds int   `json:"critical_finds"`
	HighFinds     int   `json:"high_finds"`

	// C2 指挥台
	C2Online      bool        `json:"c2_online"`
	C2Sessions    int         `json:"c2_sessions"`
	C2Autopilot   bool        `json:"c2_autopilot"`
	C2Tunnels     int         `json:"c2_tunnels"`

	// Webshell
	WebshellTargets int `json:"webshell_targets"`
	WebshellAlive   int `json:"webshell_alive"`

	// 知识库
	KBTotal    int `json:"kb_total"`
	KBChunks   int `json:"kb_chunks"`
	DictTotal  int `json:"dict_total"`

	// AI/LLM
	LLMProfiles    int    `json:"llm_profiles"`
	LLMCallsToday   int    `json:"llm_calls_today"`
	TokenInput      int64  `json:"token_input"`
	TokenOutput     int64  `json:"token_output"`
	C2AICalls       int    `json:"c2_ai_calls"`
	C2AutoFindings  int    `json:"c2_auto_findings"`

	// 资产
	TotalAssets int `json:"total_assets"`

	// 工具箱
	RepeaterHistory  int `json:"repeater_history"`
	ScanJobs          int `json:"scan_jobs"`

	// 时间
	Timestamp string `json:"timestamp"`
}

// GET /api/dashboard/enhanced — 聚合全平台状态。
func (s *Server) dashboardEnhanced(w http.ResponseWriter, r *http.Request) {
	d := EnhancedDashboard{Timestamp: time.Now().Format("15:04:05")}

	pg := s.m.PG()

	// 任务
	_ = pg.QueryRow(`SELECT COUNT(*) FROM tasks WHERE status IN ('running','created','queued')`).Scan(&d.ActiveTasks)
	// 发现
	_ = pg.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END),0)
		FROM findings`).Scan(&d.TotalFindings, &d.CriticalFinds, &d.HighFinds)

	// C2
	clients, err := c2Client().ListClients(r.Context(), nil)
	if err == nil {
		d.C2Online = true
		d.C2Sessions = len(clients)
	}
	autopilot.mu.Lock()
	d.C2Autopilot = autopilot.Running
	autopilot.mu.Unlock()
	tunnelState.mu.Lock()
	d.C2Tunnels = len(tunnelState.Tunnels)
	tunnelState.mu.Unlock()

	// Webshell
	_ = pg.QueryRow("SELECT COUNT(*), COALESCE(SUM(CASE WHEN alive THEN 1 ELSE 0 END),0) FROM webshell_targets").Scan(&d.WebshellTargets, &d.WebshellAlive)

	// 知识库
	_ = pg.QueryRow("SELECT COUNT(*) FROM kb_summaries").Scan(&d.KBTotal)
	_ = pg.QueryRow("SELECT COUNT(*) FROM kb_chunks").Scan(&d.KBChunks)
	_ = pg.QueryRow("SELECT COUNT(*) FROM dict_entries").Scan(&d.DictTotal)

	// AI
	_ = pg.QueryRow("SELECT COUNT(*) FROM llm_profiles WHERE enabled=true").Scan(&d.LLMProfiles)
	_ = pg.QueryRow("SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0) FROM llm_usage WHERE created_at > now() - interval '1 day'").Scan(&d.TokenInput, &d.TokenOutput)

	// C2 AI
	s.ensureC2AuditTable()
	_ = pg.QueryRow(`SELECT COALESCE(SUM(CASE WHEN action LIKE 'ai_%' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN action='auto_finding' THEN 1 ELSE 0 END),0) FROM c2_audit`).Scan(&d.C2AICalls, &d.C2AutoFindings)

	// 资产
	_ = pg.QueryRow("SELECT COUNT(*) FROM assets").Scan(&d.TotalAssets)

	// 工具箱
	_ = pg.QueryRow("SELECT COUNT(*) FROM repeater_history").Scan(&d.RepeaterHistory)
	_ = pg.QueryRow("SELECT COUNT(*) FROM scan_jobs").Scan(&d.ScanJobs)

	writeJSON(w, 200, map[string]any{"data": d})
}

// GET /api/dashboard/stream — 仪表盘 SSE（5s 推送一次全量状态）。
func (s *Server) dashboardStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 辅助函数：获取状态 JSON
	getData := func() []byte {
		d := EnhancedDashboard{Timestamp: time.Now().Format("15:04:05")}
		pg := s.m.PG()
		_ = pg.QueryRow(`SELECT COUNT(*) FROM tasks WHERE status IN ('running','created','queued')`).Scan(&d.ActiveTasks)
		_ = pg.QueryRow(`SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END),0)
			FROM findings`).Scan(&d.TotalFindings, &d.CriticalFinds, &d.HighFinds)
		clients, err := c2Client().ListClients(r.Context(), nil)
		if err == nil {
			d.C2Online = true
			d.C2Sessions = len(clients)
		}
		autopilot.mu.Lock()
		d.C2Autopilot = autopilot.Running
		autopilot.mu.Unlock()
		tunnelState.mu.Lock()
		d.C2Tunnels = len(tunnelState.Tunnels)
		tunnelState.mu.Unlock()
		_ = pg.QueryRow("SELECT COUNT(*), COALESCE(SUM(CASE WHEN alive THEN 1 ELSE 0 END),0) FROM webshell_targets").Scan(&d.WebshellTargets, &d.WebshellAlive)
		_ = pg.QueryRow("SELECT COUNT(*) FROM kb_summaries").Scan(&d.KBTotal)
		_ = pg.QueryRow("SELECT COUNT(*) FROM dict_entries").Scan(&d.DictTotal)
		_ = pg.QueryRow("SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0) FROM llm_usage WHERE created_at > now() - interval '1 day'").Scan(&d.TokenInput, &d.TokenOutput)
		// 序列化
		b := make([]byte, 0, 512)
		b = append(b, '{')
		b = append(b, `"active_tasks":`...)
		b = append(b, []byte(itoa(d.ActiveTasks))...)
		b = append(b, `,"c2_sessions":`...)
		b = append(b, []byte(itoa(d.C2Sessions))...)
		b = append(b, `,"total_findings":`...)
		b = append(b, []byte(itoa(d.TotalFindings))...)
		b = append(b, `,"timestamp":"`...)
		b = append(b, []byte(d.Timestamp)...)
		b = append(b, `","c2_autopilot":`...)
		if d.C2Autopilot {
			b = append(b, '1')
		} else {
			b = append(b, '0')
		}
		b = append(b, '}')
		return b
	}

	// 初始推送
	fmt.Fprintf(w, "event: dashboard\ndata: %s\n\n", getData())
	flusher.Flush()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, "event: dashboard\ndata: %s\n\n", getData())
			flusher.Flush()
		}
	}
}
