package server

import (
	"database/sql"
	"net/http"
	"time"
)

// 审批统计聚合（守门审计）：拦截率、按状态/来源/工具分布、模型判定平均耗时。
// 数据源 = intercept_pending（历史与在途审批同表）；耗时 = decided_at - created_at。

// InterceptStats 是审批记录页顶部的聚合视图。
type InterceptStats struct {
	Total          int            `json:"total"`
	Allowed        int            `json:"allowed"`
	Denied         int            `json:"denied"`
	Pending        int            `json:"pending"`
	Timeout        int            `json:"timeout"`
	DenyRate       float64        `json:"deny_rate"` // denied/(allowed+denied+timeout)
	BySource       map[string]int `json:"by_source"` // rule / model / unknown
	ByTool         map[string]int `json:"by_tool"`   // top 10 tools by decisions
	ModelDecisions int            `json:"model_decisions"`
	ModelAvgMs     int64          `json:"model_avg_ms"`
	WindowHours    int            `json:"window_hours"`
	CallTotal      int64          `json:"call_total"`     // 窗口内全部工具调用（真实口径分母）
	TrueDenyRate   float64        `json:"true_deny_rate"` // denied/call_total：真实拦截率
}

func (s *Server) interceptStats(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	window := parseWindowHours(r.URL.Query().Get("hours"))
	// window=0 语义是「全部」：不带时间过滤。此前 since=now 让 WHERE created_at>=now
	// 恒空——页面不传 hours 时统计卡全 0 而表格有数据（实测踩坑）。
	var rows *sql.Rows
	var err error
	if window > 0 {
		since := time.Now().Add(-time.Duration(window) * time.Hour)
		rows, err = pg.Query(`
			SELECT status,
			       COALESCE(NULLIF(decision_source,''),
			        CASE WHEN rule_id IS NOT NULL THEN 'rule'
			             WHEN reason LIKE '[模型]%' THEN 'model' ELSE 'unknown' END) AS src,
			       tool_name,
			       CASE WHEN decided_at IS NOT NULL
			            THEN EXTRACT(EPOCH FROM (decided_at - created_at)) * 1000 END AS ms
			FROM intercept_pending
			WHERE created_at >= $1`, since)
	} else {
		rows, err = pg.Query(`
			SELECT status,
			       COALESCE(NULLIF(decision_source,''),
			        CASE WHEN rule_id IS NOT NULL THEN 'rule'
			             WHEN reason LIKE '[模型]%' THEN 'model' ELSE 'unknown' END) AS src,
			       tool_name,
			       CASE WHEN decided_at IS NOT NULL
			            THEN EXTRACT(EPOCH FROM (decided_at - created_at)) * 1000 END AS ms
			FROM intercept_pending`)
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()

	st := InterceptStats{
		WindowHours: window,
		BySource:    map[string]int{},
		ByTool:      map[string]int{},
	}
	var modelMsSum, modelMsN int64
	for rows.Next() {
		var status, src, tool string
		var ms *float64
		if err := rows.Scan(&status, &src, &tool, &ms); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		st.Total++
		switch status {
		case "allowed":
			st.Allowed++
		case "denied":
			st.Denied++
		case "pending":
			st.Pending++
		case "timeout":
			st.Timeout++
		}
		st.BySource[src]++
		if len(st.ByTool) < 10 || st.ByTool[tool] > 0 {
			st.ByTool[tool]++
		}
		if src == "model" {
			st.ModelDecisions++
			if ms != nil {
				modelMsSum += int64(*ms)
				modelMsN++
			}
		}
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	decided := st.Allowed + st.Denied + st.Timeout
	if decided > 0 {
		st.DenyRate = float64(st.Denied) / float64(decided)
	}
	if modelMsN > 0 {
		st.ModelAvgMs = modelMsSum / modelMsN
	}
	// 真实拦截率口径：denied / 窗口内全部工具调用（activity kind='tool_use'）。
	// DenyRate 只是「留痕判定里的拒占比」——judge 启用前未命中规则的放行
	// 调用不入 intercept_pending，历史 allowed 严重欠采样，DenyRate 会虚高
	// （实测曾显示 77%，真实 <1%）。CallTotal/TrueDenyRate 才是运营口径。
	if calls := s.statsWindowToolCalls(window); calls > 0 {
		st.CallTotal = calls
		st.TrueDenyRate = float64(st.Denied) / float64(calls)
	}
	writeJSON(w, 200, map[string]any{"stats": st})
}

// statsWindowToolCalls 统计窗口内全部工具调用次数（activity 表 tool_use 事件，
// 含所有 agent：planner/worker/main）。window=0 表示全部时间。
func (s *Server) statsWindowToolCalls(window int) int64 {
	pg := s.m.PG()
	if pg == nil {
		return 0
	}
	q := `SELECT COUNT(*) FROM activity WHERE kind='tool_use'`
	var args []any
	if window > 0 {
		q += ` AND created_at >= $1`
		args = append(args, time.Now().Add(-time.Duration(window)*time.Hour))
	}
	var n int64
	if err := pg.QueryRow(q, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

func parseWindowHours(raw string) int {
	switch raw {
	case "24":
		return 24
	case "168":
		return 168
	case "720":
		return 720
	}
	return 0 // 全部
}
