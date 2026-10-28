package server

import (
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
}

func (s *Server) interceptStats(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	window := parseWindowHours(r.URL.Query().Get("hours"))
	since := time.Now().Add(-time.Duration(window) * time.Hour)

	rows, err := pg.Query(`
		SELECT status,
		       COALESCE(NULLIF(decision_source,''),
		        CASE WHEN rule_id IS NOT NULL THEN 'rule'
		             WHEN reason LIKE '[模型]%' THEN 'model' ELSE 'unknown' END) AS src,
		       tool_name,
		       CASE WHEN decided_at IS NOT NULL
		            THEN EXTRACT(EPOCH FROM (decided_at - created_at)) * 1000 END AS ms
		FROM intercept_pending
		WHERE created_at >= $1`, since)
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
	writeJSON(w, 200, map[string]any{"stats": st})
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
