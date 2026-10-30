package server

// kb_api.go — 知识库 REST（移植自 AI-PENTEST knowledge_base.py 的核心面）：
// 总览统计 / 总结列表+详情 / 手动重建 / 检索（UI 与 kb_search 工具共用内核）。

import (
	"database/sql"
	"net/http"
)

// GET /api/kb/overview — 总览统计 + 最近 5 条。
func (s *Server) kbOverview(w http.ResponseWriter, r *http.Request) {
	var total, done, failed, vulns int64
	_ = s.m.PG().QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status='done' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(vuln_count),0) FROM kb_summaries`).
		Scan(&total, &done, &failed, &vulns)
	var chunks int64
	_ = s.m.PG().QueryRow("SELECT COUNT(*) FROM kb_chunks").Scan(&chunks)
	writeJSON(w, 200, map[string]any{
		"total": total, "done": done, "failed": failed, "vulns": vulns, "chunks": chunks,
	})
}

// GET /api/kb/summaries?q=&limit=50 — 列表（q 匹配标题/正文）。
func (s *Server) kbSummariesList(w http.ResponseWriter, r *http.Request) {
	q := trimQuery(r.URL.Query().Get("q"))
	limit := parseIntDefault(r.URL.Query().Get("limit"), 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := "1=1"
	args := []any{}
	if q != "" {
		args = append(args, "%"+q+"%")
		where = "title ILIKE $1 OR summary_md ILIKE $1"
	}
	rows, err := s.m.PG().Query(`SELECT task_id, title, task_status, status, source, model,
		vuln_count, fact_count, updated_at FROM kb_summaries`+" WHERE "+where+
		" ORDER BY updated_at DESC LIMIT "+itoa(limit), args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		TaskID     int64  `json:"task_id"`
		Title      string `json:"title"`
		TaskStatus string `json:"task_status"`
		Status     string `json:"status"`
		Source     string `json:"source"`
		Model      string `json:"model"`
		VulnCount  int    `json:"vuln_count"`
		FactCount  int    `json:"fact_count"`
		UpdatedAt  string `json:"updated_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var ts sql.NullTime
		if err := rows.Scan(&it.TaskID, &it.Title, &it.TaskStatus, &it.Status, &it.Source,
			&it.Model, &it.VulnCount, &it.FactCount, &ts); err != nil {
			continue
		}
		if ts.Valid {
			it.UpdatedAt = ts.Time.Format("2006-01-02 15:04")
		}
		out = append(out, it)
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// GET /api/kb/summaries/{task_id} — 详情（含 summary_md 全文）。
func (s *Server) kbSummaryDetail(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("task_id"))
	if id <= 0 {
		writeErr(w, 400, "bad task_id")
		return
	}
	var title, taskStatus, status, source, model, md, errMsg string
	var vulns, facts int
	var ts sql.NullTime
	err := s.m.PG().QueryRow(`SELECT COALESCE(title,''), COALESCE(task_status,''), status, source,
		COALESCE(model,''), summary_md, COALESCE(error,''), vuln_count, fact_count, updated_at
		FROM kb_summaries WHERE task_id=$1`, id).
		Scan(&title, &taskStatus, &status, &source, &model, &md, &errMsg, &vulns, &facts, &ts)
	if err != nil {
		writeErr(w, 404, "总结不存在（任务可能尚未终态或蒸馏排队中）")
		return
	}
	updated := ""
	if ts.Valid {
		updated = ts.Time.Format("2006-01-02 15:04")
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"task_id": id, "title": title, "task_status": taskStatus, "status": status,
		"source": source, "model": model, "summary_md": md, "error": errMsg,
		"vuln_count": vulns, "fact_count": facts, "updated_at": updated,
	}})
}

// POST /api/kb/summaries/{task_id}/regenerate — 手动重建（LLM 真跑，可能 30-120s，异步）。
func (s *Server) kbRegenerate(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("task_id"))
	if id <= 0 {
		writeErr(w, 400, "bad task_id")
		return
	}
	var exists bool
	err := s.m.PG().QueryRow("SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1)", id).Scan(&exists)
	if err != nil || !exists {
		writeErr(w, 404, "任务不存在")
		return
	}
	// 重置为 queued（占位行），循环 30s 内会接走；也可直接同步跑——异步对齐 aipentest 手感
	_, _ = s.m.PG().Exec(`INSERT INTO kb_summaries (task_id, status, source) VALUES ($1,'queued','manual')
		ON CONFLICT (task_id) DO UPDATE SET status='queued', source='manual', updated_at=now()`, id)
	go s.distillTask(id, "manual")
	writeJSON(w, 200, map[string]any{"ok": true, "task_id": id})
}

// GET /api/kb/search?q=&top_k= — 检索（UI 用；agent 工具走同一内核）。
func (s *Server) kbSearchAPI(w http.ResponseWriter, r *http.Request) {
	q := trimQuery(r.URL.Query().Get("q"))
	topK := parseIntDefault(r.URL.Query().Get("top_k"), 5)
	res, total, err := s.kbSearchRetrieval(q, topK)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": res, "total_chunks": total})
}

func trimQuery(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
