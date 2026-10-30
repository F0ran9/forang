package server

// repeater_history.go — Repeater 历史 CRUD（移植自 AI-PENTEST backend/app/api/repeater.py
// 的 /history 部分）：显式保存请求报文+选项，收藏/搜索/回填，与任务制发送解耦。
// raw 模式忠实重放的设计保持不变（不自动补 UA/Content-Type——所见即所发）。

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

type repHistoryBody struct {
	Title         string `json:"title"`
	Raw           string `json:"raw"`
	FollowRedir   *bool  `json:"follow_redirect"`
	ForceHTTPS    *bool  `json:"force_https"`
	MaxBodyKB     *int   `json:"max_body_kb"`
	TimeoutSec    *int   `json:"timeout_sec"`
	Starred       *bool  `json:"starred"`
}

// GET /api/tools/repeater/history?q=&starred=1&limit=50 — 列表（q 匹配 title/raw）。
func (s *Server) repHistoryList(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	starred := r.URL.Query().Get("starred") == "1"
	limit := 50
	if n := parseIntDefault(r.URL.Query().Get("limit"), 50); n > 0 && n <= 200 {
		limit = n
	}
	where := "1=1"
	args := []any{}
	if q != "" {
		where += " AND (title ILIKE $1 OR raw ILIKE $1)"
		args = append(args, "%"+q+"%")
	}
	if starred {
		where += " AND starred"
	}
	argN := len(args)
	rows, err := s.m.PG().Query(
		"SELECT id, title, raw, follow_redirect, force_https, max_body_kb, timeout_sec, starred, updated_at "+
			"FROM repeater_history WHERE "+where+" ORDER BY updated_at DESC LIMIT "+itoa(limit),
		args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID          int64  `json:"id"`
		Title       string `json:"title"`
		Raw         string `json:"raw"`
		Preview     string `json:"preview"`
		FollowRedir bool   `json:"follow_redirect"`
		ForceHTTPS  bool   `json:"force_https"`
		MaxBodyKB   int    `json:"max_body_kb"`
		TimeoutSec  int    `json:"timeout_sec"`
		Starred     bool   `json:"starred"`
		UpdatedAt   string `json:"updated_at"`
	}
	out := []item{}
	_ = argN
	for rows.Next() {
		var it item
		var ts sql.NullTime
		if err := rows.Scan(&it.ID, &it.Title, &it.Raw, &it.FollowRedir, &it.ForceHTTPS,
			&it.MaxBodyKB, &it.TimeoutSec, &it.Starred, &ts); err != nil {
			continue
		}
		if ts.Valid {
			it.UpdatedAt = ts.Time.Format("2006-01-02 15:04")
		}
		// preview：请求行 + Host，给列表用
		line := strings.SplitN(strings.ReplaceAll(it.Raw, "\r\n", "\n"), "\n", 2)[0]
		it.Preview = truncateStr(line, 120)
		it.Raw = truncateStr(it.Raw, 20000)
		out = append(out, it)
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// POST /api/tools/repeater/history — 新建（返回 id）。
func (s *Server) repHistoryCreate(w http.ResponseWriter, r *http.Request) {
	var b repHistoryBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.Raw) == "" {
		writeErr(w, 400, "raw 不能为空")
		return
	}
	fd, fh, mb, ts, st := boolDeref(b.FollowRedir, true), boolDeref(b.ForceHTTPS, false),
		intDeref(b.MaxBodyKB, 1024), intDeref(b.TimeoutSec, 30), boolDeref(b.Starred, false)
	var id int64
	err := s.m.PG().QueryRow(
		"INSERT INTO repeater_history (title, raw, follow_redirect, force_https, max_body_kb, timeout_sec, starred) "+
			"VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
		truncateStr(b.Title, 200), b.Raw, fd, fh, mb, ts, st).Scan(&id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"id": id}})
}

// PUT /api/tools/repeater/history/{id} — 更新。
func (s *Server) repHistoryUpdate(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	var b repHistoryBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	sets := []string{}
	args := []any{}
	add := func(col string, v any) { args = append(args, v); sets = append(sets, col+" = $"+itoa(len(args))) }
	if b.Title != "" {
		add("title", truncateStr(b.Title, 200))
	}
	if b.Raw != "" {
		add("raw", b.Raw)
	}
	if b.FollowRedir != nil {
		add("follow_redirect", *b.FollowRedir)
	}
	if b.ForceHTTPS != nil {
		add("force_https", *b.ForceHTTPS)
	}
	if b.MaxBodyKB != nil {
		add("max_body_kb", *b.MaxBodyKB)
	}
	if b.TimeoutSec != nil {
		add("timeout_sec", *b.TimeoutSec)
	}
	if b.Starred != nil {
		add("starred", *b.Starred)
	}
	if len(sets) == 0 {
		writeErr(w, 400, "无更新字段")
		return
	}
	args = append(args, id)
	res, err := s.m.PG().Exec("UPDATE repeater_history SET "+strings.Join(sets, ", ")+
		", updated_at = now() WHERE id = $"+itoa(len(args)), args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "记录不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/tools/repeater/history/{id}。
func (s *Server) repHistoryDelete(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	if _, err := s.m.PG().Exec("DELETE FROM repeater_history WHERE id = $1", id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/tools/repeater/history/{id}/star — 收藏/取消。
func (s *Server) repHistoryStar(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	var b struct {
		Starred bool `json:"starred"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	if _, err := s.m.PG().Exec(
		"UPDATE repeater_history SET starred = $1, updated_at = now() WHERE id = $2", b.Starred, id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- 小工具（本文件族共用） ----

func boolDeref(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func intDeref(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func parseID(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
		if n > 1<<40 {
			return 0
		}
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func parseIntDefault(s string, def int) int {
	n := 0
	if s == "" {
		return def
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}
