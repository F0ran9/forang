package server

// webshell_targets.go — Webshell 目标管理（参考 morelian 默连的目标列表/批量测活）：
// 保存连接配置（分组/URL/密码/编码器/脚本类型/附加头），REST CRUD + 并发存活检测。
// 密码/头只存服务端库；会话操作走 webshell_exec API 现场建连。

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/webshell"
)

// GET /api/tools/webshell/targets?q=&group=
func (s *Server) wsTargetsList(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	group := strings.TrimSpace(r.URL.Query().Get("group"))
	where := "1=1"
	args := []any{}
	if q != "" {
		args = append(args, "%"+q+"%")
		where += " AND (name ILIKE $1 OR url ILIKE $1 OR note ILIKE $1)"
	}
	if group != "" {
		args = append(args, group)
		where += " AND group_name = $" + itoa(len(args))
	}
	rows, err := s.m.PG().Query(`SELECT id, group_name, COALESCE(name,''), url, password, encoder,
		script_type, COALESCE(note,''), COALESCE(headers,''), alive, COALESCE(last_check,''), updated_at
		FROM webshell_targets`+" WHERE "+where+" ORDER BY group_name, id DESC LIMIT 500", args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID         int64  `json:"id"`
		Group      string `json:"group"`
		Name       string `json:"name"`
		URL        string `json:"url"`
		Password   string `json:"password"`
		Encoder    string `json:"encoder"`
		ScriptType string `json:"script_type"`
		Note       string `json:"note"`
		Headers    string `json:"headers"`
		Alive      bool   `json:"alive"`
		LastCheck  string `json:"last_check"`
		UpdatedAt  string `json:"updated_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var ts sql.NullTime
		if err := rows.Scan(&it.ID, &it.Group, &it.Name, &it.URL, &it.Password, &it.Encoder,
			&it.ScriptType, &it.Note, &it.Headers, &it.Alive, &it.LastCheck, &ts); err != nil {
			continue
		}
		it.Password = s.wsDecryptPassword(it.Password)
		if ts.Valid {
			it.UpdatedAt = ts.Time.Format("2006-01-02 15:04")
		}
		out = append(out, it)
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// POST /api/tools/webshell/targets — 新建/更新（id>0 为更新）。
func (s *Server) wsTargetsSave(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID         int64  `json:"id"`
		Group      string `json:"group"`
		Name       string `json:"name"`
		URL        string `json:"url"`
		Password   string `json:"password"`
		Encoder    string `json:"encoder"`
		ScriptType string `json:"script_type"`
		Note       string `json:"note"`
		Headers    string `json:"headers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.URL) == "" {
		writeErr(w, 400, "url 必填")
		return
	}
	if b.Group == "" {
		b.Group = "default"
	}
	if b.Encoder == "" {
		b.Encoder = "raw"
	}
	if b.ScriptType == "" {
		b.ScriptType = "php"
	}
	if b.Headers != "" && !json.Valid([]byte(b.Headers)) {
		writeErr(w, 400, "headers 需为 JSON 对象")
		return
	}
	if b.ID > 0 {
		_, err := s.m.PG().Exec(`UPDATE webshell_targets SET group_name=$2,name=$3,url=$4,password=$5,
			encoder=$6,script_type=$7,note=$8,headers=$9,updated_at=now() WHERE id=$1`,
			b.ID, b.Group, b.Name, b.URL, s.wsEncryptPassword(b.Password), b.Encoder, b.ScriptType, truncateStr(b.Note, 4000), b.Headers)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": b.ID})
		return
	}
	var id int64
	err := s.m.PG().QueryRow(`INSERT INTO webshell_targets (group_name,name,url,password,encoder,script_type,note,headers)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		b.Group, b.Name, b.URL, s.wsEncryptPassword(b.Password), b.Encoder, b.ScriptType, truncateStr(b.Note, 4000), b.Headers).Scan(&id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

// DELETE /api/tools/webshell/targets/{id}
func (s *Server) wsTargetsDelete(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	if _, err := s.m.PG().Exec("DELETE FROM webshell_targets WHERE id=$1", id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/tools/webshell/targets/check — 批量存活检测（body {ids?:[]} 空=全部）。
func (s *Server) wsTargetsCheck(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []int64 `json:"ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	rows, err := s.m.PG().Query(`SELECT id, url, password, encoder, script_type, COALESCE(headers,'')
		FROM webshell_targets`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type trow struct {
		id, url, pw, enc, st, headers string
	}
	var all []trow
	for rows.Next() {
		var t trow
		if rows.Scan(&t.id, &t.url, &t.pw, &t.enc, &t.st, &t.headers) == nil {
			t.pw = s.wsDecryptPassword(t.pw)
			all = append(all, t)
		}
	}
	if len(b.IDs) > 0 {
		want := map[int64]bool{}
		for _, id := range b.IDs {
			want[id] = true
		}
		var filtered []trow
		for _, t := range all {
			if want[parseID(t.id)] {
				filtered = append(filtered, t)
			}
		}
		all = filtered
	}
	type result struct {
		ID    int64  `json:"id"`
		Alive bool   `json:"alive"`
		Err   string `json:"error"`
	}
	results := make([]result, len(all))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, t := range all {
		wg.Add(1)
		go func(i int, t trow) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cli := &webshell.Client{
				URL: t.url, Password: t.pw, Encoder: t.enc, ScriptType: t.st, Timeout: 12 * time.Second,
			}
			if t.headers != "" {
				var hs map[string]string
				if json.Unmarshal([]byte(t.headers), &hs) == nil && len(hs) > 0 {
					cli.ExtraHeaders = hs
				}
			}
			res, err := cli.Test()
			ok := err == nil && res.OK
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			} else if !res.OK {
				errMsg = res.Error
			}
			results[i] = result{ID: parseID(t.id), Alive: ok, Err: truncateStr(errMsg, 200)}
			stamp := time.Now().Format("2006-01-02 15:04:05")
			_, _ = s.m.PG().Exec("UPDATE webshell_targets SET alive=$2, last_check=$3, updated_at=now() WHERE id=$1",
				parseID(t.id), ok, stamp)
		}(i, t)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"data": results})
}
