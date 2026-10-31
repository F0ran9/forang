package server

// dict.go — 字典中心（知识库二期，移植思路来自 AI-PENTEST 知识库 + 工具模块联动）：
// Web 路径（目录与 API 统一为 path）、用户名、密码、参数名、子域五类字典的沉淀与复用。
//   沉淀：①内置种子（seedDictBuiltins，幂等）②任务蒸馏时从 findings/facts 自动提取
//        （dictExtractTexts）③dirscan 命中回灌（dirscan.go 调 dictRecordHit）
//   复用：①dirscan 默认联用（dictWordlistForScan）②agent dict_query 工具
//        ③UI 浏览/搜索/导出 txt（hydra/dirsearch/Intruder 直接吃）

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const dictValueMax = 512

// 内置用户名/密码/参数/子域种子（目录种子复用 dirscan.go 的 dirWordlist）。
var (
	builtinUsers = []string{
		"admin", "administrator", "root", "test", "guest", "demo", "user", "system",
		"oracle", "mysql", "postgres", "sa", "mongo", "redis", "ftp", "svn", "git",
		"tomcat", "apache", "nginx", "manager", "operator", "service", "api", "backup",
		"deploy", "jenkins", "dev", "ops", "sec", "audit", "finance", "hr", "oa",
	}
	builtinPasses = []string{
		"123456", "admin123", "Admin@123", "admin", "password", "P@ssw0rd", "Passw0rd!",
		"root", "111111", "123123", "12345678", "123456789", "admin@2024", "admin@2025",
		"1qaz2wsx", "Aa123456", "admin888", "test123", "qwer1234", "zaq12wsx", "88888888",
		"66666666", "abc123456", "a123456", "123321", "654321", "1234qwer", "!@#$%^&*",
		"qwe123", "1q2w3e4r", "abcd1234", "admin1234", "Admin123", "Admin@1234", "P@ss1234",
	}
	builtinParams = []string{
		"debug", "test", "token", "file", "path", "url", "redirect", "callback", "cmd",
		"exec", "query", "sql", "id", "uid", "role", "isAdmin", "admin", "type", "lang",
		"template", "module", "action", "method", "format", "jsonp", "source", "dest",
		"next", "return", "goto", "continue", "page", "size", "keyword", "keyword2",
		"username", "user", "password", "passwd", "pwd", "openId", "ticket", "code",
		"secret", "key", "access_key", "signature", "sign", "nonce", "timestamp",
	}
	builtinSubdomains = []string{
		"www", "api", "admin", "mail", "vpn", "oa", "sso", "test", "dev", "staging",
		"uat", "prod", "git", "svn", "jenkins", "sonar", "nexus", "harbor", "kibana",
		"grafana", "prometheus", "zabbix", "erp", "crm", "hr", "smtp", "pop", "imap",
		"ftp", "ssh", "mysql", "redis", "mq", "rabbit", "es", "nacos", "eureka",
		"gateway", "portal", "app", "m", "h5", "static", "img", "cdn", "download",
	}
)

// seedDictBuiltins 幂等种子：只补 (kind,value) 缺失的行，不动已沉淀数据。
func (s *Server) seedDictBuiltins() {
	seeds := map[string][]string{
		"user": builtinUsers, "pass": builtinPasses,
		"param": builtinParams, "subdomain": builtinSubdomains,
	}
	for kind, vals := range seeds {
		for _, v := range vals {
			_, _ = s.m.PG().Exec(`INSERT INTO dict_entries (kind, value, source) VALUES ($1,$2,'builtin')
				ON CONFLICT (kind, value) DO NOTHING`, kind, v)
		}
	}
	// 路径种子：dirscan.go 的内置字典整体入 path 类（目录与 API 路径统一）
	for _, v := range dirWordlist {
		_, _ = s.m.PG().Exec(`INSERT INTO dict_entries (kind, value, source) VALUES ('path',$1,'builtin')
			ON CONFLICT (kind, value) DO NOTHING`, v)
	}
}

// dictAdd 添加/更新一条字典（dedup on kind+value，命中即 hit_count+1 更新上下文）。
func (s *Server) dictAdd(kind, value, note, context, source string, taskID int64, lastStatus int) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > dictValueMax || !validDictKind(kind) {
		return
	}
	value = strings.TrimLeft(value, "/") // 统一去前导斜杠（dir/api 类）
	_, _ = s.m.PG().Exec(`INSERT INTO dict_entries (kind, value, note, context, source, task_id, hit_count, last_status)
		VALUES ($1,$2,$3,$4,$5,$6,1,$7)
		ON CONFLICT (kind, value) DO UPDATE SET hit_count = dict_entries.hit_count + 1,
			context = CASE WHEN $4 <> '' THEN $4 ELSE dict_entries.context END,
			last_status = CASE WHEN $7 > 0 THEN $7 ELSE dict_entries.last_status END,
			task_id = COALESCE(dict_entries.task_id, $6),
			note = CASE WHEN $3 <> '' THEN $3 ELSE dict_entries.note END,
			updated_at = now()`,
		kind, value, truncateStr(note, 300), truncateStr(context, 200), source, nilIfZero(taskID), lastStatus)
}

func nilIfZero(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func validDictKind(k string) bool {
	switch k {
	case "path", "user", "pass", "param", "subdomain", "fingerprint":
		return true
	}
	return false
}

// ---- 自动提取（蒸馏时从 findings 证据 / facts 文本里挖路径与凭据） ----

var (
	// 路径只从两种可信上下文提取：完整 URL 的 path 部分 / HTTP 请求行的 path。
	// 裸 /xxx 匹配会把 Content-Type 片段、base64 串、数字、字段名全误提进来。
	reFullURL = regexp.MustCompile(`(?i)https?://[A-Za-z0-9.\-]+(?::\d+)?(/[A-Za-z0-9_\-./%]{1,120})?`)
	reReqLine = regexp.MustCompile(`(?im)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[ 	]+(/[A-Za-z0-9_\-./%]{2,120})[ 	]+HTTP`)
	reQueryUser = regexp.MustCompile(`[?&](?:username|user|uname|user_name|login|account|email|phone)=([A-Za-z0-9_.@\-]{2,32})`)
	reQueryPass = regexp.MustCompile(`[?&](?:password|passwd|pwd|pass)=([^&\s"']{4,64})`)
	reJSONUser  = regexp.MustCompile(`"(?:username|userName|user|login|account)"\s*:\s*"([A-Za-z0-9_.@\-]{2,32})"`)
	reJSONPass  = regexp.MustCompile(`"(?:password|passwd|pwd|pass|passWord)"\s*:\s*"([^"]{4,64})"`)
	reParam     = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=`)
	staticExtRe = regexp.MustCompile(`(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|mp4|mp3|webp|min\.(js|css))$`)
)

// dictExtractTexts 从一批文本（findings 证据/包体 + facts）提取字典条目并沉淀。
// 每个 kind 有单任务上限，防刷表。
func (s *Server) dictExtractTexts(taskID int64, contextHost string, texts []string) {
	caps := map[string]int{"path": 80, "user": 20, "pass": 20, "param": 30}
	added := map[string]bool{}
	for _, t := range texts {
		if t == "" {
			continue
		}
		// 路径：完整 URL + 请求行两种上下文
		paths := map[string]bool{}
		for _, m := range reFullURL.FindAllStringSubmatch(t, -1) {
			if m[1] != "" {
				paths[m[1]] = true
			}
		}
		for _, m := range reReqLine.FindAllStringSubmatch(t, -1) {
			paths[m[1]] = true
		}
		for p := range paths {
			if !dictPathPlausible(p) {
				continue
			}
			key := "path|" + p
			if !added[key] && caps["path"] > 0 {
				added[key] = true
				caps["path"]--
				s.dictAdd("path", p, "", contextHost, "task", taskID, 0)
			}
		}
		// 凭据
		for _, re := range []*regexp.Regexp{reQueryUser, reJSONUser} {
			for _, m := range re.FindAllStringSubmatch(t, -1) {
				key := "user|" + m[1]
				if !added[key] && caps["user"] > 0 {
					added[key] = true
					caps["user"]--
					s.dictAdd("user", m[1], "", contextHost, "task", taskID, 0)
				}
			}
		}
		for _, re := range []*regexp.Regexp{reQueryPass, reJSONPass} {
			for _, m := range re.FindAllStringSubmatch(t, -1) {
				key := "pass|" + m[1]
				if !added[key] && caps["pass"] > 0 {
					added[key] = true
					caps["pass"]--
					s.dictAdd("pass", m[1], "", contextHost, "task", taskID, 0)
				}
			}
		}
		// 参数名
		for _, m := range reParam.FindAllStringSubmatch(t, -1) {
			key := "param|" + m[1]
			if !added[key] && caps["param"] > 0 {
				added[key] = true
				caps["param"]--
				s.dictAdd("param", m[1], "", contextHost, "task", taskID, 0)
			}
		}
	}
}

// dictRecordHit dirscan 命中回灌（一条非 404 结果 → 路径字典 +1 hit）。
// 目录与 API 路径同构（都是 base_url 拼接探测），统一沉淀为 path 一类。
func (s *Server) dictRecordHit(path string, status int, contextHost string) {
	s.dictAdd("path", path, "", contextHost, "dirscan", 0, status)
}

// dictWordlistForScan dirscan 联用：返回内置 + 字典沉淀（hit_count 降序、有 last_status 优先）。
// limit 防极端膨胀。
func (s *Server) dictWordlistForScan(limit int) []string {
	rows, err := s.m.PG().Query(`SELECT value FROM dict_entries
		WHERE kind = 'path' ORDER BY hit_count DESC, updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil && strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

// ---- REST ----

// GET /api/kb/dicts?kind=&q=&limit=&source= — 字典列表。
func (s *Server) dictList(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	source := r.URL.Query().Get("source")
	limit := parseIntDefault(r.URL.Query().Get("limit"), 200)
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	where := "1=1"
	args := []any{}
	if kind != "" && validDictKind(kind) {
		args = append(args, kind)
		where += " AND kind = $" + itoa(len(args))
	}
	if source != "" {
		args = append(args, source)
		where += " AND source = $" + itoa(len(args))
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		where += " AND (value ILIKE $" + itoa(len(args)) + " OR note ILIKE $" + itoa(len(args)) + " OR context ILIKE $" + itoa(len(args)) + ")"
	}
	rows, err := s.m.PG().Query(`SELECT id, kind, value, note, context, source, task_id, hit_count, last_status, updated_at
		FROM dict_entries`+" WHERE "+where+" ORDER BY hit_count DESC, updated_at DESC LIMIT "+itoa(limit), args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID         int64  `json:"id"`
		Kind       string `json:"kind"`
		Value      string `json:"value"`
		Note       string `json:"note"`
		Context    string `json:"context"`
		Source     string `json:"source"`
		TaskID     any    `json:"task_id"`
		HitCount   int    `json:"hit_count"`
		LastStatus int    `json:"last_status"`
		UpdatedAt  string `json:"updated_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var ts sql.NullTime
		if err := rows.Scan(&it.ID, &it.Kind, &it.Value, &it.Note, &it.Context, &it.Source,
			&it.TaskID, &it.HitCount, &it.LastStatus, &ts); err != nil {
			continue
		}
		if ts.Valid {
			it.UpdatedAt = ts.Time.Format("2006-01-02 15:04")
		}
		out = append(out, it)
	}
	// 每类计数
	counts := map[string]int{}
	crows, err := s.m.PG().Query("SELECT kind, COUNT(*) FROM dict_entries GROUP BY kind")
	if err == nil {
		for crows.Next() {
			var k string
			var n int
			if crows.Scan(&k, &n) == nil {
				counts[k] = n
			}
		}
		crows.Close()
	}
	writeJSON(w, 200, map[string]any{"data": out, "counts": counts})
}

// POST /api/kb/dicts — 手动添加。
func (s *Server) dictCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Kind   string `json:"kind"`
		Values string `json:"values"` // 支持多行批量
		Note   string `json:"note"`
	}
	if err := decodeJSONBody(r, &b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if !validDictKind(b.Kind) {
		writeErr(w, 400, "kind 需为 path/user/pass/param/subdomain")
		return
	}
	n := 0
	for _, line := range strings.Split(b.Values, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			s.dictAdd(b.Kind, line, b.Note, "", "manual", 0, 0)
			n++
		}
	}
	if n == 0 {
		writeErr(w, 400, "values 为空")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "added": n})
}

// DELETE /api/kb/dicts/{id}。
func (s *Server) dictDelete(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	if _, err := s.m.PG().Exec("DELETE FROM dict_entries WHERE id=$1 AND source <> 'builtin'", id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/kb/dicts/export?kind= — 导出 txt（每行一条，hydra/dirsearch/Intruder 直接可用）。
func (s *Server) dictExport(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if !validDictKind(kind) {
		writeErr(w, 400, "kind 非法")
		return
	}
	rows, err := s.m.PG().Query(`SELECT value FROM dict_entries WHERE kind=$1
		ORDER BY hit_count DESC, updated_at DESC LIMIT 50000`, kind)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			if kind == "dir" || kind == "api" {
				b.WriteString("/" + strings.TrimLeft(v, "/") + "\n")
			} else if kind == "subdomain" {
				b.WriteString(v + ".example.com\n")
			} else {
				b.WriteString(v + "\n")
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=dict-"+kind+".txt")
	_, _ = io.WriteString(w, b.String())
}

func decodeJSONBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// dictPathPlausible 路径合理性：滤静态资源、本地文件路径、动态 ID 段、随机串段。
func dictPathPlausible(p string) bool {
	if len(p) < 3 || len(p) > 120 {
		return false
	}
	if staticExtRe.MatchString(p) {
		return false
	}
	// 服务器本地文件路径特征（证据截图等落盘路径）
	low := strings.ToLower(p)
	if strings.Contains(low, "evidence/") || strings.Contains(low, "desktop/") ||
		strings.HasPrefix(low, "/root/") || strings.HasPrefix(low, "/home/") ||
		strings.HasPrefix(low, "/tmp/") || strings.HasPrefix(low, "/var/") ||
		strings.HasPrefix(low, "/usr/") || strings.HasPrefix(low, "/proc") ||
		strings.HasPrefix(low, "/etc/") || strings.HasPrefix(low, "/data/") {
		return false
	}
	// 已知非路径单词（Content-Type 片段等历史误提形态）
	switch strings.ToLower(p) {
	case "/json", "/xml", "/html", "/text", "/x-www-form-urlencoded",
		"/application", "/multipart", "/octet-stream", "/true", "/false", "/null":
		return false
	}
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg == "" {
			continue
		}
		// 纯数字段 = 动态 ID/状态码/端口（/api/12345、500）
		if isAllDigits(seg) {
			return false
		}
		// 超长段 = base64/随机 token（正常路径段不会超过 24 字符）
		if len(seg) > 24 {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
