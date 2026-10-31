package server

// c2_linkage.go — C2 ↔ 通知/指纹/POC/AI 任务联动：
//   1) C2 新 beacon 上线 → 钉钉/飞书实时推送
//   2) 指纹识别工具（agent 可调，入库 assets）
//   3) 指纹 → POC 自动匹配 → 自动创建 AI 渗透任务
//   4) 资产发现 → 自动触发 POC 扫描

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// 1) C2 新上线 → 通知推送
// ═══════════════════════════════════════════════════════════════

var (
	c2NotifiedSessions sync.Map // 已推送过的 session_id
)

// c2CheckNewSessions 检测新上线 beacon → 推送通知。
// 在 load() 会话列表刷新时调用。
func (s *Server) c2CheckNewSessions(clients []any) {
	for _, c := range clients {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		// 已推送过？跳过
		if _, loaded := c2NotifiedSessions.LoadOrStore(id, true); loaded {
			continue
		}
		hostname, _ := m["hostname"].(string)
		ip, _ := m["internalIp"].(string)
		os, _ := m["osType"].(string)
		arch, _ := m["arch"].(string)

		title := fmt.Sprintf("🔴 C2 新 Beacon 上线：%s", hostname)
		body := fmt.Sprintf("**主机**: %s\n**内网 IP**: %s\n**系统**: %s/%s\n**会话 ID**: `%s`\n\n> 点击工具箱→C2 指挥 查看详情",
			hostname, ip, os, arch, truncateStr(id, 20))

		go func() {
			if err := s.sendAll(title, body); err != nil {
				// 通知失败不影响主流程
				_ = err
			}
			s.c2AuditHashed(id, hostname, "beacon_online", fmt.Sprintf("IP:%s OS:%s", ip, os))
		}()
	}
}

// ═══════════════════════════════════════════════════════════════
// 2) 指纹识别（Agent 工具 + API）
// ═══════════════════════════════════════════════════════════════

// FingerPrint 指纹识别结果。
type FingerPrint struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	Server     string `json:"server"`
	XPower     string `json:"x_powered_by"`
	Framework  string `json:"framework"`   // ThinkPHP/Spring/Django/Express...
	CMS        string `json:"cms"`         // WordPress/ Discuz /...
	Language   string `json:"language"`    // PHP/Java/Python/Node...
	Container  string `json:"container"`  // Tomcat/Nginx/Apache...
	Fingerprint string `json:"fingerprint"` // 综合指纹描述
}

// 指纹规则库（正则 → 标签）
var fingerprintRules = []struct {
	Header   string // 检查哪个响应头
	Pattern  string // 正则
	Tag      string // 标签值
	Category string // 分类
}{
	{"server", `(?i)nginx`, "Nginx", "container"},
	{"server", `(?i)apache`, "Apache", "container"},
	{"server", `(?i tomcat|tengine`, "Tomcat/Tengine", "container"},
	{"server", `(?i)iis`, "IIS", "container"},
	{"server", `(?i)jetty`, "Jetty", "container"},
	{"x-powered-by", `(?i)php`, "PHP", "language"},
	{"x-powered-by", `(?i)asp\.net`, "ASP.NET", "language"},
	{"x-powered-by", `(?i)express`, "Express/Node.js", "language"},
	{"x-powered-by", `(?i)servlet`, "Java Servlet", "language"},
	{"x-generator", `(?i)drupal`, "Drupal", "cms"},
	{"x-generator", `(?i)wordpress`, "WordPress", "cms"},
}

// GET /api/tools/fingerprint?url= — 指纹识别（HTTP 响应头 + Body 关键词）。
func (s *Server) fingerprintAPI(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		writeErr(w, 400, "url 必填")
		return
	}
	fp, err := doFingerprint(r.Context(), targetURL)
	if err != nil {
		writeErr(w, 502, "指纹识别失败: "+err.Error())
		return
	}

	// 入库 assets
	_, _ = s.m.PG().Exec(`INSERT INTO assets (type, value, source, metadata)
		VALUES ('service', $1, 'fingerprint', $2)
		ON CONFLICT DO NOTHING`,
		targetURL, fp.Fingerprint)

	// POC 匹配
	matches := s.matchPOCByFingerprint(fp)

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"fingerprint": fp,
		"poc_matches": matches,
	}})
}

// doFingerprint 执行指纹识别。
func doFingerprint(ctx context.Context, url string) (*FingerPrint, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	fp := &FingerPrint{URL: url}
	fp.Title = resp.Header.Get("Title")
	fp.Server = resp.Header.Get("Server")
	fp.XPower = resp.Header.Get("X-Powered-By")

	// 读取 body 前 4KB 检测框架/CMS
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	// 匹配规则
	var tags []string
	for _, rule := range fingerprintRules {
		headerVal := resp.Header.Get(rule.Header)
		if headerVal != "" && strings.Contains(strings.ToLower(headerVal), strings.ToLower(extractPattern(rule.Pattern))) {
			tags = append(tags, rule.Tag)
		}
	}

	// Body 关键词检测
	bodyChecks := map[string]string{
		"ThinkPHP": "thinkphp", "Laravel": "laravel", "Spring Boot": "spring",
		"Django": "django", "Flask": "flask", "WordPress": "wp-content",
		"Discuz": "discuz", "Typecho": "typecho", "Vue.js": "vue.js",
		"React": "react", "jQuery": "jquery", "Bootstrap": "bootstrap",
		"Nacos": "nacos", "Druid": "druid", "Eureka": "eureka",
		"Swagger": "swagger", "Kibana": "kibana", "Grafana": "grafana",
		"Jenkins": "jenkins", "Solr": "solr", "Zabbix": "zabbix",
	}
	for tag, keyword := range bodyChecks {
		if strings.Contains(strings.ToLower(bodyStr), keyword) {
			tags = append(tags, tag)
		}
	}

	fp.Fingerprint = strings.Join(tags, " / ")
	if fp.Fingerprint == "" {
		fp.Fingerprint = "Unknown"
	}
	return fp, nil
}

func extractPattern(p string) string {
	// 简化：取正则中的可读部分
	return strings.TrimPrefix(strings.TrimPrefix(p, "(?i)"), "(?i")
}

// ═══════════════════════════════════════════════════════════════
// 3) 指纹 → POC 自动匹配
// ═══════════════════════════════════════════════════════════════

type POCMatch struct {
	POCID   string `json:"poc_id"`
	Name    string `json:"name"`
	Target  string `json:"target"`
	Severity string `json:"severity"`
	Reason  string `json:"reason"`
}

// matchPOCByFingerprint 根据指纹匹配 POC 库。
func (s *Server) matchPOCByFingerprint(fp *FingerPrint) []POCMatch {
	matches := []POCMatch{}
	fpLower := strings.ToLower(fp.Fingerprint + " " + fp.Server + " " + fp.XPower + " " + fp.Title)

	rows, err := s.m.PG().Query(`SELECT id, name FROM pocs WHERE enabled=true LIMIT 500`)
	if err != nil {
		return matches
	}
	defer rows.Close()

	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) != nil {
			continue
		}
		nameLower := strings.ToLower(name)
		// 简单关键词匹配：POC 名包含指纹关键词
		for _, kw := range strings.Fields(fpLower) {
			if len(kw) > 2 && strings.Contains(nameLower, kw) {
				matches = append(matches, POCMatch{
					POCID: id, Name: name, Target: fp.URL,
					Reason: fmt.Sprintf("指纹 %q 匹配 POC %q", kw, name),
				})
				break
			}
		}
		if len(matches) >= 10 {
			break
		}
	}
	return matches
}

// POST /api/tools/fingerprint/autotest — 指纹识别 + POC 匹配 + 自动创建 AI 渗透任务。
func (s *Server) fingerprintAutoTest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.URL == "" {
		writeErr(w, 400, "url 必填")
		return
	}

	// 1) 指纹识别
	fp, err := doFingerprint(r.Context(), b.URL)
	if err != nil {
		writeErr(w, 502, "指纹识别失败: "+err.Error())
		return
	}

	// 2) POC 匹配
	matches := s.matchPOCByFingerprint(fp)

	// 3) 构建任务目标
	var goalLines []string
	goalLines = append(goalLines, fmt.Sprintf("对目标 %s 进行渗透测试。", b.URL))
	goalLines = append(goalLines, fmt.Sprintf("指纹识别结果：%s（Server: %s, X-Powered-By: %s）", fp.Fingerprint, fp.Server, fp.XPower))
	if len(matches) > 0 {
		goalLines = append(goalLines, fmt.Sprintf("已匹配 %d 个 POC 模板：", len(matches)))
		for i, m := range matches {
			if i >= 5 {
				break
			}
			goalLines = append(goalLines, fmt.Sprintf("  %d. %s（%s）", i+1, m.Name, m.Reason))
		}
		goalLines = append(goalLines, "优先验证以上 POC，然后进行手动渗透测试。")
	} else {
		goalLines = append(goalLines, "未匹配到 POC 模板，请手动进行渗透测试。")
	}
	goalLines = append(goalLines, "发现的漏洞用 report_finding 提交，截图用 bind_finding_evidence 绑定。")

	// 4) 创建探索图 + AI 渗透任务（tasks 需要 exploration_id）
	goalStr := strings.Join(goalLines, "\n")
	taskName := fmt.Sprintf("指纹联动渗透：%s", fp.Fingerprint)

	// 创建探索图
	var expID int64
	if err := s.m.PG().QueryRow(`INSERT INTO explorations(description, goal) VALUES ($1,$2) RETURNING id`,
		b.URL, goalStr).Scan(&expID); err != nil {
		writeErr(w, 500, "创建探索图失败: "+err.Error())
		return
	}
	// 创建 origin fact 节点
	originPayload, _ := json.Marshal(map[string]any{
		"summary":     "指纹联动任务：" + taskName,
		"description": b.URL,
		"goal":        goalStr,
	})
	_, _ = s.m.PG().Exec(`INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
		VALUES ($1, 'fact', $2, 0, 'origin', 'system')`, expID, string(originPayload))

	// 创建任务
	var taskID int64
	err = s.m.PG().QueryRow(`INSERT INTO tasks (name, description, goal, exploration_id, category_id)
		VALUES ($1, $2, $3, $4, (SELECT id FROM task_categories WHERE name='Web' LIMIT 1))
		RETURNING id`, taskName, b.URL, goalStr, expID).Scan(&taskID)
	if err != nil {
		// 尝试无分类
		err = s.m.PG().QueryRow(`INSERT INTO tasks (name, description, goal, exploration_id)
			VALUES ($1, $2, $3, $4) RETURNING id`, taskName, b.URL, goalStr, expID).Scan(&taskID)
		if err != nil {
			writeErr(w, 500, "创建任务失败: "+err.Error())
			return
		}
	}

	s.c2AuditHashed("", "", "fingerprint_autotest", fmt.Sprintf("URL:%s FP:%s POCs:%d Task:%d", b.URL, fp.Fingerprint, len(matches), taskID))

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"fingerprint":  fp,
		"poc_matches":  matches,
		"task_id":      taskID,
		"task_goal":    strings.Join(goalLines, "\n"),
		"message":      fmt.Sprintf("✅ 指纹=%s，匹配 %d 个 POC，AI 渗透任务 #%d 已创建", fp.Fingerprint, len(matches), taskID),
	}})
}

// ═══════════════════════════════════════════════════════════════
// 4) Hook：load() 会话刷新时检测新上线
// ═══════════════════════════════════════════════════════════════

// initC2SessionNotify 在 c2StatusAPI 里 hook 检测新上线。
func (s *Server) initC2SessionNotify() {
	// 原有 c2StatusAPI / load 会话列表时调用 c2CheckNewSessions
	// 在 C2Console 的 load 回调中注入
}
