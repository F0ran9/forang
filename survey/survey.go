// Package survey — 公网资产测绘（FOFA / 360 Quake / 奇安信 Hunter）。
// 移植自 Full-Chain-Sentinel-System asset-platforms.ts + asset-config.ts（MIT），
// API 参数/鉴权/分页/限速语义全部照抄：
//   FOFA   GET /api/v1/search/all?key=&qbase64=<标准base64>&size=&page=&fields=<固定列表>
//   Quake  POST /api/v3/search/quake_service  Header X-QuakeToken，body {query,start,size}（start 偏移分页）
//   Hunter GET /openApi/search?api-key=&search=<base64URL去垫片>&page=&page_size=<吸附[1,10,20,50,100]>&is_web=1
// 通用机制：每平台串行队列；可重试错误（q3005/频率/429）退避 1.5s/4s 重试 2 次；
// 原始响应落 evidence；查询（含失败）记流水；配置存 settings（enabled+key+
// baseUrl+status 门控，只有可用平台工具才真正出结果）。
package survey

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

type Platform string

const (
	Fofa   Platform = "fofa"
	Quake  Platform = "quake"
	Hunter Platform = "hunter"
)

var Platforms = []Platform{Fofa, Quake, Hunter}

var labels = map[Platform]string{Fofa: "FOFA", Quake: "360 Quake", Hunter: "奇安信 Hunter"}

var syntax = map[Platform]string{
	Fofa:   `ip="1.1.1.1"、domain="example.com"、title="后台"、body="login"、port="8080"`,
	Quake:  `ip:"1.1.1.1"、domain:"example.com"、title:"后台"、port:8080、service:"http"`,
	Hunter: `ip="1.1.1.1"、domain="example.com"、web.title="后台"、port="8080"（page_size 只接受 1/10/20/50/100）`,
}

// Record 归一化的一条资产。
type Record struct {
	IP, Port, Host, Domain, URL, Title, Server, Protocol, OS, Org, Country, Province, City, Updated, Banner string
}

// Result 一次查询的完整产物。
type Result struct {
	Platform     Platform
	Query        string
	Page, Size   int
	Total        int64
	Count        int
	Quota        string
	EvidencePath string
	Records      []Record
}

// Config 单平台配置（settings 键 survey.<platform> 的 JSON）。
type Config struct {
	Enabled  bool   `json:"enabled"`
	Key      string `json:"key"`
	BaseURL  string `json:"base_url"`
	StatusOK bool   `json:"status_ok"`
	StatusAt int64  `json:"status_at"` // unix ms；0=从未验证
	StatusErr string `json:"status_error"`
	StatusQuota string `json:"status_quota"`
}

// Service 测绘服务：配置 + 客户端 + 流水 + 证据。
type Service struct {
	db  *db.DB
	dir string // evidence 根（平台工作目录）
	mu  map[Platform]*sync.Mutex
	http *http.Client
}

func NewService(d *db.DB, evidenceDir string) *Service {
	m := map[Platform]*sync.Mutex{}
	for _, p := range Platforms {
		m[p] = &sync.Mutex{}
	}
	return &Service{db: d, dir: evidenceDir, mu: m,
		http: &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}}}
}

// ---------- 配置 ----------

func (s *Service) loadConfig(p Platform) Config {
	var c Config
	if s.db == nil {
		return c
	}
	if v, ok, _ := s.db.GetSetting("survey." + string(p)); ok {
		_ = json.Unmarshal([]byte(v), &c)
	}
	return c
}

func (s *Service) saveConfig(p Platform, c Config) error {
	b, _ := json.Marshal(c)
	return s.db.SetSetting("survey."+string(p), string(b))
}

// ConfigView UI 视图（key 只回尾 4 位）。
func (s *Service) ConfigView(p Platform) map[string]any {
	c := s.loadConfig(p)
	tail := ""
	if len(c.Key) >= 4 {
		tail = c.Key[len(c.Key)-4:]
	}
	return map[string]any{
		"enabled": c.Enabled, "has_key": c.Key != "", "key_tail": tail,
		"base_url": c.BaseURL, "status_ok": c.StatusOK, "status_at": c.StatusAt,
		"status_error": c.StatusErr, "status_quota": c.StatusQuota,
		"usable": s.Usable(p), "syntax": syntax[p], "label": labels[p],
	}
}

// SaveConfig UI 保存（key 传 null/空=保持原值语义由调用方处理；这里 key=="" 表示清除）。
func (s *Service) SaveConfig(p Platform, enabled bool, key, baseURL string) (Config, error) {
	c := s.loadConfig(p)
	c.Enabled = enabled
	switch {
	case key == "\x00":
		// 显式清除（API 层把 "clear" 转成该哨兵值；空串表示保持原值）。
		c.Key, c.StatusOK, c.StatusAt = "", false, 0
	case key != "":
		c.Key = strings.TrimSpace(key)
		c.StatusOK, c.StatusAt = false, 0 // 换 key 后重新验证（哨兵语义）
	}
	if c.Key == "" {
		c.StatusOK, c.StatusAt = false, 0
	}
	c.BaseURL = normalizeBaseURL(baseURL)
	return c, s.saveConfig(p, c)
}

// Usable 哨兵门控：enabled && key 非空 && 验证通过。
func (s *Service) Usable(p Platform) bool {
	c := s.loadConfig(p)
	return c.Enabled && c.Key != "" && c.StatusOK && c.StatusAt > 0
}

func normalizeBaseURL(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/")
}

// endpoint 哨兵 assetEndpoint：baseURL 是前缀，官方 pathname 拼在后面。
func endpoint(official string, base string) string {
	if base == "" {
		return official
	}
	u, err := url.Parse(base)
	if err != nil {
		return official
	}
	o, err := url.Parse(official)
	if err != nil {
		return official
	}
	u.Path = strings.TrimRight(u.Path, "/") + o.Path
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// ---------- 平台客户端 ----------

var retryableRe = regexp.MustCompile(`q3005|频率|过于频繁|too many|rate.?limit|429`)

type platformError struct{ msg string; retryable bool }

func (e *platformError) Error() string { return e.msg }

var fofaFields = []string{"host", "ip", "port", "domain", "title", "server", "protocol", "country", "province", "city", "org", "os", "updated_at"}

func (s *Service) do(ctx context.Context, method, u string, header map[string]string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if header["Content-Type"] == "" && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 500 {
		return b, &platformError{msg: fmt.Sprintf("HTTP %d", resp.StatusCode), retryable: true}
	}
	return b, nil
}

// Search 统一入口：串行 + 限速重试 + 归一化 + 证据 + 流水。
func (s *Service) Search(ctx context.Context, p Platform, query string, page, size int) (*Result, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	c := s.loadConfig(p)
	if !s.Usable(p) {
		return nil, fmt.Errorf("%s 未配置或未验证：请操作员到「设置→资产测绘」配置并测试通过后使用", labels[p])
	}
	s.mu[p].Lock()
	defer s.mu[p].Unlock()

	start := time.Now()
	var res *Result
	var lastErr error
	backoff := []time.Duration{0, 1500 * time.Millisecond, 4000 * time.Millisecond}
	for i, bo := range backoff {
		if bo > 0 {
			select {
			case <-time.After(bo):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var err error
		res, err = s.searchOnce(ctx, p, c, query, page, size)
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		pe, ok := err.(*platformError)
		if !ok || !pe.retryable || i == len(backoff)-1 {
			break
		}
	}
	latency := time.Since(start).Milliseconds()
	ok := lastErr == nil && res != nil
	evPath := ""
	if res != nil {
		evPath = res.EvidencePath
	}
	q := ""
	if res != nil {
		q = res.Quota
	}
	_ = q // quota 由 logQuery 从 res 内部读取，这里保留下次接流水限额的入口
	s.logQuery(p, query, page, size, res, ok, latency, lastErr, evPath)
	if lastErr != nil {
		return nil, lastErr
	}
	return res, nil
}

func (s *Service) searchOnce(ctx context.Context, p Platform, c Config, query string, page, size int) (*Result, error) {
	switch p {
	case Fofa:
		return s.searchFofa(ctx, c, query, page, size)
	case Quake:
		return s.searchQuake(ctx, c, query, page, size)
	case Hunter:
		return s.searchHunter(ctx, c, query, page, size)
	}
	return nil, fmt.Errorf("未知平台 %s", p)
}

func (s *Service) searchFofa(ctx context.Context, c Config, query string, page, size int) (*Result, error) {
	u, _ := url.Parse(endpoint("https://fofa.info/api/v1/search/all", c.BaseURL))
	q := u.Query()
	q.Set("key", c.Key)
	q.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	q.Set("size", fmt.Sprint(size))
	q.Set("page", fmt.Sprint(page))
	q.Set("fields", strings.Join(fofaFields, ","))
	u.RawQuery = q.Encode()
	b, err := s.do(ctx, "GET", u.String(), nil, nil)
	if err != nil {
		return nil, &platformError{msg: err.Error(), retryable: true}
	}
	var raw struct {
		Error   bool     `json:"error"`
		Errmsg  string   `json:"errmsg"`
		Size    int      `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, &platformError{msg: "响应不是 JSON（key/baseURL 是否正确）", retryable: false}
	}
	if raw.Error {
		return nil, &platformError{msg: raw.Errmsg, retryable: retryableRe.MatchString(raw.Errmsg)}
	}
	res := &Result{Platform: Fofa, Query: query, Page: page, Size: size, Total: int64(raw.Size)}
	idx := map[string]int{}
	for i, f := range fofaFields {
		idx[f] = i
	}
	get := func(r []string, k string) string {
		if i, ok := idx[k]; ok && i < len(r) {
			return r[i]
		}
		return ""
	}
	for _, r := range raw.Results {
		res.Records = append(res.Records, Record{
			IP: get(r, "ip"), Port: get(r, "port"), Host: get(r, "host"), Domain: get(r, "domain"),
			Title: get(r, "title"), Server: get(r, "server"), Protocol: get(r, "protocol"),
			OS: get(r, "os"), Org: get(r, "org"), Country: get(r, "country"), Province: get(r, "province"),
			City: get(r, "city"), Updated: get(r, "updated_at"),
		})
	}
	res.Count = len(res.Records)
	res.EvidencePath = s.writeEvidence(Fofa, page, b)
	// FOFA 每页固定 size 条；配额行从 info 接口来的存在 status 里，这里附带
	if c.StatusQuota != "" {
		res.Quota = c.StatusQuota
	}
	return res, nil
}

func (s *Service) searchQuake(ctx context.Context, c Config, query string, page, size int) (*Result, error) {
	body, _ := json.Marshal(map[string]any{"query": query, "start": (page - 1) * size, "size": size})
	b, err := s.do(ctx, "POST", endpoint("https://quake.360.net/api/v3/search/quake_service", c.BaseURL),
		map[string]string{"X-QuakeToken": c.Key}, body)
	if err != nil {
		return nil, &platformError{msg: err.Error(), retryable: true}
	}
	if bytes.Contains(b, []byte("/quake/login")) {
		return nil, &platformError{msg: "令牌无效或已过期（Quake 返回登录跳转）", retryable: false}
	}
	var raw struct {
		Code    any `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Total int64 `json:"total"`
			List  []struct {
				IP, Port  any
				Hostname, Domain, Org string
				Time  string
				Location struct{ CountryCn, ProvinceCn, CityCn string }
				Service struct {
					Response, Name, Version string
				}
				Components []struct{ ProductNameCn, ProductNameEn string }
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, &platformError{msg: "响应不是 JSON（token 是否正确）", retryable: false}
	}
	codeStr := fmt.Sprint(raw.Code)
	if codeStr != "0" {
		return nil, &platformError{msg: fmt.Sprintf("%s（code %s）", raw.Message, codeStr), retryable: codeStr == "q3005" || retryableRe.MatchString(raw.Message)}
	}
	res := &Result{Platform: Quake, Query: query, Page: page, Size: size, Total: raw.Data.Total}
	for _, it := range raw.Data.List {
		org := it.Org
		prod := ""
		if len(it.Components) > 0 {
			prod = it.Components[0].ProductNameCn
			if prod == "" {
				prod = it.Components[0].ProductNameEn
			}
		}
		res.Records = append(res.Records, Record{
			IP: anyStr(it.IP), Port: anyStr(it.Port), Host: it.Hostname, Domain: it.Domain,
			Title: prod, Server: it.Service.Version, Protocol: it.Service.Name,
			Org: org, Country: it.Location.CountryCn, Province: it.Location.ProvinceCn, City: it.Location.CityCn,
			Updated: it.Time, Banner: clip(it.Service.Response, 400),
		})
	}
	res.Count = len(res.Records)
	res.EvidencePath = s.writeEvidence(Quake, page, b)
	if c.StatusQuota != "" {
		res.Quota = c.StatusQuota
	}
	return res, nil
}

var hunterPageSizes = []int{1, 10, 20, 50, 100}

func hunterPageSize(size int) int {
	for _, v := range hunterPageSizes {
		if v >= size {
			return v
		}
	}
	return 100
}

func (s *Service) searchHunter(ctx context.Context, c Config, query string, page, size int) (*Result, error) {
	u, _ := url.Parse(endpoint("https://hunter.qianxin.com/openApi/search", c.BaseURL))
	q := u.Query()
	q.Set("api-key", c.Key)
	b64 := base64.URLEncoding.EncodeToString([]byte(query))
	q.Set("search", strings.TrimRight(b64, "="))
	q.Set("page", fmt.Sprint(page))
	q.Set("page_size", fmt.Sprint(hunterPageSize(size)))
	q.Set("is_web", "1")
	u.RawQuery = q.Encode()
	b, err := s.do(ctx, "GET", u.String(), nil, nil)
	if err != nil {
		return nil, &platformError{msg: err.Error(), retryable: true}
	}
	var raw struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Total   int64 `json:"total"`
			ConsumeQuota int64 `json:"consume_quota"`
			RestQuota    int64 `json:"rest_quota"`
			SyntaxPrompt []string `json:"syntax_prompt"`
			Arr []struct {
				IP, Port any
				Domain, URL, WebTitle, HeaderServer, Protocol, OS string
				Company, Isp, AsOrg, Country, Province, City, UpdatedAt, Banner, Header string
			} `json:"arr"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, &platformError{msg: "响应不是 JSON（api-key 是否正确）", retryable: false}
	}
	if raw.Code != 200 {
		msg := fmt.Sprintf("%s（code %d）", raw.Message, raw.Code)
		return nil, &platformError{msg: msg, retryable: raw.Code == 429 || retryableRe.MatchString(raw.Message)}
	}
	res := &Result{Platform: Hunter, Query: query, Page: page, Size: size, Total: raw.Data.Total}
	for _, it := range raw.Data.Arr {
		org := it.Company
		if org == "" {
			org = it.Isp
		}
		if org == "" {
			org = it.AsOrg
		}
		banner := it.Banner
		if banner == "" {
			banner = it.Header
		}
		res.Records = append(res.Records, Record{
			IP: anyStr(it.IP), Port: anyStr(it.Port), Domain: it.Domain, URL: it.URL,
			Title: it.WebTitle, Server: it.HeaderServer, Protocol: it.Protocol, OS: it.OS,
			Org: org, Country: it.Country, Province: it.Province, City: it.City, Updated: it.UpdatedAt,
			Banner: clip(banner, 400),
		})
	}
	res.Count = len(res.Records)
	res.Quota = fmt.Sprintf("本次消耗 %d 点，剩余 %d 点", raw.Data.ConsumeQuota, raw.Data.RestQuota)
	if spN := len(raw.Data.SyntaxPrompt); spN > 0 {
		if spN > 3 {
			spN = 3
		}
		res.Quota += "；平台语法提示：" + strings.Join(raw.Data.SyntaxPrompt[:spN], "；")
	}
	res.EvidencePath = s.writeEvidence(Hunter, page, b)
	return res, nil
}

func anyStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case int:
		return fmt.Sprint(t)
	case int64:
		return fmt.Sprint(t)
	}
	return fmt.Sprint(v)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ---------- 验证（账号信息接口） ----------

// Probe 验证 key（保存后自动跑；也可单独测）。成功会写回 status。
func (s *Service) Probe(ctx context.Context, p Platform, keyOverride, baseURLOverride string) (bool, string, error) {
	c := s.loadConfig(p)
	if keyOverride != "" {
		c.Key = strings.TrimSpace(keyOverride)
	}
	if baseURLOverride != "" || keyOverride != "" {
		if baseURLOverride != "" {
			c.BaseURL = normalizeBaseURL(baseURLOverride)
		}
	}
	if c.Key == "" {
		return false, "", fmt.Errorf("未配置 API Key")
	}
	var ok bool
	var quota string
	var err error
	switch p {
	case Fofa:
		ok, quota, err = s.probeFofa(ctx, c)
	case Quake:
		ok, quota, err = s.probeQuake(ctx, c)
	case Hunter:
		ok, quota, err = s.probeHunter(ctx, c)
	default:
		return false, "", fmt.Errorf("未知平台")
	}
	c.StatusOK, c.StatusAt, c.StatusQuota = ok, time.Now().UnixMilli(), quota
	if !ok && err != nil {
		c.StatusErr = err.Error()
	} else {
		c.StatusErr = ""
	}
	_ = s.saveConfig(p, c)
	return ok, quota, err
}

func (s *Service) probeFofa(ctx context.Context, c Config) (bool, string, error) {
	b, err := s.do(ctx, "GET", endpoint("https://fofa.info/api/v1/info/my?key="+url.QueryEscape(c.Key), c.BaseURL), nil, nil)
	if err != nil {
		return false, "", err
	}
	var raw struct {
		Error           bool    `json:"error"`
		Errmsg          string  `json:"errmsg"`
		FofaPoint       float64 `json:"fofa_point,string"`
		RemainFreePoint float64 `json:"remain_free_point,string"`
		IsVIP           float64 `json:"isvip,string"`
		VIPLevel        float64 `json:"vip_level,string"`
	}
	_ = json.Unmarshal(b, &raw)
	if raw.Error {
		return false, "", fmt.Errorf("%s", raw.Errmsg)
	}
	var vip string
	if raw.VIPLevel > 0 {
		vip = fmt.Sprintf(" · VIP%.0f", raw.VIPLevel)
	}
	return true, fmt.Sprintf("免费点 %.0f · F 点 %.0f%s", raw.RemainFreePoint, raw.FofaPoint, vip), nil
}

func (s *Service) probeQuake(ctx context.Context, c Config) (bool, string, error) {
	b, err := s.do(ctx, "GET", endpoint("https://quake.360.net/api/v3/user/info", c.BaseURL), map[string]string{"X-QuakeToken": c.Key}, nil)
	if err != nil {
		return false, "", err
	}
	if bytes.Contains(b, []byte("/quake/login")) {
		return false, "", fmt.Errorf("令牌无效或已过期（Quake 返回登录跳转）")
	}
	var raw struct {
		Code any `json:"code"`
		Message string `json:"message"`
		Data struct {
			MonthRemainingCredit float64 `json:"month_remaining_credit"`
			Credit float64 `json:"credit"`
			Baned bool `json:"baned"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return false, "", fmt.Errorf("响应不是 JSON")
	}
	if raw.Data.Baned {
		return false, "", fmt.Errorf("Quake 账号已被封禁")
	}
	if fmt.Sprint(raw.Code) != "0" {
		return false, "", fmt.Errorf("%s（code %v）", raw.Message, raw.Code)
	}
	return true, fmt.Sprintf("本月剩余额度 %.0f 点 · 总额度 %.0f", raw.Data.MonthRemainingCredit, raw.Data.Credit), nil
}

func (s *Service) probeHunter(ctx context.Context, c Config) (bool, string, error) {
	u, _ := url.Parse(endpoint("https://hunter.qianxin.com/openApi/userInfo", c.BaseURL))
	q := u.Query()
	q.Set("api-key", c.Key)
	u.RawQuery = q.Encode()
	b, err := s.do(ctx, "GET", u.String(), nil, nil)
	if err != nil {
		return false, "", err
	}
	var raw struct {
		Code int `json:"code"`
		Message string `json:"message"`
		Data struct {
			RestFreePoint float64 `json:"rest_free_point"`
			DayFreePoint float64 `json:"day_free_point"`
			RestEquityPoint float64 `json:"rest_equity_point"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return false, "", fmt.Errorf("响应不是 JSON")
	}
	if raw.Code != 200 {
		return false, "", fmt.Errorf("%s（code %d）", raw.Message, raw.Code)
	}
	return true, fmt.Sprintf("免费点 %.0f / 每日 %.0f · 权益点 %.0f", raw.Data.RestFreePoint, raw.Data.DayFreePoint, raw.Data.RestEquityPoint), nil
}

// ---------- 证据 + 流水 ----------

func (s *Service) writeEvidence(p Platform, page int, raw []byte) string {
	if s.dir == "" {
		return ""
	}
	d := filepath.Join(s.dir, "evidence", "survey")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return ""
	}
	name := fmt.Sprintf("%s-p%d-%s.json", p, page, strings.ReplaceAll(time.Now().Format("20060102T150405"), ":", "-"))
	path := filepath.Join(d, name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return ""
	}
	return path
}

func (s *Service) logQuery(p Platform, query string, page, size int, res *Result, ok bool, latency int64, err error, ev string) {
	if s.db == nil {
		return
	}
	var total int64
	var count int
	quota := ""
	records, _ := json.Marshal([]Record{})
	if res != nil {
		total, count, quota = res.Total, res.Count, res.Quota
		if b, jerr := json.Marshal(res.Records); jerr == nil {
			records = b
		}
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	_, _ = s.db.Exec(`INSERT INTO survey_queries (platform, query, page, size, total, count, ok, latency_ms, quota, error, evidence_path, records)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		string(p), query, page, size, total, count, ok, latency, quota, errMsg, ev, string(records))
}

// ListLog 查询流水（UI 用）。
func (s *Service) ListLog(platform string, limit int) []map[string]any {
	if s.db == nil {
		return nil
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT platform, query, page, size, total, count, ok, latency_ms, quota, error, created_at
FROM survey_queries WHERE ($1='' OR platform=$1) ORDER BY id DESC LIMIT $2`, platform, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var p, q, quota, errMsg string
		var page, size, count int
		var total int64
		var lat int
		var ok bool
		var at time.Time
		if rows.Scan(&p, &q, &page, &size, &total, &count, &ok, &lat, &quota, &errMsg, &at) == nil {
			out = append(out, map[string]any{"platform": p, "query": q, "page": page, "size": size,
				"total": total, "count": count, "ok": ok, "latency_ms": lat, "quota": quota, "error": errMsg, "created_at": at})
		}
	}
	return out
}

// Syntax 平台语法提示（工具描述用）。
func Syntax(p Platform) string { return syntax[p] }
func Label(p Platform) string { return labels[p] }

var _ = sql.ErrNoRows
