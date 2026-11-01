package server

// netexit.go — 测试网络出口（内网/互联网分线路由）：
//   网线直连内网测试入口时，Linux 路由表已让所有工具可达内网（direct 出口零配置）；
//   平台不在内网时，可配 socks5/http 代理出口。每条出口可绑定网段规则——平台原生
//   工具（端口扫描/目录扫描/指纹/Webshell）按「目标 IP 匹配网段 → 选出口」发包，
//   与 agent Bash 的全局代理（HTTP_PROXY/ALL_PROXY）互补。
//
//   GET  /api/network/exits        出口+规则配置
//   PUT  /api/network/exits        保存（校验 CIDR/代理 URL）
//   POST /api/network/check        连通自检：对出口经其自身路径探测样例目标

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"golang.org/x/net/proxy"
)

// insecureTLSConf 渗透目标常见自签证书的宽容 TLS 配置。
func insecureTLSConf() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

// NetExit 一个网络出口。Type: direct（本机直连，走系统路由——网线接内网口即通）/
// socks5 / http（代理地址，Addr 形如 socks5://10.0.0.1:1080 或 http://user:pass@ip:port）。
type NetExit struct {
	Name string `json:"name"`
	Type string `json:"type"` // direct | socks5 | http
	Addr string `json:"addr"` // direct 留空；proxy 填完整 URL
	Note string `json:"note"`
}

// NetRoute 网段 → 出口。有序匹配：命中即用；都没中用默认出口（DefaultExit）。
type NetRoute struct {
	CIDR     string `json:"cidr"`      // 如 192.168.0.0/16
	ExitName string `json:"exit_name"` // 对应 NetExit.Name
}

// NetExitConfig 配置整体（settings KV，key=network_exits）。
type NetExitConfig struct {
	Exits       []NetExit  `json:"exits"`
	Routes      []NetRoute `json:"routes"`
	DefaultExit string     `json:"default_exit"` // 兜底出口名（一般=互联网出口）
}

const netExitSettingKey = "network_exits"

func defaultNetExitConfig() NetExitConfig {
	return NetExitConfig{
		Exits: []NetExit{
			{Name: "互联网", Type: "direct", Note: "默认出口：本机系统路由直连"},
			{Name: "内网测试", Type: "direct", Note: "网线接内网测试入口后即通；平台不在内网时改为 socks5/http 代理"},
		},
		Routes: []NetRoute{
			{CIDR: "192.168.0.0/16", ExitName: "内网测试"},
			{CIDR: "10.0.0.0/8", ExitName: "内网测试"},
			{CIDR: "172.16.0.0/12", ExitName: "内网测试"},
		},
		DefaultExit: "互联网",
	}
}

// netExitConfig 读取（带 5s 缓存：扫描每个 host 都要查）。
func (s *Server) netExitConfig() NetExitConfig {
	s.netExitMu.Lock()
	defer s.netExitMu.Unlock()
	if time.Since(s.netExitCacheAt) < 5*time.Second {
		return s.netExitCache
	}
	cfg := defaultNetExitConfig()
	if raw, ok, _ := s.m.PG().GetSetting(netExitSettingKey); ok && raw != "" {
		var loaded NetExitConfig
		if json.Unmarshal([]byte(raw), &loaded) == nil && len(loaded.Exits) > 0 {
			cfg = loaded
		}
	}
	s.netExitCache, s.netExitCacheAt = cfg, time.Now()
	return cfg
}

func (s *Server) invalidateNetExitCache() {
	s.netExitMu.Lock()
	s.netExitCacheAt = time.Time{}
	s.netExitMu.Unlock()
}

// findExit 按名取出口；找不到返回 nil。
func (c NetExitConfig) findExit(name string) *NetExit {
	for i := range c.Exits {
		if c.Exits[i].Name == name {
			return &c.Exits[i]
		}
	}
	return nil
}

// validate 校验配置：CIDR 合法、路由出口存在、代理 URL 合法、默认出口存在。
func (c NetExitConfig) validate() error {
	seen := map[string]bool{}
	for _, e := range c.Exits {
		if e.Name == "" {
			return fmt.Errorf("出口名称不能为空")
		}
		if seen[e.Name] {
			return fmt.Errorf("出口名称重复：%s", e.Name)
		}
		seen[e.Name] = true
		switch e.Type {
		case "direct":
		case "socks5", "http", "https":
			u, err := url.Parse(e.Addr)
			if err != nil || u.Host == "" {
				return fmt.Errorf("出口 %s 的代理地址不合法：%q", e.Name, e.Addr)
			}
		default:
			return fmt.Errorf("出口 %s 类型必须是 direct/socks5/http", e.Name)
		}
	}
	for _, r := range c.Routes {
		if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
			return fmt.Errorf("网段不合法：%s", r.CIDR)
		}
		if !seen[r.ExitName] {
			return fmt.Errorf("网段 %s 指向的出口 %q 不存在", r.CIDR, r.ExitName)
		}
	}
	if c.DefaultExit != "" && !seen[c.DefaultExit] {
		return fmt.Errorf("默认出口 %q 不存在", c.DefaultExit)
	}
	return nil
}

// MatchExit 按目标 host（IP 或域名）选出口。域名不匹配网段 → 默认出口。
func (s *Server) MatchExit(host string) *NetExit {
	cfg := s.netExitConfig()
	if ip := net.ParseIP(host); ip != nil {
		for _, r := range cfg.Routes {
			if _, net4, err := net.ParseCIDR(r.CIDR); err == nil && net4.Contains(ip) {
				if e := cfg.findExit(r.ExitName); e != nil {
					return e
				}
			}
		}
	}
	if e := cfg.findExit(cfg.DefaultExit); e != nil {
		return e
	}
	return &NetExit{Name: "direct", Type: "direct"}
}

// ExitHTTPClient 按出口构造 HTTP 客户端（direct=系统路由直连；socks5/http=经代理）。
// 调用方自行叠加 Timeout/InsecureSkipVerify。
func ExitHTTPClient(e *NetExit, timeout time.Duration, insecureTLS bool) *http.Client {
	tr := &http.Transport{}
	if insecureTLS {
		tr.TLSClientConfig = insecureTLSConf()
	}
	switch e.Type {
	case "socks5", "http", "https":
		if u, err := url.Parse(e.Addr); err == nil && u.Host != "" {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// ExitDialContext 按出口返回 TCP 拨号函数（端口扫描用）。
// direct → 系统路由（网线内网口即通）；socks5 → SOCKS5 拨号；http 代理不支持
// 任意 TCP 拨号（仅 CONNECT），返回明确错误让扫描层提示改 socks5。
func ExitDialContext(ctx context.Context, e *NetExit, timeout time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if e == nil || e.Type == "direct" {
		d := &net.Dialer{Timeout: timeout}
		return d.DialContext, nil
	}
	if e.Type == "socks5" {
		u, err := url.Parse(e.Addr)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("socks5 出口地址不合法")
		}
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext, nil
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}, nil
	}
	return nil, fmt.Errorf("出口 %s 是 http 代理：不支持端口扫描的任意 TCP 拨号，请为该网段配 socks5 出口或 direct", e.Name)
}

// exitProxyFor 目标 URL 应走的出口代理地址（direct 出口返回空串=直连）。
// 供 webshell API / agent 注入回调统一使用。
func (s *Server) exitProxyFor(targetURL string) string {
	host := targetURL
	if u, err := url.Parse(targetURL); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	if e := s.MatchExit(host); e != nil && (e.Type == "socks5" || e.Type == "http" || e.Type == "https") {
		return e.Addr
	}
	return ""
}

// ---- API ----

func (s *Server) netExitsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"data": s.netExitConfig()})
}

func (s *Server) netExitsSet(w http.ResponseWriter, r *http.Request) {
	var cfg NetExitConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if err := cfg.validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	raw, _ := json.Marshal(cfg)
	if _, err := s.m.PG().Exec(`INSERT INTO settings (key, value) VALUES ($1,$2)
		ON CONFLICT (key) DO UPDATE SET value=$2`, netExitSettingKey, string(raw)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.invalidateNetExitCache()
	writeJSON(w, 200, map[string]any{"data": cfg})
}

// netExitCheck 连通自检：POST {exit_name, probe_host, probe_port}
//   direct → 本机直连 TCP 探测；socks5/http → 经代理 TCP（socks5）或 HTTP GET（http）。
func (s *Server) netExitCheck(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ExitName  string `json:"exit_name"`
		ProbeHost string `json:"probe_host"`
		ProbePort int    `json:"probe_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	cfg := s.netExitConfig()
	e := cfg.findExit(b.ExitName)
	if e == nil {
		writeErr(w, 404, "出口不存在")
		return
	}
	if b.ProbeHost == "" {
		b.ProbeHost = "223.5.5.5" // direct 出口默认探公网 DNS TCP
		if b.ProbePort == 0 {
			b.ProbePort = 53
		}
	}
	if b.ProbePort == 0 {
		b.ProbePort = 80
	}
	addr := net.JoinHostPort(b.ProbeHost, fmt.Sprint(b.ProbePort))
	start := time.Now()

	if e.Type == "http" || e.Type == "https" {
		// HTTP 代理：经代理 GET http://probe（80 端口）验证链路
		client := ExitHTTPClient(e, 8*time.Second, true)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+addr+"/", nil)
		resp, err := client.Do(req)
		if err != nil {
			writeJSON(w, 200, map[string]any{"data": map[string]any{"ok": false, "error": "经代理探测失败: " + err.Error(), "ms": time.Since(start).Milliseconds()}})
			return
		}
		resp.Body.Close()
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ok": true, "detail": fmt.Sprintf("经代理连通 %s（HTTP %d）", addr, resp.StatusCode), "ms": time.Since(start).Milliseconds()}})
		return
	}

	dial, err := ExitDialContext(r.Context(), e, 5*time.Second)
	if err != nil {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ok": false, "error": err.Error()}})
		return
	}
	conn, err := dial(r.Context(), "tcp", addr)
	if err != nil {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ok": false, "error": "探测 " + addr + " 失败: " + err.Error(), "ms": time.Since(start).Milliseconds()}})
		return
	}
	conn.Close()
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"ok": true, "detail": fmt.Sprintf("出口 %s（%s）连通 %s，耗时 %dms", e.Name, e.Type, addr, time.Since(start).Milliseconds()),
		"ms": time.Since(start).Milliseconds(),
	}})
}

// sortedExitNames 供 UI 下拉。
func (c NetExitConfig) sortedExitNames() []string {
	names := make([]string, 0, len(c.Exits))
	for _, e := range c.Exits {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return names
}
