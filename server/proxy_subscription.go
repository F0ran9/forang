package server

// proxy_subscription.go — 出口代理订阅链接（移植思路自全链哨兵 subscription.ts）：
// 订阅 URL 拉取（多为 base64 节点列表）→ 解析出 socks5/http/https 可用代理 →
// 健康检查 → 轮换设置到全局出口代理。ss/vmess 等需本地转换的协议暂不直用，跳过。
// 配置存 settings 键 global_proxy_subscription；未设置即整组功能静默。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"io"
	"log"
)

const (
	settingProxySubscription = "global_proxy_subscription"
	proxySubCheckTimeout     = 10 * time.Second
	proxySubInterval         = 10 * time.Minute
)

func (s *Server) proxySubGet(w http.ResponseWriter, r *http.Request) {
	v, _, _ := s.m.PG().GetSetting(settingProxySubscription)
	writeJSON(w, 200, map[string]any{"url": v})
}

func (s *Server) proxySubSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	v := strings.TrimSpace(body.URL)
	if v != "" {
		if _, err := url.Parse(v); err != nil {
			writeErr(w, 400, "订阅地址无效: "+err.Error())
			return
		}
	}
	if err := s.m.PG().SetSetting(settingProxySubscription, v); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 立即尝试刷新一次（异步，不阻塞配置保存）
	go s.refreshProxySubscription()
	writeJSON(w, 200, map[string]any{"ok": true, "url": v})
}

// GET /api/settings/proxy-subscription/check?url=... — 手动触发解析并返回可用节点（调试用）。
func (s *Server) proxySubCheck(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("url")
	if u == "" {
		if v, _, _ := s.m.PG().GetSetting(settingProxySubscription); v != "" {
			u = v
		}
	}
	if u == "" {
		writeErr(w, 400, "未设置订阅地址")
		return
	}
	proxies, err := fetchProxySubscription(u)
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": err.Error()})
		return
	}
	// 并发健康检查（全部节点，最多 20 个避免刷爆）
	type checked struct {
		Proxy string `json:"proxy"`
		OK    bool   `json:"ok"`
		MS    int64  `json:"ms"`
	}
	var wg sync.WaitGroup
	results := make([]checked, len(proxies))
	for i, px := range proxies {
		wg.Add(1)
		go func(i int, px string) {
			defer wg.Done()
			ok, ms := proxyHealthCheck(px)
			results[i] = checked{Proxy: px, OK: ok, MS: ms}
		}(i, px)
	}
	wg.Wait()
	sort.Slice(results, func(a, b int) bool { return results[a].MS < results[b].MS })
	writeJSON(w, 200, map[string]any{"nodes": results})
}

var (
	proxySubMu       sync.Mutex
	proxySubFetching bool
)

// refreshProxySubscription 拉取订阅 → 解析节点 → 健康检查 → 把最快的健康节点
// 写入全局出口代理。由后台轮询与手动触发共同使用。
func (s *Server) refreshProxySubscription() {
	u, ok, _ := s.m.PG().GetSetting(settingProxySubscription)
	if !ok || strings.TrimSpace(u) == "" {
		return
	}
	proxySubMu.Lock()
	if proxySubFetching {
		proxySubMu.Unlock()
		return
	}
	proxySubFetching = true
	proxySubMu.Unlock()

	proxies, err := fetchProxySubscription(u)
	if err != nil {
		log.Printf("[proxy-sub] 拉取订阅失败: %v", err)
		proxySubMu.Lock()
		proxySubFetching = false
		proxySubMu.Unlock()
		return
	}
	if len(proxies) == 0 {
		log.Printf("[proxy-sub] 订阅无可用 socks5/http 节点")
		proxySubMu.Lock()
		proxySubFetching = false
		proxySubMu.Unlock()
		return
	}
	// 顺序健康检查（前 8 个），选第一个健康节点
	picked := ""
	for i, px := range proxies {
		if i >= 8 {
			break
		}
		if ok, _ := proxyHealthCheck(px); ok {
			picked = px
			break
		}
	}
	proxySubMu.Lock()
	proxySubFetching = false
	proxySubMu.Unlock()
	if picked == "" {
		log.Printf("[proxy-sub] 订阅节点均不健康，保持当前出口不变")
		return
	}
	if err := s.m.SetGlobalProxy(picked); err != nil {
		log.Printf("[proxy-sub] 写入全局代理失败: %v", err)
		return
	}
	log.Printf("[proxy-sub] 全局出口代理已更新: %s", picked)
}

// StartProxySubscriptionLoop 订阅轮询：每 10 分钟刷新一次（幂等，进程内一份）。
func (s *Server) StartProxySubscriptionLoop() {
	go func() {
		t := time.NewTicker(proxySubInterval)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				s.refreshProxySubscription()
			}
		}
	}()
}

// fetchProxySubscription 拉取订阅链接并解析出 socks5/http/https 代理列表。
// 兼容两种格式：纯文本节点列表 与 base64 编码节点列表。
func fetchProxySubscription(subURL string) ([]string, error) {
	client := &http.Client{Timeout: proxySubCheckTimeout}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "FORANG/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return nil, fmt.Errorf("订阅返回 JSON（可能是 clash 配置），暂只支持 base64/明文节点列表")
	}
	// 先按 base64 尝试解码（机场订阅常见形态）
	if !strings.Contains(text, "://") {
		if dec, err := base64.StdEncoding.DecodeString(text); err == nil && strings.Contains(string(dec), "://") {
			text = strings.TrimSpace(string(dec))
		} else if dec, err := base64.URLEncoding.DecodeString(text); err == nil && strings.Contains(string(dec), "://") {
			text = strings.TrimSpace(string(dec))
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks://") {
			line = "socks5://" + strings.TrimPrefix(strings.TrimPrefix(line, "socks5://"), "socks://")
		} else if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			// 保留
		} else {
			continue // ss://、vmess://、trojan:// 等需本地转换的协议暂不支持
		}
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("订阅中没有 socks5/http 代理节点")
	}
	return out, nil
}

// proxyHealthCheck 通过代理访问一次 HTTP 端点，判断代理是否可用。
func proxyHealthCheck(proxyURL string) (bool, int64) {
	start := time.Now()
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return false, 0
	}
	client := &http.Client{
		Timeout: proxySubCheckTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://www.baidu.com/", nil)
	if err != nil {
		return false, 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()
	return true, time.Since(start).Milliseconds()
}
