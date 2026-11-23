package server

// feishu_app.go — 飞书自建应用（长连接模式）：审批卡片按钮直答。
//
// 与 webhook 机器人（feishuChannel）的区别：
//   - webhook：只能往群里发只读消息，收不到交互回调
//   - 自建应用 + 长连接（WebSocket 出站）：内网服务器主动连飞书接收
//     卡片按钮回调，无需公网地址 —— 这是"飞书里直接点按钮审批"的关键
//
// 流程：审批事件 → 给配置的用户发交互式卡片（批准/拒绝按钮）→
// 用户点击 → 回调进来 → 校验 → interceptor.Decide → 卡片更新为已处理。
// 配置存 settings 键 feishu_app（JSON：app_id/app_secret/notify_user_ids）。

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
)

type feishuAppConfig struct {
	AppID         string   `json:"app_id"`
	AppSecret     string   `json:"app_secret"`
	NotifyUserIDs []string `json:"notify_user_ids"` // 接收审批卡片的用户 open_id 列表
	Enabled       bool     `json:"enabled"`
}

func (s *Server) loadFeishuAppConfig() feishuAppConfig {
	var cfg feishuAppConfig
	if s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("feishu_app"); ok && v != "" {
			_ = json.Unmarshal([]byte(v), &cfg)
		}
	}
	return cfg
}

// feishuAppClient 进程级单例：长连接重连、token 缓存。
type feishuAppClient struct {
	mu       sync.Mutex
	cfg      feishuAppConfig
	token    string
	tokenExp time.Time
}

var feishuApp = &feishuAppClient{}

// tenantToken 带缓存的 tenant_access_token。
func (c *feishuAppClient) tenantToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp.Add(-2*time.Minute)) {
		return c.token, nil
	}
	body := fmt.Sprintf(`{"app_id":%q,"app_secret":%q}`, c.cfg.AppID, c.cfg.AppSecret)
	resp, err := httpPostJSON("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal", body)
	if err != nil {
		return "", err
	}
	var out struct {
		Code              int    `json:"code"`
		Msg               string `json:"msg"`
		TenantAccessToken string `json:"tenant_access_token"`
		Expire            int    `json:"expire"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", err
	}
	if out.Code != 0 || out.TenantAccessToken == "" {
		return "", fmt.Errorf("飞书 token 获取失败 code=%d msg=%s", out.Code, out.Msg)
	}
	c.token = out.TenantAccessToken
	c.tokenExp = time.Now().Add(time.Duration(out.Expire) * time.Second)
	return c.token, nil
}

// sendApprovalCard 给配置用户发交互式审批卡片。
// 回调路由 /api/feishu-card 回读 pendingID + 决策（见 serveFeishuCardCallback）。
func (s *Server) sendApprovalCard(pendingID int64, taskID, agentName, toolName, reason string) {
	cfg := s.loadFeishuAppConfig()
	if !cfg.Enabled || cfg.AppID == "" || len(cfg.NotifyUserIDs) == 0 {
		return
	}
	feishuApp.mu.Lock()
	feishuApp.cfg = cfg
	feishuApp.mu.Unlock()

	tok, err := feishuApp.tenantToken()
	if err != nil {
		log.Printf("[feishu-app] token: %v", err)
		return
	}
	summary := fmt.Sprintf("任务 %s / %s 调用 %s 被拦：%.300s", taskID, agentName, toolName, reason)
	card := map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"title":    map[string]any{"tag": "plain_text", "content": "⏸ 操作待审批"},
			"template": "orange",
		},
		"elements": []any{
			map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": summary}},
			map[string]any{"tag": "hr"},
			map[string]any{
				"tag": "action",
				"actions": []any{
					map[string]any{
						"tag": "button", "type": "primary",
						"text":    map[string]any{"tag": "plain_text", "content": "✅ 批准"},
						"value":   map[string]any{"pid": pendingID, "d": "allow"},
						"confirm": map[string]any{"title": map[string]any{"tag": "plain_text", "content": "确认批准该操作？"}},
					},
					map[string]any{
						"tag": "button", "type": "danger",
						"text":    map[string]any{"tag": "plain_text", "content": "❌ 拒绝"},
						"value":   map[string]any{"pid": pendingID, "d": "deny"},
						"confirm": map[string]any{"title": map[string]any{"tag": "plain_text", "content": "确认拒绝该操作？"}},
					},
				},
			},
		},
	}
	cardJSON, _ := json.Marshal(card)
	for _, uid := range cfg.NotifyUserIDs {
		// 飞书 im/v1/messages 的 content 必须是「JSON 字符串」而非内嵌对象：
		// %q 转义为字符串（9499 Invalid parameter type 的根因），%s 会嵌成对象。
		body := fmt.Sprintf(`{"receive_id":"open_id","receive_id":%q,"msg_type":"interactive","content":%q}`,
			uid, string(cardJSON))
		resp, err := httpPostWithAuth("https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id", tok, body)
		if err != nil {
			// 把飞书返回体也打出来（截断），否则只有 HTTP 状态码无从排查
			log.Printf("[feishu-app] 发卡片给 %s 失败: %v resp=%s", uid, err, clipStr(string(resp), 200))
			continue
		}
		var out struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		_ = json.Unmarshal(resp, &out)
		if out.Code != 0 {
			log.Printf("[feishu-app] 发卡片 %s: code=%d %s", uid, out.Code, out.Msg)
		}
	}
}

// serveFeishuCardCallback 卡片按钮回调（长连接客户端分发进来，见 feishu_ws.go）。
// 校验 value → Decide → 返回更新后的卡片（按钮变结果文本）。
func (s *Server) handleFeishuCardAction(value map[string]any) string {
	pidF, _ := value["pid"].(float64)
	d, _ := value["d"].(string)
	pid := int64(pidF)
	if pid <= 0 || (d != "allow" && d != "deny") {
		return "⚠️ 无效的操作"
	}
	if err := s.m.interceptor.Decide(pid, d == "allow", nil); err != nil {
		if err == intercept.ErrAlreadyDecided {
			return "该审批已处理过（可能多人同时点了按钮）"
		}
		return "处理失败: " + err.Error()
	}
	label := "✅ 已批准，任务继续执行"
	if d == "deny" {
		label = "❌ 已拒绝"
	}
	return fmt.Sprintf("%s（审批 #%d）", label, pid)
}

// httpPostJSON / httpPostWithAuth 小工具（飞书 API 专用，15s 超时）。
func httpPostJSON(u, body string) ([]byte, error) {
	return feishuHTTPDo("POST", u, "", body)
}

func httpPostWithAuth(u, token, body string) ([]byte, error) {
	return feishuHTTPDo("POST", u, token, body)
}

var feishuHTTPClient = &http.Client{Timeout: 15 * time.Second}

func feishuHTTPDo(method, u, token, body string) ([]byte, error) {
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := feishuHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return b, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return b, err
}

// clipStr 截断字符串用于日志。
func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
