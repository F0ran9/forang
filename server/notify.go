package server

// notify.go — Webhook 通知（钉钉/飞书，签名算法移植自 Full-Chain-Sentinel-System
// notify.ts，MIT：钉钉 timestamp+sign=HMAC-SHA256(webhook secret)；飞书 sign 同构）。
// 触发：评审确认的高危/严重漏洞。配置存 settings 键 notify.dingtalk /
// notify.feishu（JSON），未启用即静默。

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

type notifyChannel struct {
	Enabled bool   `json:"enabled"`
	Webhook string `json:"webhook"`
	Secret  string `json:"secret"` // 钉钉加签 / 飞书签名密钥
}

type notifyConfig struct {
	Dingtalk notifyChannel `json:"dingtalk"`
	Feishu   notifyChannel `json:"feishu"`
}

func (s *Server) loadNotifyConfig() notifyConfig {
	var cfg notifyConfig
	if s.m.pg == nil {
		return cfg
	}
	if v, ok, _ := s.m.pg.GetSetting("notify.config"); ok && v != "" {
		_ = json.Unmarshal([]byte(v), &cfg)
	}
	return cfg
}

func (s *Server) saveNotifyConfig(cfg notifyConfig) error {
	b, _ := json.Marshal(cfg)
	return s.m.pg.SetSetting("notify.config", string(b))
}

// GET/PUT /api/notify/config
func (s *Server) notifyGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.loadNotifyConfig())
}

func (s *Server) notifySetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg notifyConfig
	if err := decode(r, &cfg); err != nil {
		writeErr(w, 400, "请求体无效")
		return
	}
	if err := s.saveNotifyConfig(cfg); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

// POST /api/notify/test
func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if err := s.sendAll("FORANG 通知测试", "如果你看到这条消息，说明通知通道配置成功。"); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
// sendFindingNotify 高危发现推送（markdown 摘要）。
func (s *Server) sendFindingNotify(f *db.DBFinding, severity string, score float64) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[notify] finding %d 推送 panic: %v", f.ID, r)
		}
	}()
	title := f.Name
	if title == "" {
		title = f.VulnClass
	}
	t := fmt.Sprintf("🚨 高危漏洞评审确认（%s）", title)
	body := fmt.Sprintf("**%s**\n\n等级：%s · CVSS %.1f\n提交：%s\n\n> %s",
		title, severity, score, f.CreatedAt.Format("01-02 15:04"), clipTo(f.Summary, 300))
	if err := s.sendAll(t, body); err != nil {
		log.Printf("[notify] finding %d 推送失败: %v", f.ID, err)
	}
}


func (s *Server) sendAll(title, body string) error {
	cfg := s.loadNotifyConfig()
	var errs []string
	if cfg.Dingtalk.Enabled && cfg.Dingtalk.Webhook != "" {
		if err := sendDingtalk(cfg.Dingtalk, title, body); err != nil {
			errs = append(errs, "钉钉: "+err.Error())
		}
	}
	if cfg.Feishu.Enabled && cfg.Feishu.Webhook != "" {
		if err := sendFeishu(cfg.Feishu, title, body); err != nil {
			errs = append(errs, "飞书: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "；"))
	}
	return nil
}

func postJSON(u string, payload any, timeout time.Duration) error {
	b, _ := json.Marshal(payload)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		ErrCode float64 `json:"errcode"` // 钉钉
		Code    float64 `json:"code"`    // 飞书
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.ErrCode != 0 {
		return fmt.Errorf("errcode %.0f", out.ErrCode)
	}
	if out.Code != 0 {
		return fmt.Errorf("code %.0f", out.Code)
	}
	return nil
}

// sendDingtalk 钉钉自定义机器人（加签）：sign = base64(HMAC-SHA256(secret, ts+"\n"+secret))。
func sendDingtalk(c notifyChannel, title, body string) error {
	u := c.Webhook
	ts := time.Now().UnixMilli()
	if c.Secret != "" {
		mac := hmac.New(sha256.New, []byte(c.Secret))
		mac.Write([]byte(fmt.Sprintf("%d\n%s", ts, c.Secret)))
		sign := url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		sep := "&"
		if !strings.Contains(u, "?") {
			sep = "?"
		}
		u = fmt.Sprintf("%s%stimestamp=%d&sign=%s", u, sep, ts, sign)
	}
	return postJSON(u, map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			"text":  fmt.Sprintf("### %s\n\n%s", title, body),
		},
	}, 10*time.Second)
}

// sendFeishu 飞书自定义机器人（签名校验）：sign = base64(HMAC-SHA256(key=ts+"\n"+secret, ""))。
func sendFeishu(c notifyChannel, title, body string) error {
	payload := map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"header": map[string]any{
				"title":    map[string]string{"tag": "plain_text", "content": title},
				"template": "red",
			},
			"elements": []map[string]any{{"tag": "markdown", "content": body}},
		},
	}
	if c.Secret != "" {
		ts := time.Now().Unix()
		mac := hmac.New(sha256.New, []byte(fmt.Sprintf("%d\n%s", ts, c.Secret)))
		sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		payload["timestamp"] = fmt.Sprintf("%d", ts)
		payload["sign"] = sign
	}
	return postJSON(c.Webhook, payload, 10*time.Second)
}

func (s *Server) registerNotifyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/notify/config", s.notifyGetConfig)
	mux.HandleFunc("PUT /api/notify/config", s.notifySetConfig)
	mux.HandleFunc("POST /api/notify/test", s.notifyTest)
}
