// Package c2client — goc2 teamserver 管理 API 的 Go 客户端（移植自 AI-PENTEST
// backend/app/core/goc2.py）。C2 核心由独立运行的 goc2-server 承载
// （/api/v1/c2/* 契约），本包只做 HTTP 对接，不移植服务器本体。
//
// 配置：环境变量 GOC2_URL（默认 http://172.25.0.1:18400，compose 网关 → 宿主机
// admin 面）、GOC2_TOKEN（默认 goc2-admin）。
package c2client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultURL / DefaultToken 与 Python 侧默认值一致。
const (
	DefaultURL   = "http://172.25.0.1:18400"
	DefaultToken = "goc2-admin"
)

// Config goc2 admin 面连接配置。
type Config struct {
	BaseURL string
	Token   string
}

// FromEnv 从环境变量构造配置（缺省回退默认值）。
func FromEnv() Config {
	u := strings.TrimSpace(os.Getenv("GOC2_URL"))
	if u == "" {
		u = DefaultURL
	}
	t := strings.TrimSpace(os.Getenv("GOC2_TOKEN"))
	if t == "" {
		t = DefaultToken
	}
	return Config{BaseURL: strings.TrimRight(u, "/"), Token: t}
}

// ---- 全局默认配置（server 侧用 settings 覆盖，优先级：settings > env > 内置默认） ----

var (
	defaultMu       sync.RWMutex
	defaultCfg      Config
	defaultCfgValid bool
)

// SetDefault 服务启动/设置变更时写入的运行时默认配置。
func SetDefault(cfg Config) {
	defaultMu.Lock()
	defaultCfg, defaultCfgValid = cfg, strings.TrimSpace(cfg.BaseURL) != ""
	defaultMu.Unlock()
}

// CurrentOrDefault 当前生效配置：settings 覆盖 → env → 内置默认。
func CurrentOrDefault() Config {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	if defaultCfgValid {
		return defaultCfg
	}
	return FromEnv()
}

// Client goc2 admin API 客户端。
type Client struct {
	cfg Config
	hc  *http.Client
}

func New(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg = CurrentOrDefault()
	}
	return &Client{cfg: cfg, hc: &http.Client{Timeout: 20 * time.Second}}
}

// Request 通用请求：返回 goc2 的 {"data":...} 原始包裹。错误契约是
// {"detail": ...} + HTTP 状态码。
func (c *Client) Request(ctx context.Context, method, path string, params url.Values, jsonBody any) (map[string]any, error) {
	u := c.cfg.BaseURL + "/api/v1/c2" + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	var body io.Reader
	if jsonBody != nil {
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	if jsonBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("goc2 不可达（%s）: %w", c.cfg.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("goc2 返回非 JSON（HTTP %d）", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		detail, _ := payload["detail"].(string)
		if detail == "" {
			detail = fmt.Sprintf("goc2 HTTP %d", resp.StatusCode)
		}
		return payload, fmt.Errorf("%s", detail)
	}
	return payload, nil
}

// data 提取 {"data":...} 包裹里的 data 字段（没有就整包返回）。
func unwrap(payload map[string]any) map[string]any {
	if d, ok := payload["data"].(map[string]any); ok {
		return d
	}
	return payload
}

// ClientSummary beacon 会话摘要字段（JSON 直接透传 goc2 返回）。
type ClientSummary = map[string]any

// ListClients GET /clients — beacon 会话列表。
func (c *Client) ListClients(ctx context.Context, params url.Values) ([]any, error) {
	payload, err := c.Request(ctx, http.MethodGet, "/clients", params, nil)
	if err != nil {
		return nil, err
	}
	if arr, ok := payload["data"].([]any); ok {
		return arr, nil
	}
	if d, ok := unwrap(payload)["clients"].([]any); ok {
		return d, nil
	}
	return []any{}, nil
}

// GetClient GET /clients/{id} — 单会话详情。
func (c *Client) GetClient(ctx context.Context, sessionID string) (map[string]any, error) {
	payload, err := c.Request(ctx, http.MethodGet, "/clients/"+url.PathEscape(sessionID), nil, nil)
	if err != nil {
		return nil, err
	}
	return unwrap(payload), nil
}

// DeleteClient DELETE /clients/{id} — 关闭会话。
func (c *Client) DeleteClient(ctx context.Context, sessionID string) error {
	_, err := c.Request(ctx, http.MethodDelete, "/clients/"+url.PathEscape(sessionID), nil, nil)
	return err
}

// EnqueueTask POST /clients/{id}/tasks — 任务下发，返回 task_id。
// 兼容映射：exec 任务参数 command → Go beacon 的 cmd（与 Python 侧一致）。
func (c *Client) EnqueueTask(ctx context.Context, clientID, taskType string, args map[string]any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	if taskType == "exec" {
		if cmd, ok := args["command"]; ok {
			if _, has := args["cmd"]; !has {
				args["cmd"] = cmd
			}
			delete(args, "command")
		}
	}
	payload, err := c.Request(ctx, http.MethodPost, "/clients/"+url.PathEscape(clientID)+"/tasks", nil,
		map[string]any{"type": taskType, "args": args})
	if err != nil {
		return "", err
	}
	id, _ := unwrap(payload)["taskId"].(string)
	return id, nil
}

// ListTasks GET /clients/{id}/tasks — 任务列表（含结果，用于轮询取回输出）。
func (c *Client) ListTasks(ctx context.Context, sessionID string, params url.Values) ([]any, error) {
	payload, err := c.Request(ctx, http.MethodGet, "/clients/"+url.PathEscape(sessionID)+"/tasks", params, nil)
	if err != nil {
		return nil, err
	}
	if arr, ok := payload["data"].([]any); ok {
		return arr, nil
	}
	if d, ok := unwrap(payload)["tasks"].([]any); ok {
		return d, nil
	}
	return []any{}, nil
}

// ListListeners GET /listeners — 监听器列表。
func (c *Client) ListListeners(ctx context.Context) ([]any, error) {
	payload, err := c.Request(ctx, http.MethodGet, "/listeners", nil, nil)
	if err != nil {
		return nil, err
	}
	if arr, ok := payload["data"].([]any); ok {
		return arr, nil
	}
	if d, ok := unwrap(payload)["listeners"].([]any); ok {
		return d, nil
	}
	return []any{}, nil
}

// DeleteListener DELETE /listeners/{id}。
func (c *Client) DeleteListener(ctx context.Context, id string) error {
	_, err := c.Request(ctx, http.MethodDelete, "/listeners/"+url.PathEscape(id), nil, nil)
	return err
}

// ListCredentials GET /credentials — 凭据库。
func (c *Client) ListCredentials(ctx context.Context) ([]any, error) {
	payload, err := c.Request(ctx, http.MethodGet, "/credentials", nil, nil)
	if err != nil {
		return nil, err
	}
	if arr, ok := payload["data"].([]any); ok {
		return arr, nil
	}
	if d, ok := unwrap(payload)["credentials"].([]any); ok {
		return d, nil
	}
	return []any{}, nil
}

// UpdateNotes PUT /clients/{id}/notes — 会话备注（CS 备注）。
func (c *Client) UpdateNotes(ctx context.Context, sessionID, notes string) error {
	_, err := c.Request(ctx, "PUT", "/clients/"+url.PathEscape(sessionID)+"/notes", nil,
		map[string]any{"notes": notes})
	return err
}
