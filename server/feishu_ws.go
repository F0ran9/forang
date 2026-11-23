package server

// feishu_ws.go — 飞书长连接客户端（SDK ws）：内网接收卡片按钮回调。
// 出站 WebSocket 连 open.feishu.cn，无需公网地址/域名/证书。
// 仅在 feishu_app 配置启用时启动；配置为空则完全不连（零开销）。

import (
	"context"
	"fmt"
	"log"

	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkws "github.com/larksuite/oapi-sdk-go/v3/ws"
)

// StartFeishuWS 启动长连接。配置变化由进程重启生效（配置页保存后提示）。
func (s *Server) StartFeishuWS(ctx context.Context) {
	cfg := s.loadFeishuAppConfig()
	if !cfg.Enabled || cfg.AppID == "" || cfg.AppSecret == "" {
		return
	}
	feishuApp.mu.Lock()
	feishuApp.cfg = cfg
	feishuApp.mu.Unlock()

	// 卡片按钮回调：就地更新卡片（按钮区替换为结果文本）+ Toast 提示。
	handler := dispatcher.NewEventDispatcher("", "")
	handler.OnP2CardActionTrigger(func(ctx context.Context, e *callback.CardActionTriggerEvent) (*callback.CardActionTriggerResponse, error) {
		if e == nil || e.Event == nil || e.Event.Action == nil {
			return nil, nil
		}
		result := s.handleFeishuCardAction(e.Event.Action.Value)
		operator := ""
		if e.Event.Operator != nil && len(e.Event.Operator.OpenID) >= 8 {
			operator = "\n操作人：`" + e.Event.Operator.OpenID[:12] + "…`"
		}
		log.Printf("[feishu-ws] 卡片审批: %s", result)
		return &callback.CardActionTriggerResponse{
			Toast: &callback.Toast{Type: "info", Content: result},
			Card: &callback.Card{
				Type: "raw",
				Data: map[string]any{
					"config": map[string]any{"wide_screen_mode": true},
					"header": map[string]any{
						"title":    map[string]any{"tag": "plain_text", "content": "⏸ 操作待审批 · 已处理"},
						"template": "grey",
					},
					"elements": []any{
						map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": result + operator}},
					},
				},
			},
		}, nil
	})

	// 消息接收（只为拿 open_id 一次性配置：用户给应用发条消息，日志打出后填进配置）
	handler.OnP2MessageReceiveV1(func(ctx context.Context, e *larkim.P2MessageReceiveV1) error {
		if e != nil && e.Event != nil && e.Event.Sender != nil && e.Event.Sender.SenderId != nil {
			oid := e.Event.Sender.SenderId.OpenId
			log.Printf("[feishu-ws] 收到消息，发送者 open_id: %s（填入 feishu_app.notify_user_ids 后重启生效）", deref(oid))
		}
		return nil
	})

	cli := larkws.NewClient(cfg.AppID, cfg.AppSecret,
		larkws.WithEventHandler(handler),
		larkws.WithAutoReconnect(true),
	)
	go func() {
		if err := cli.Start(ctx); err != nil {
			log.Printf("[feishu-ws] 长连接退出: %v", err)
		}
	}()
	log.Printf("[feishu-ws] 飞书长连接已启动（app %s…，卡片按钮审批就绪）", fmt.Sprintf("%.10s", cfg.AppID))
}

// deref 字符串指针安全取值。
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
