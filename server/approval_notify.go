package server

// approval_notify.go — 待审批事件桥接到新版通知中心。
// interceptor.HandleAsk 建待审批记录后回调这里（server.New 装配），
// 写一条 notification_events(approval_pending)，由 Notifier 3 秒内
// 扇出到全部启用渠道（飞书卡片消息带「前往批准/拒绝」回链）。
// 失败只记日志——通知故障不能阻塞审批流本身。

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/notify"
)

func (s *Server) enqueueApprovalEvent(pendingID int64, taskID, agentName, toolName, reason string) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tid := int64(0)
	if n, err := strconv.ParseInt(taskID, 10, 64); err == nil {
		tid = n
	}
	summary := fmt.Sprintf("任务 %s / %s 调用 %s 被拦：%.200s", taskID, agentName, toolName, reason)
	// 快捷链接：Summary 末尾附「批准/拒绝」免登录直答链接（10 分钟一次性令牌）。
	// baseURL 未配置时退回纯文本（点开平台审批页处理）。
	exp := time.Now().Add(approvalQuickTTL).Unix()
	tok := s.approvalQuickToken(pendingID, exp)
	if base := s.notifyPublicBaseURL(); base != "" {
		q := fmt.Sprintf("?pid=%d&exp=%d&t=%s", pendingID, exp, tok)
		summary += fmt.Sprintf("\n[✅ 批准](%s/approval-quick%sd=allow) · [❌ 拒绝](%s/approval-quick%sd=deny)",
			base, q, base, q)
	}
	_, err := s.m.pg.AddNotificationEvent(ctx, notify.EventApprovalPending, 0, notify.Snapshot{
		Kind:      notify.EventApprovalPending,
		TaskID:    tid,
		Name:      "操作待审批（pending #" + strconv.FormatInt(pendingID, 10) + "）",
		VulnClass: "审批",
		Summary:   summary,
	})
	if err != nil {
		log.Printf("[notify] 审批事件入队失败 pending=%d: %v", pendingID, err)
	}
}
