package server

// notify_health.go — 通知渠道健康巡检：
//   每 6 小时对启用渠道发一条探测（轻量：直接复用「测试消息」投递），结果写
//   notification_channels.health_ok/health_at/health_err。投递引擎发现渠道
//   health_ok=false 时不投递（消息滞留队列等恢复），渠道页显示最近巡检状态。
//   首次启动 90s 后跑一轮（不等满 6h 才知道 webhook 已失效）。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/notify"
)

const notifyHealthInterval = 6 * time.Hour

// startNotifyHealthLoop 启动巡检循环（幂等：server New 里调用一次）。
func (s *Server) startNotifyHealthLoop() {
	go func() {
		time.Sleep(90 * time.Second) // 等 PG/渠道配置就绪
		s.notifyHealthPass(s.ctx)
		t := time.NewTicker(notifyHealthInterval)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				s.notifyHealthPass(s.ctx)
			}
		}
	}()
}

// notifyHealthPass 巡检一轮：所有启用渠道各探测一次。
// 探测失败只记录，不影响其他渠道；渠道页/API 随时可查最近结果。
func (s *Server) notifyHealthPass(ctx context.Context) {
	pg := s.m.PG()
	if pg == nil {
		return
	}
	rows, err := pg.Query(`SELECT id, kind, config FROM notification_channels WHERE enabled`)
	if err != nil {
		return
	}
	type target struct {
		id     int64
		kind   string
		config []byte
	}
	targets := []target{}
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.kind, &t.config); err == nil {
			targets = append(targets, t)
		}
	}
	rows.Close()
	if len(targets) == 0 {
		return
	}
	baseURL := s.notifierBaseURL(pg)
	for _, t := range targets {
		// 巡检消息与手工测试一致：能一眼认出是探测而非真实漏洞。
		if err := s.probeChannel(ctx, t.kind, t.config, baseURL); err != nil {
			log.Printf("[notify] 渠道 #%d(%s) 巡检失败: %v", t.id, t.kind, err)
			_, _ = pg.Exec(`UPDATE notification_channels SET health_ok=false, health_at=now(), health_err=$1 WHERE id=$2`,
				truncateStr(err.Error(), 300), t.id)
			continue
		}
		_, _ = pg.Exec(`UPDATE notification_channels SET health_ok=true, health_at=now(), health_err='' WHERE id=$1`, t.id)
	}
}

// probeChannel 对单个渠道发送探测消息。
func (s *Server) probeChannel(ctx context.Context, kind string, config []byte, baseURL string) error {
	channel, ok := notify.Get(kind)
	if !ok {
		return fmt.Errorf("渠道类型 %q 未注册", kind)
	}
	var cfg map[string]any
	if len(config) > 0 {
		_ = json.Unmarshal(config, &cfg)
	}
	if err := channel.Validate(cfg); err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, err := channel.Send(pctx, cfg, notifyTestMessage(baseURL))
	return err
}
