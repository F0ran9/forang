package server

// tunnel_notify.go — 公网入口变化时主动推飞书。
//
// 背景：临时隧道每次进程重启都会换域名，用户在手机上根本不知道自己该用哪个
// 链接。这里起一个轻量守候协程：每 30 秒比对 data/entry-url.txt 与上次已通知
// 的值，一旦变化就：
//  1. 落库 settings.tunnel.last_notified_entry（重启不重复推）；
//  2. 若 tunnel.auto_sync 开启，同步 settings.notify_public_base_url；
//  3. 用飞书应用（与审批卡片同一套凭据）给 NotifyUserIDs 发一条文本消息。
//
// 失败只记日志：通知故障不能影响隧道本身。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	settingTunnelLastNotified = "tunnel.last_notified_entry"
	tunnelWatchInterval       = 30 * time.Second
)

// sendFeishuText 给飞书应用配置的接收人发一条纯文本消息。
func (s *Server) sendFeishuText(text string) error {
	cfg := s.loadFeishuAppConfig()
	if !cfg.Enabled || cfg.AppID == "" || len(cfg.NotifyUserIDs) == 0 {
		return fmt.Errorf("飞书应用未启用或未配置接收人")
	}
	feishuApp.mu.Lock()
	feishuApp.cfg = cfg
	feishuApp.mu.Unlock()

	tok, err := feishuApp.tenantToken()
	if err != nil {
		return fmt.Errorf("获取 tenant token 失败: %w", err)
	}
	content, _ := json.Marshal(map[string]string{"text": text})
	var firstErr error
	for _, uid := range cfg.NotifyUserIDs {
		body := fmt.Sprintf(`{"receive_id":"open_id","receive_id":%q,"msg_type":"text","content":%q}`,
			uid, string(content))
		resp, err := httpPostWithAuth("https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id", tok, body)
		if err != nil {
			firstErr = err
			log.Printf("[tunnel] 飞书推送失败 %s: %v resp=%s", uid, err, clipStr(string(resp), 200))
			continue
		}
		var out struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		_ = json.Unmarshal(resp, &out)
		if out.Code != 0 {
			firstErr = fmt.Errorf("code=%d %s", out.Code, out.Msg)
			log.Printf("[tunnel] 飞书推送 %s: code=%d %s", uid, out.Code, out.Msg)
		}
	}
	return firstErr
}

// tunnelEntryMessage 拼推送文案（带隐身 token 的完整入口）。
func (s *Server) tunnelEntryMessage(entry string) string {
	parts := []string{"🔗 MIXC-X 公网入口已更新", entry}
	if s.tunnelAutoSync() {
		parts = append(parts, "✅ 推送回连地址已同步（飞书审批/详情链接可直接点）")
	} else {
		parts = append(parts, "⚠️ 自动同步已关闭，请到「设置 → 公网入口」手动同步回连地址")
	}
	parts = append(parts, "旧链接已失效，请更新收藏夹。")
	return strings.Join(parts, "\n")
}

// checkTunnelChange 比对并处理一次变化；返回是否发生了通知。
func (s *Server) checkTunnelChange() bool {
	entry := s.readTunnelEntry()
	if entry == "" {
		return false
	}
	last := ""
	if v, ok, _ := s.m.pg.GetSetting(settingTunnelLastNotified); ok {
		last = strings.TrimSpace(v)
	}
	if entry == last {
		return false
	}
	// 先落库再推送：重复推送比漏推更烦人
	_ = s.m.pg.SetSetting(settingTunnelLastNotified, entry)
	if s.tunnelAutoSync() {
		if share := s.tunnelShareBase(); share != "" {
			if err := s.m.pg.SetSetting(settingNotifyPublicBaseURL, share); err != nil {
				log.Printf("[tunnel] 同步回连地址失败: %v", err)
			}
		}
	}
	if err := s.sendFeishuText(s.tunnelEntryMessage(entry)); err != nil {
		log.Printf("[tunnel] 入口变化未推送成功（%s）: %v", entry, err)
		return false
	}
	log.Printf("[tunnel] 入口已变化并推送飞书: %s", entry)
	return true
}

// startTunnelWatcher 常驻守候（30s 一轮）。
func (s *Server) startTunnelWatcher(ctx context.Context) {
	// 启动时先跑一次，避免"平台重启后整段时间不知道新链接"
	if s.checkTunnelChange() {
		log.Printf("[tunnel] 启动检测到入口变化，已推送")
	}
	t := time.NewTicker(tunnelWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkTunnelChange()
		}
	}
}

// tunnelTestNotify 手动触发一次推送（设置页「发到飞书」按钮用）。
func (s *Server) tunnelTestNotify(w http.ResponseWriter, r *http.Request) {
	entry := s.readTunnelEntry()
	if entry == "" {
		writeErr(w, 409, "还没有隧道链接")
		return
	}
	if err := s.sendFeishuText(s.tunnelEntryMessage(entry)); err != nil {
		writeErr(w, 502, "推送失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "entry": entry})
}

var _ = http.StatusOK
