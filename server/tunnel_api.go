package server

// tunnel_api.go — 公网入口（Cloudflare 临时隧道）的查看 / 重建 / 回链同步。
//
// 背景：平台的推送回链（飞书审批、任务详情）必须是**公网可达**地址；而临时
// 隧道域名每次进程重启都会变。之前回连地址写死内网 IP，手机点开必然失败，
// 审批就卡在平台里。这里把三件事收口到一个接口：
//  1. 读当前隧道链接（data/entry-url.txt，由 scripts/tunnel-run.sh 写入）；
//  2. 一键重建隧道并等新链接就绪（systemctl restart mixcx-tunnel）；
//  3. 把「带隐身 token 的公网基址」同步到 settings.notify_public_base_url，
//     推送链接形如 https://host/<token>/approval-quick?... —— gate 认这个前缀，
//     自动种 cookie 再 302 到目标路径，手机点一次就通。

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	settingTunnelAutoSync = "tunnel.auto_sync" // 隧道换域名后是否自动同步回连地址
	tunnelUnitName        = "mixcx-tunnel"
	tunnelRebuildTimeout  = 75 * time.Second
)

func (s *Server) tunnelEntryFile() string {
	dir := ""
	if s.m != nil {
		dir = s.m.dir
	}
	return filepath.Join(dir, "entry-url.txt")
}

// readTunnelEntry 读当前入口链接（形如 https://xxx.trycloudflare.com/<token>）。
func (s *Server) readTunnelEntry() string {
	b, err := os.ReadFile(s.tunnelEntryFile())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// splitTunnelEntry 拆成 base（scheme://host）与 token 路径。
func splitTunnelEntry(entry string) (base, tokenPath string) {
	entry = strings.TrimRight(strings.TrimSpace(entry), "/")
	if entry == "" {
		return "", ""
	}
	rest := entry
	if i := strings.Index(rest, "://"); i >= 0 {
		j := strings.IndexByte(rest[i+3:], '/')
		if j < 0 {
			return rest, ""
		}
		base = rest[:i+3+j]
		return base, strings.Trim(rest[i+3+j:], "/")
	}
	return rest, ""
}

func (s *Server) tunnelAutoSync() bool {
	if s.m == nil || s.m.pg == nil {
		return true
	}
	v, ok, _ := s.m.pg.GetSetting(settingTunnelAutoSync)
	if !ok {
		return true // 默认开启：回连地址跟不上隧道等于推送失效
	}
	return v == "true" || v == "1"
}

// tunnelShareBase 是写进推送回链的基址：https://host/<token>
// 让拼接出的任何路径都自带 gate 深链前缀。
func (s *Server) tunnelShareBase() string {
	base, tok := splitTunnelEntry(s.readTunnelEntry())
	if base == "" {
		return ""
	}
	if tok == "" {
		return base
	}
	return base + "/" + tok
}

func (s *Server) tunnelUnitActive() bool {
	c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "systemctl", "is-active", tunnelUnitName).Output()
	if err != nil {
		return strings.TrimSpace(string(out)) == "active"
	}
	return strings.TrimSpace(string(out)) == "active"
}

// registerTunnelRoutes 注册公网入口相关接口。
func (s *Server) registerTunnelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/tunnel", s.tunnelGet)
	mux.HandleFunc("POST /api/tunnel/refresh", s.tunnelRefresh)
	mux.HandleFunc("POST /api/tunnel/sync", s.tunnelSync)
	mux.HandleFunc("POST /api/tunnel/notify", s.tunnelTestNotify) // 手动把当前入口推一次飞书
}

func (s *Server) tunnelPayload() map[string]any {
	entry := s.readTunnelEntry()
	base, tokenPath := splitTunnelEntry(entry)
	notifyBase := s.notifyPublicBaseURL()
	share := base
	if tokenPath != "" {
		share = base + "/" + tokenPath
	}
	return map[string]any{
		"entry":       entry, // 完整入口（含 token）
		"host":        strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://"),
		"token":       tokenPath,  // 隐身 token
		"share_base":  share,      // 可写进回连地址的基址（含 token）
		"notify_base": notifyBase, // 当前推送回连地址
		"auto_sync":   s.tunnelAutoSync(),
		"in_sync":     notifyBase != "" && share != "" && strings.TrimRight(notifyBase, "/") == share,
		"unit_active": s.tunnelUnitActive(),
		"entry_file":  s.tunnelEntryFile(),
		"checked_at":  time.Now().Format(time.RFC3339),
	}
}

func (s *Server) tunnelGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.tunnelPayload())
}

// tunnelSync 把当前隧道基址写入回连地址。
func (s *Server) tunnelSync(w http.ResponseWriter, r *http.Request) {
	share := s.tunnelShareBase()
	if share == "" {
		writeErr(w, 409, "还没有隧道链接（entry-url.txt 为空），请先重建隧道")
		return
	}
	if err := s.m.pg.SetSetting(settingNotifyPublicBaseURL, share); err != nil {
		writeErr(w, 500, "写入回连地址失败: "+err.Error())
		return
	}
	out := s.tunnelPayload()
	out["ok"] = true
	writeJSON(w, 200, out)
}

// tunnelRefresh 重建隧道并等待新链接（最多 75s），随后按开关同步回连地址。
func (s *Server) tunnelRefresh(w http.ResponseWriter, r *http.Request) {
	old := s.readTunnelEntry()

	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(c, "systemctl", "restart", tunnelUnitName).CombinedOutput(); err != nil {
		writeErr(w, 500, "重启隧道服务失败: "+strings.TrimSpace(string(out))+" "+err.Error())
		return
	}

	// 等新链接出现（域名变化 = 进程真的重建了）
	deadline := time.Now().Add(tunnelRebuildTimeout)
	var entry string
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		cur := s.readTunnelEntry()
		if cur != "" && cur != old {
			entry = cur
			break
		}
	}
	if entry == "" {
		writeErr(w, 504, "隧道已重启，但 75 秒内没有拿到新链接；请查看 journalctl -u mixcx-tunnel")
		return
	}

	synced := false
	if s.tunnelAutoSync() {
		if err := s.m.pg.SetSetting(settingNotifyPublicBaseURL, s.tunnelShareBase()); err == nil {
			synced = true
		}
	}
	out := s.tunnelPayload()
	out["ok"] = true
	out["synced"] = synced
	fmt.Printf("[tunnel] 新入口 %s（回连地址%s）\n", entry, map[bool]string{true: "已同步", false: "未同步"}[synced])
	writeJSON(w, 200, out)
}
