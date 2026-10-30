package server

// mumu.go — MuMu 模拟器一键启动（agent 部署在物理机，平台经 HTTP 指挥）：
//   GET  /api/tools/mumu/status   agent 在线 + 模拟器运行状态
//   POST /api/tools/mumu/launch   一键启动（agent 拉起 MuMu 并等 Android ready）
//   POST /api/tools/mumu/connect  平台侧 adb connect <物理机IP>:16384（VM 直连 MuMu）
// agent 协议：X-Token 头；配置 settings 键 mumu_agent_url / mumu_agent_token。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

const (
	settingMumuURL   = "mumu_agent_url"
	settingMumuToken = "mumu_agent_token"
	settingMumuPath  = "mumu_launch_path" // 用户输入的 MuMu 启动路径（物理机）
)

func (s *Server) mumuConfig() (string, string) {
	u, ok, _ := s.m.PG().GetSetting(settingMumuURL)
	if !ok || strings.TrimSpace(u) == "" {
		u = "http://192.168.17.1:18911"
	}
	t, ok, _ := s.m.PG().GetSetting(settingMumuToken)
	if !ok || strings.TrimSpace(t) == "" {
		t = "forang-mumu-2026"
	}
	return strings.TrimRight(u, "/"), t
}

// mumuAgent 调 agent（超时 8s；launch 等待可能 60s+ 由调用方传超时）。body 可为 nil。
func (s *Server) mumuAgent(method, path string, timeout time.Duration, body map[string]any) ([]byte, int, error) {
	u, tok := s.mumuConfig()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, u+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Token", tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cli := &http.Client{Timeout: timeout}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("agent 不可达（%s）: %w", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, nil
}

// GET /api/tools/mumu/status
func (s *Server) mumuStatus(w http.ResponseWriter, r *http.Request) {
	lp, _, _ := s.m.PG().GetSetting(settingMumuPath)
	b, code, err := s.mumuAgent(http.MethodGet, "/mumu/status", 6*time.Second, nil)
	if err != nil {
		writeJSON(w, 200, map[string]any{"agent_online": false, "launch_path": lp, "error": err.Error()})
		return
	}
	var st map[string]any
	_ = json.Unmarshal(b, &st)
	st["agent_online"] = code == 200
	st["launch_path"] = lp
	writeJSON(w, 200, map[string]any{"data": st})
}

// POST /api/tools/mumu/launch — 一键启动：agent 拉起 MuMu（阻塞到 ready，超时 120s）→ 自动 adb connect。
func (s *Server) mumuLaunch(w http.ResponseWriter, r *http.Request) {
	lp, _, _ := s.m.PG().GetSetting(settingMumuPath)
	b, code, err := s.mumuAgent(http.MethodPost, "/mumu/launch", 150*time.Second,
		map[string]any{"path": lp})
	if err != nil {
		writeErr(w, 502, "启动失败: "+err.Error())
		return
	}
	if code != 200 {
		writeErr(w, 502, "agent 返回 "+itoa(code)+": "+string(b))
		return
	}
	var st map[string]any
	_ = json.Unmarshal(b, &st)
	// Android ready 后自动 adb connect（VM 侧直连物理机的 MuMu adb 端口）
	adbOut := s.mumuAdbConnect()
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"launch": st, "adb": adbOut,
	}})
}

// POST /api/tools/mumu/connect — 平台侧 adb connect（物理机IP:16384，host 取自 agent url）。
func (s *Server) mumuConnect(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"data": s.mumuAdbConnect()})
}

// mumuAdbConnect 在 VM 上执行 adb connect <host>:16384 + devices。
func (s *Server) mumuAdbConnect() map[string]any {
	u, _ := s.mumuConfig()
	pu, err := url.Parse(u)
	host := "192.168.17.1"
	if err == nil && pu.Hostname() != "" {
		host = pu.Hostname()
	}
	target := host + ":16384"
	adb, _ := exec.LookPath("adb")
	if adb == "" {
		return map[string]any{"error": "VM 未安装 adb（apt install adb）", "target": target}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cout, _ := exec.CommandContext(ctx, adb, "connect", target).CombinedOutput()
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	dout, _ := exec.CommandContext(dctx, adb, "devices").CombinedOutput()
	return map[string]any{
		"target": target, "connect": strings.TrimSpace(string(cout)),
		"devices": strings.TrimSpace(string(dout)),
	}
}


// GET /api/tools/mumu/config — agent 地址/token（脱敏）+ 启动路径。
func (s *Server) mumuConfigGet(w http.ResponseWriter, r *http.Request) {
	u, t := s.mumuConfig()
	lp, _, _ := s.m.PG().GetSetting(settingMumuPath)
	masked := ""
	if len(t) > 4 {
		masked = t[:4] + "…"
	}
	writeJSON(w, 200, map[string]any{"agent_url": u, "token_masked": masked, "launch_path": lp})
}

// POST /api/tools/mumu/config — 保存启动路径（及可选 agent 地址/token）。
func (s *Server) mumuConfigSet(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AgentURL string `json:"agent_url"`
		Token    string `json:"token"`
		LaunchPath string `json:"launch_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.LaunchPath) != "" {
		if err := s.m.PG().SetSetting(settingMumuPath, strings.TrimSpace(b.LaunchPath)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if strings.TrimSpace(b.AgentURL) != "" {
		_ = s.m.PG().SetSetting(settingMumuURL, strings.TrimRight(strings.TrimSpace(b.AgentURL), "/"))
	}
	if strings.TrimSpace(b.Token) != "" {
		_ = s.m.PG().SetSetting(settingMumuToken, strings.TrimSpace(b.Token))
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
