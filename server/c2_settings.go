package server

// c2_settings.go — goc2 (C2 teamserver) 连接配置：settings 键 c2_url/c2_token，
// 启动与保存时同步进 c2client 运行时默认（优先级 settings > env > 内置默认）。
// token 只进服务端 settings 表，绝不写进代码/仓库。

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/c2client"
)

const (
	settingC2URL   = "c2_url"
	settingC2Token = "c2_token"
)

// syncC2Settings 把 settings 里的 goc2 配置同步进 c2client 默认值。
// 未配置时不动（保留 env/内置默认）。
func (s *Server) syncC2Settings() {
	u, okU, _ := s.m.PG().GetSetting(settingC2URL)
	t, okT, _ := s.m.PG().GetSetting(settingC2Token)
	if (!okU || strings.TrimSpace(u) == "") && (!okT || strings.TrimSpace(t) == "") {
		return
	}
	base := c2client.CurrentOrDefault()
	if okU && strings.TrimSpace(u) != "" {
		base.BaseURL = strings.TrimRight(strings.TrimSpace(u), "/")
	}
	if okT && strings.TrimSpace(t) != "" {
		base.Token = strings.TrimSpace(t)
	}
	c2client.SetDefault(base)
}

func (s *Server) c2SettingsGet(w http.ResponseWriter, r *http.Request) {
	u, _, _ := s.m.PG().GetSetting(settingC2URL)
	t, _, _ := s.m.PG().GetSetting(settingC2Token)
	// token 只回前 6 位供确认，完整值不下发
	masked := ""
	if len(t) > 6 {
		masked = t[:6] + "…"
	} else if t != "" {
		masked = "已设置"
	}
	writeJSON(w, 200, map[string]any{"url": u, "token_masked": masked})
}

func (s *Server) c2SettingsSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if body.URL != "" && !strings.HasPrefix(strings.TrimSpace(body.URL), "http") {
		writeErr(w, 400, "url 需以 http(s):// 开头")
		return
	}
	if body.URL != "" {
		if err := s.m.PG().SetSetting(settingC2URL, strings.TrimSpace(body.URL)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	// token 空串=清除配置（回退 env/默认）；占位符 "…" 表示不改
	if body.Token != "…" {
		if err := s.m.PG().SetSetting(settingC2Token, strings.TrimSpace(body.Token)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	s.syncC2Settings()
	// 探活：列一次 clients 验证配置
	cli := c2client.New(c2client.CurrentOrDefault())
	_, err := cli.ListClients(r.Context(), nil)
	status := "ok"
	if err != nil {
		status = "unreachable: " + err.Error()
	}
	writeJSON(w, 200, map[string]any{"ok": err == nil, "status": status})
}
