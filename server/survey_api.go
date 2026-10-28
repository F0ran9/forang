package server

// survey_api.go — 资产测绘配置/验证/流水 HTTP API（配置门控语义照抄哨兵：
// 保存后立即验证；只有「已启用+已配 key+验证通过」的平台，agent 工具查询才放行）。

import (
	"net/http"

	"github.com/Autumn-27/artex/survey"
)

func (s *Server) registerSurveyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/survey/config", s.surveyGetConfig)
	mux.HandleFunc("PUT /api/survey/config", s.surveySetConfig)
	mux.HandleFunc("POST /api/survey/test", s.surveyTest)
	mux.HandleFunc("GET /api/survey/log", s.surveyLog)
}

func (s *Server) surveyGetConfig(w http.ResponseWriter, r *http.Request) {
	views := map[string]any{}
	for _, p := range survey.Platforms {
		views[string(p)] = s.surveySvc.ConfigView(p)
	}
	writeJSON(w, 200, views)
}

// surveySetConfig 保存后自动验证（enabled 且有 key 时），验证结果写回 status。
func (s *Server) surveySetConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Platform string `json:"platform"`
		Enabled  bool   `json:"enabled"`
		Key      string `json:"key"`      // 空=保持不变；"clear"=清除
		BaseURL  string `json:"base_url"` // 空=恢复官方地址
	}
	if err := decode(r, &body); err != nil || body.Platform == "" {
		writeErr(w, 400, "platform 必填（fofa/quake/hunter）")
		return
	}
	var p survey.Platform
	switch body.Platform {
	case "fofa":
		p = survey.Fofa
	case "quake":
		p = survey.Quake
	case "hunter":
		p = survey.Hunter
	default:
		writeErr(w, 400, "未知平台")
		return
	}
	if body.Key == "clear" {
		body.Key = "\x00" // 语义：置空（SaveConfig 对 "" 解释为保持）
	}
	cfg, err := s.surveySvc.SaveConfig(p, body.Enabled, body.Key, body.BaseURL)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if cfg.Enabled && cfg.Key != "" {
		go func() { _, _, _ = s.surveySvc.Probe(r.Context(), p, "", "") }()
	}
	writeJSON(w, 200, s.surveySvc.ConfigView(p))
}

// surveyTest 不落库的即时验证（key/baseURL 可临时覆盖）。
func (s *Server) surveyTest(w http.ResponseWriter, r *http.Request) {
	var body struct{ Platform, Key, BaseURL string }
	if err := decode(r, &body); err != nil || body.Platform == "" {
		writeErr(w, 400, "platform 必填")
		return
	}
	var p survey.Platform
	switch body.Platform {
	case "fofa":
		p = survey.Fofa
	case "quake":
		p = survey.Quake
	case "hunter":
		p = survey.Hunter
	default:
		writeErr(w, 400, "未知平台")
		return
	}
	ok, quota, err := s.surveySvc.Probe(r.Context(), p, body.Key, body.BaseURL)
	writeJSON(w, 200, map[string]any{"ok": ok, "quota": quota, "error": errString(err)})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) surveyLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.surveySvc.ListLog(r.URL.Query().Get("platform"), 100)})
}
