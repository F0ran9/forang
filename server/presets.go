package server

import (
	"net/http"

	"github.com/Autumn-27/artex/agent"
)

// GET /api/presets — 三端预设 Agent(测试模式)清单。
// 前端对话框用它渲染 Web / 微信小程序 / 移动 APP 三个模式选项。
func (s *Server) listPresets(w http.ResponseWriter, _ *http.Request) {
	out := make([]agent.Preset, 0, len(agent.Presets))
	for _, p := range agent.Presets {
		out = append(out, p)
	}
	// 稳定顺序: web → miniprogram → app
	order := map[string]int{"web": 0, "miniprogram": 1, "app": 2}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && order[out[j].ID] < order[out[j-1].ID]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	writeJSON(w, 200, map[string]any{"presets": out})
}

// normalizePreset validates a preset id from user input; unknown → "".
func normalizePreset(id string) string {
	if p := agent.GetPreset(id); p != nil {
		return p.ID
	}
	return ""
}
