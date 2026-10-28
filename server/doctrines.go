package server

// doctrines.go — 指挥条令 CRUD（移植自哨兵 doctrines.ts，MIT，文案照抄）。
// 条令存 settings 单键 doctrines（JSON 数组）；内置「攻防Web渗透打点」不可删。
// agent 侧经 doc:<id> 复用预设注入管道（见 agent/presets.go 尾部）。

import (
	"encoding/json"
	"net/http"
	"strings"
	"fmt"

	"github.com/Autumn-27/artex/agent"
)

type doctrine struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Text    string `json:"text"`
	Builtin bool   `json:"builtin"`
}

// 哨兵内置条令原文（doctrines.ts BUILTIN_DOCTRINES，MIT）。
var builtinDoctrine = doctrine{
	ID: "attack-defense-web", Name: "攻防Web渗透打点", Builtin: true,
	Text: "对 Web 目标进行深度渗透测试，以权限和数据为目标，最终尝试 RCE，注意不允许影响业务正常运行，在 RCE 后，只允许执行 whoami 进行测试。\n" +
		"\n任务分配优先级：\n需要先探查任务优先级：\n自研 IIS .NEW 系统 > 自研其他系统的优先级 > 通用系统 > 通用 OA>WordPress > 各种门户网站\n" +
		"在下发任务前，请优先测试一下用户提交的目标有无重复，有可能不同域名/IP但是内容是重复的，这点请你熟知。\n" +
		"\n用户输入类型判断：\n1.如果是 http(s):// 类型，那么直接当做任务目标即可\n2.如果是 ip 或者域名，请优先进行信息收集后再进行任务提交",
}

func (s *Server) loadDoctrines() []doctrine {
	var out []doctrine
	if s.m.pg == nil {
		return out
	}
	if v, ok, _ := s.m.pg.GetSetting("doctrines"); ok && v != "" {
		_ = json.Unmarshal([]byte(v), &out)
	}
	if len(out) == 0 {
		out = []doctrine{builtinDoctrine}
		_ = s.m.pg.SetSetting("doctrines", mustJSONStr(out))
	}
	return out
}

func mustJSONStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (s *Server) saveDoctrines(list []doctrine) error {
	return s.m.pg.SetSetting("doctrines", mustJSONStr(list))
}

// wireDoctrineResolver 把条令查询注入 agent 包（每次调用读 settings，改完即生效）。
func (s *Server) wireDoctrineResolver() {
	agent.SetDoctrineResolver(func(id string) *agent.Preset {
		for _, d := range s.loadDoctrines() {
			if d.ID == id && strings.TrimSpace(d.Text) != "" {
				return &agent.Preset{
					ID: agent.DoctrinePrefix + d.ID, Name: d.Name,
					Description: "作战条令", Prompt: d.Text, IsDoctrine: true,
				}
			}
		}
		return nil
	})
}

func (s *Server) registerDoctrineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/doctrines", s.doctrinesList)
	mux.HandleFunc("POST /api/doctrines", s.doctrinesCreate)
	mux.HandleFunc("PUT /api/doctrines/{id}", s.doctrinesUpdate)
	mux.HandleFunc("DELETE /api/doctrines/{id}", s.doctrinesDelete)
}

func (s *Server) doctrinesList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.loadDoctrines()})
}

func (s *Server) doctrinesCreate(w http.ResponseWriter, r *http.Request) {
	var d doctrine
	if err := decode(r, &d); err != nil || strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Text) == "" {
		writeErr(w, 400, "name 与 text 必填")
		return
	}
	d.Builtin = false
	d.ID = slugDoctrine(d.Name)
	list := s.loadDoctrines()
	base := d.ID
	for i := 2; i < 100; i++ {
		dup := false
		for _, e := range list {
			if e.ID == d.ID {
				dup = true
			}
		}
		if !dup {
			break
		}
		d.ID = fmt.Sprintf("%s-%d", base, i)
	}
	list = append(list, d)
	if err := s.saveDoctrines(list); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) doctrinesUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct{ Name, Text string }
	if err := decode(r, &body); err != nil || (strings.TrimSpace(body.Name) == "" && strings.TrimSpace(body.Text) == "") {
		writeErr(w, 400, "name 或 text 至少一项")
		return
	}
	list := s.loadDoctrines()
	for i := range list {
		if list[i].ID == id {
			if strings.TrimSpace(body.Name) != "" {
				list[i].Name = body.Name
			}
			if strings.TrimSpace(body.Text) != "" {
				list[i].Text = body.Text
			}
			if err := s.saveDoctrines(list); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, 200, list[i])
			return
		}
	}
	writeErr(w, 404, "条令不存在")
}

func (s *Server) doctrinesDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list := s.loadDoctrines()
	var out []doctrine
	for _, d := range list {
		if d.ID == id {
			if d.Builtin {
				writeErr(w, 403, "内置条令不可删除")
				return
			}
			continue
		}
		out = append(out, d)
	}
	if len(out) == len(list) {
		writeErr(w, 404, "条令不存在")
		return
	}
	if err := s.saveDoctrines(out); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func slugDoctrine(name string) string {
	var sb strings.Builder
	for _, c := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			sb.WriteRune(c)
		default:
			sb.WriteByte('-')
		}
	}
	s := strings.Trim(sb.String(), "-")
	if s == "" {
		s = "doctrine"
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}
