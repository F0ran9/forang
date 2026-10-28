package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// POC 闭环 API：库 CRUD / 批量匹配 / nuclei 精确验证。
// 验证通过 exec 调用宿主机 nuclei（未安装时明确报错，不伪造结论）。

// validateVerifyTarget 把 POC 验证目标限制在 http(s)。nuclei 会按任意 scheme 发起
// 请求——file:// 直接读宿主机文件（自测漏洞 #2，file:///etc/passwd 实测可读），
// gopher:// 等还能出网。内网/本机目标对渗透平台是合法用例，故只限协议不做地址黑名单。
func validateVerifyTarget(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "target 必须是带主机的 URL（如 http://target:port）"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "target 仅支持 http/https（拒绝 file:// 等协议）"
	}
	return ""
}

func (s *Server) pocStore() *pgdb.PocStore {
	pg := s.m.PG()
	if pg == nil {
		return nil
	}
	return pg.Pocs()
}

// GET /api/pocs
func (s *Server) pocList(w http.ResponseWriter, r *http.Request) {
	ps := s.pocStore()
	if ps == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	pocs, err := ps.ListPocs()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if pocs == nil {
		pocs = []pgdb.Poc{}
	}
	writeJSON(w, 200, map[string]any{"pocs": pocs})
}

// POST /api/pocs {title,component,cve,severity,template,source}
func (s *Server) pocCreate(w http.ResponseWriter, r *http.Request) {
	ps := s.pocStore()
	if ps == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	var body struct {
		Title     string `json:"title"`
		Component string `json:"component"`
		CVE       string `json:"cve"`
		Severity  string `json:"severity"`
		Template  string `json:"template"`
		Source    string `json:"source"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "请求体非法")
		return
	}
	if strings.TrimSpace(body.Title) == "" || strings.TrimSpace(body.Component) == "" {
		writeErr(w, 422, "title 与 component 必填")
		return
	}
	if body.Source != "ai" {
		body.Source = "manual"
	}
	p, err := ps.CreatePoc(body.Title, body.Component, body.CVE, body.Severity, body.Template, body.Source)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"poc": p})
}

// PUT /api/pocs/{id}
func (s *Server) pocUpdate(w http.ResponseWriter, r *http.Request) {
	ps := s.pocStore()
	if ps == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "非法 id")
		return
	}
	var body struct {
		Title     string `json:"title"`
		Component string `json:"component"`
		CVE       string `json:"cve"`
		Severity  string `json:"severity"`
		Template  string `json:"template"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "请求体非法")
		return
	}
	p, err := ps.UpdatePoc(id, body.Title, body.Component, body.CVE, body.Severity, body.Template)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p == nil {
		writeErr(w, 404, "POC 不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"poc": p})
}

// DELETE /api/pocs/{id}
func (s *Server) pocDelete(w http.ResponseWriter, r *http.Request) {
	ps := s.pocStore()
	if ps == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "非法 id")
		return
	}
	if err := ps.DeletePoc(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/pocs/match {assets:[{target,component}]}
func (s *Server) pocMatch(w http.ResponseWriter, r *http.Request) {
	ps := s.pocStore()
	if ps == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	var body struct {
		Assets []pgdb.PocTargetMatchInput `json:"assets"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Assets) == 0 {
		writeErr(w, 400, "assets 必填（[{target,component}]）")
		return
	}
	if len(body.Assets) > 2000 {
		body.Assets = body.Assets[:2000]
	}
	matches, err := ps.MatchPocs(body.Assets)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"matches": matches, "total": len(matches)})
}

// POST /api/pocs/{id}/verify {target}
func (s *Server) pocVerify(w http.ResponseWriter, r *http.Request) {
	ps := s.pocStore()
	if ps == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "非法 id")
		return
	}
	var body struct {
		Target string `json:"target"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Target) == "" {
		writeErr(w, 400, "target 必填")
		return
	}
	if msg := validateVerifyTarget(body.Target); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	p, err := ps.GetPoc(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p == nil {
		writeErr(w, 404, "POC 不存在")
		return
	}
	if strings.TrimSpace(p.Template) == "" {
		writeErr(w, 422, "POC 模板为空")
		return
	}
	nuclei, err := exec.LookPath("nuclei")
	if err != nil {
		writeErr(w, 503, "宿主机未安装 nuclei；请先安装（go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest）")
		return
	}
	tmp, err := os.CreateTemp("", "artex-poc-*.yaml")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(ensureNucleiAuthor(p.Template)); err != nil {
		tmp.Close()
		writeErr(w, 500, err.Error())
		return
	}
	tmp.Close()

	runCtx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, nuclei, "-u", body.Target, "-t", tmp.Name(), "-silent", "-duc")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	runErr := cmd.Run()

	output := strings.TrimSpace(out.String())
	if runErr != nil && output == "" {
		msg := fmt.Sprintf("error: nuclei 运行失败: %v；stderr: %s", runErr, truncateStr(errBuf.String(), 500))
		_ = ps.RecordVerifyResult(id, body.Target, msg, false)
		writeJSON(w, 200, map[string]any{"matched": false, "result": msg})
		return
	}
	if output != "" {
		res := truncateStr("matched: "+output, 4000)
		_ = ps.RecordVerifyResult(id, body.Target, res, true)
		writeJSON(w, 200, map[string]any{"matched": true, "result": res})
		return
	}
	res := "not_matched"
	_ = ps.RecordVerifyResult(id, body.Target, res, false)
	writeJSON(w, 200, map[string]any{"matched": false, "result": res})
}

// ensureNucleiAuthor injects `author` into the info block when missing —
// nuclei v3 refuses to load templates without it ("no templates provided").
func ensureNucleiAuthor(tpl string) string {
	if strings.Contains(tpl, "author:") {
		return tpl
	}
	idx := strings.Index(tpl, "info:")
	if idx < 0 {
		return tpl
	}
	rest := tpl[idx+len("info:"):]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		return tpl + "\n  author: artex\n"
	}
	return tpl[:idx+len("info:")+nl+1] + "  author: artex\n" + rest[nl+1:]
}

func (s *Server) registerPocRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/pocs", s.pocList)
	mux.HandleFunc("POST /api/pocs", s.pocCreate)
	mux.HandleFunc("PUT /api/pocs/{id}", s.pocUpdate)
	mux.HandleFunc("DELETE /api/pocs/{id}", s.pocDelete)
	mux.HandleFunc("POST /api/pocs/match", s.pocMatch)
	mux.HandleFunc("POST /api/pocs/{id}/verify", s.pocVerify)
}
