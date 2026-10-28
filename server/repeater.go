package server

// repeater.go — 工具箱 · Repeater HTTP API：原始报文发送 + 带时间取证页截图。
// 截图存 data/evidence/repeater/（全局留证池），可在漏洞证据里引用路径。

import (
	"encoding/json"
	"os"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/Autumn-27/artex/repeater"
)

func repeaterOptionsFrom(body map[string]any) repeater.Options {
	get := func(k string) int {
		if v, ok := body[k].(float64); ok {
			return int(v)
		}
		return 0
	}
	getB := func(k string) bool {
		v, _ := body[k].(bool)
		return v
	}
	o := repeater.DefaultOptions()
	if v, ok := body["force_https"].(bool); ok {
		o.ForceHTTPS = v
	}
	if v, ok := body["follow_redirect"].(bool); ok {
		o.FollowRedirect = v
	}
	if n := get("max_body_kb"); n > 0 {
		o.MaxBodyKB = n
	}
	if n := get("timeout"); n > 0 {
		o.TimeoutSec = n
	}
	_ = getB
	return o
}

func decodeBodyMap(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "请求体无效: "+err.Error())
		return nil, false
	}
	raw, _ := body["raw"].(string)
	if raw == "" {
		writeErr(w, 400, "raw 必填：完整原始请求报文")
		return nil, false
	}
	return body, true
}

// POST /api/tools/repeater/send — 发送报文，返回响应（不截图）。
func (s *Server) repeaterSend(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	raw, _ := body["raw"].(string)
	res, err := repeater.Send(raw, repeaterOptionsFrom(body))
	if err != nil {
		writeJSON(w, 200, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "done", "result": res})
}

// POST /api/tools/repeater/capture — 发送 + 渲染带时间取证页 + Chromium 截图。
func (s *Server) repeaterCapture(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	raw, _ := body["raw"].(string)
	note, _ := body["note"].(string)
	res, err := repeater.Send(raw, repeaterOptionsFrom(body))
	if err != nil {
		writeJSON(w, 200, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	// 取证材料：末跳实际发送报文 + 响应
	sent := res.Final.RequestSent
	resp := res.Final.StatusLine
	if res.Final.Headers != "" {
		resp += "\r\n" + res.Final.Headers
	}
	if res.Final.Body != "" {
		resp += "\r\n\r\n" + res.Final.Body
	}
	if res.Final.Err != "" {
		resp += "\n\n[发送/读取错误] " + res.Final.Err
	}
	target := fmt.Sprintf("%s://%s:%d", res.Scheme, res.Host, res.Port)

	outDir := filepath.Join(s.m.dir, "evidence", "repeater")
	stamp := time.Now().Format("0102-150405")
	_ = os.MkdirAll(outDir, 0o755)
	htmlPath := filepath.Join(outDir, "capture-"+stamp+".html")
	pngPath := filepath.Join(outDir, "capture-"+stamp+".png")
	html := repeater.RenderEvidenceHTML(repeater.EvidenceInput{
		RawSent:  sent,
		Response: resp,
		Target:   target,
		Note:     note,
		Capture:  time.Now(),
	})
	if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
		writeErr(w, 500, "写取证页失败: "+err.Error())
		return
	}
	size, err := repeater.CaptureScreenshot(htmlPath, pngPath, 1600, 1000)
	if err != nil {
		writeJSON(w, 200, map[string]any{"status": "error", "error": err.Error(), "html": htmlPath})
		return
	}
	writeJSON(w, 200, map[string]any{
		"status": "done",
		"result": res,
		"html":   htmlPath,
		"png":    pngPath,
		"size":   size,
		"note":   note,
	})
}
