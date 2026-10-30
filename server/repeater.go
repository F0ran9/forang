package server

// repeater.go — 工具箱 · Repeater HTTP API。
// 发送/截图是长操作：采用任务制——POST 启动即返回 job_id，后台执行，
// GET 轮询结果，POST stop 真取消（context 级，卡住的连接立即断）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/repeater"
)

type repJob struct {
	ID     string
	Kind   string // send | capture
	Note   string
	Ctx    context.Context
	Cancel context.CancelFunc

	mu     sync.Mutex
	State  string // running | done | error | stopped
	Err    string
	Result *repeater.Result
	Png    string
	Html   string
	Size   int
}

func (j *repJob) finish(state, errMsg string) {
	j.mu.Lock()
	if j.State == "running" {
		j.State = state
		j.Err = errMsg
	}
	j.mu.Unlock()
}

var repJobs = struct {
	sync.Mutex
	m map[string]*repJob
}{m: map[string]*repJob{}}

// POST /api/tools/repeater/stop 之外每次启动顺带清理已完成超过 30 分钟的任务。
func repJobsGC() {
	repJobs.Lock()
	defer repJobs.Unlock()
	for id, j := range repJobs.m {
		j.mu.Lock()
		done := j.State != "running"
		j.mu.Unlock()
		if done {
			delete(repJobs.m, id)
		}
	}
}

func repOptionsFrom(body map[string]any) repeater.Options {
	get := func(k string) int {
		if v, ok := body[k].(float64); ok {
			return int(v)
		}
		return 0
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

// startRepJob 启动 send/capture 任务并返回 job_id。
func (s *Server) startRepJob(kind string, body map[string]any) string {
	raw, _ := body["raw"].(string)
	note, _ := body["note"].(string)
	opt := repOptionsFrom(body)
	repJobsGC()
	ctx, cancel := context.WithCancel(context.Background())
	j := &repJob{Kind: kind, Ctx: ctx, Cancel: cancel, State: "running", Note: note}
	id := fmt.Sprintf("j%d", time.Now().UnixNano())
	repJobs.Lock()
	repJobs.m[id] = j
	repJobs.Unlock()
	go func() {
		defer j.finish("done", "")
		res, err := repeater.SendCtx(j.Ctx, raw, opt)
		if err != nil {
			if j.Ctx.Err() == context.Canceled {
				return
			}
			j.finish("error", err.Error())
			return
		}
		if j.Ctx.Err() == context.Canceled {
			return
		}
		// 二进制响应体改写为 hex 预览（移植自 AI-PENTEST：避免 JSON 序列化把非法
		// UTF-8 打成 U+FFFD 后前端显示乱码）。[]byte(s) 无损取回原始字节。
		repSanitizeBodies(res)
		if kind == "send" {
			j.mu.Lock()
			j.Result = res
			j.mu.Unlock()
			return
		}
		// capture：渲染取证页 + 截图
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
		outDir := filepath.Join(s.m.dir, "evidence", "repeater")
		_ = os.MkdirAll(outDir, 0o755)
		stamp := time.Now().Format("0102-150405")
		htmlPath := filepath.Join(outDir, "capture-"+stamp+".html")
		pngPath := filepath.Join(outDir, "capture-"+stamp+".png")
		html := repeater.RenderEvidenceHTML(repeater.EvidenceInput{
			RawSent:  sent,
			Response: resp,
			Target:   fmt.Sprintf("%s://%s:%d", res.Scheme, res.Host, res.Port),
			Note:     note,
			Capture:  time.Now(),
		})
		if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
			j.finish("error", "写取证页失败: "+err.Error())
			return
		}
		size, err := repeater.CaptureScreenshotCtx(j.Ctx, htmlPath, pngPath, 1600, 1000)
		if err != nil {
			j.mu.Lock()
			j.Html = htmlPath
			j.mu.Unlock()
			j.finish("error", "截图失败: "+err.Error())
			return
		}
		j.mu.Lock()
		j.Result = res
		j.Png = pngPath
		j.Html = htmlPath
		j.Size = size
		j.mu.Unlock()
	}()
	return id
}

// POST /api/tools/repeater/send — 启动发送任务。
func (s *Server) repeaterSend(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"job_id": s.startRepJob("send", body)})
}

// POST /api/tools/repeater/capture — 启动 发送+取证页+截图 任务。
func (s *Server) repeaterCapture(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeBodyMap(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"job_id": s.startRepJob("capture", body)})
}

// GET /api/tools/repeater/job/{id} — 轮询任务状态与结果。
func (s *Server) repeaterJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	repJobs.Lock()
	j := repJobs.m[id]
	repJobs.Unlock()
	if j == nil {
		writeErr(w, 404, "任务不存在或已过期")
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	resp := map[string]any{"job_id": id, "state": j.State, "kind": j.Kind}
	if j.Err != "" {
		resp["error"] = j.Err
	}
	if j.Result != nil {
		resp["result"] = j.Result
	}
	if j.Png != "" {
		resp["png"] = j.Png
		resp["html"] = j.Html
		resp["size"] = j.Size
	}
	writeJSON(w, 200, resp)
}

// POST /api/tools/repeater/stop — 取消运行中的任务（context 级真取消）。
func (s *Server) repeaterStop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.JobID == "" {
		writeErr(w, 400, "job_id 必填")
		return
	}
	repJobs.Lock()
	j := repJobs.m[body.JobID]
	repJobs.Unlock()
	if j == nil {
		writeErr(w, 404, "任务不存在或已过期")
		return
	}
	j.Cancel()
	j.mu.Lock()
	if j.State == "running" {
		j.State = "stopped"
	}
	j.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "state": "stopped"})
}

// repSanitizeBodies 把结果里的二进制响应体改写为 hex 预览文本（每跳 + 最终跳）。
// 判定：非法 UTF-8 或不可打印控制字符占比 > 8%。
func repSanitizeBodies(res *repeater.Result) {
	if res == nil {
		return
	}
	for i := range res.Hops {
		res.Hops[i].Body = repHexIfBinary(res.Hops[i].Body)
	}
	res.Final.Body = repHexIfBinary(res.Final.Body)
}

func repHexIfBinary(b string) string {
	if b == "" || isMostlyText(b) {
		return b
	}
	raw := []byte(b)
	sample := raw
	if len(sample) > 512 {
		sample = sample[:512]
	}
	const hexDigits = "0123456789abcdef"
	hexBuf := make([]byte, 0, len(sample)*3)
	for i, c := range sample {
		if i > 0 {
			hexBuf = append(hexBuf, ' ')
		}
		hexBuf = append(hexBuf, hexDigits[c>>4], hexDigits[c&0xf])
	}
	return fmt.Sprintf("(binary content, %d bytes total)\n\nHex preview (first %d bytes):\n%s",
		len(raw), len(sample), string(hexBuf))
}

func isMostlyText(s string) bool {
	bad := 0
	total := len(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			bad++
		}
	}
	if total == 0 {
		return true
	}
	// 非法 UTF-8：utf8.ValidString 判整体；控制字符按占比
	if !utf8.ValidString(s) && float64(bad)/float64(total) > 0.02 {
		return false
	}
	return float64(bad)/float64(total) <= 0.08
}
