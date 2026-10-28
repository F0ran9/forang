package agent

// tools_repeater.go — 工具箱 Repeater 的 agent 侧工具：原始报文发送与带时间
// 取证截图。与平台「工具箱」Repeater 页共用 repeater 包内核；截图（请求|响应|
// 北京时间取证面板）落 <工作目录>/evidence/repeater/，路径可直接绑进
// report_finding 的证据或报告。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/repeater"
	actool "github.com/Autumn-27/norma/tool"
)

// repeaterSend 发送原始报文并返回响应（不截图）——调试/验证用。
func (t *ToolSet) repeaterSend() actool.CoreTool {
	return writeTool("repeater_send",
		"发送原始 HTTP 报文（TCP 直写、忠实重放），返回状态行/响应头/响应体。与工具箱 Repeater 页同一内核。raw 为完整原始报文；换行 \\n 自动补成 \\r\\n。",
		obj(map[string]any{
			"raw":             str("完整原始请求报文（请求行+头[+体]）"),
			"force_https":     map[string]any{"type": "boolean", "description": "强制 https（默认 false）"},
			"follow_redirect": map[string]any{"type": "boolean", "description": "跟随 3xx 重定向（默认 true，最多 5 跳）"},
			"max_body_kb":     intp("响应截断上限 KB（默认 1024）"),
			"timeout":         intp("超时秒（默认 30）"),
		}, "raw"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Raw            string `json:"raw"`
				ForceHTTPS     bool   `json:"force_https"`
				FollowRedirect *bool  `json:"follow_redirect"`
				MaxBodyKB      int    `json:"max_body_kb"`
				Timeout        int    `json:"timeout"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Raw) == "" {
				return actool.Errorf("raw 必填"), nil
			}
			opt := repeater.DefaultOptions()
			opt.ForceHTTPS = a.ForceHTTPS
			if a.FollowRedirect != nil {
				opt.FollowRedirect = *a.FollowRedirect
			}
			if a.MaxBodyKB > 0 {
				opt.MaxBodyKB = a.MaxBodyKB
			}
			if a.Timeout > 0 {
				opt.TimeoutSec = a.Timeout
			}
			res, err := repeater.Send(a.Raw, opt)
			if err != nil {
				return actool.Errorf("发送失败: " + err.Error()), nil
			}
			f := res.Final
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s://%s:%d\n%s（%d ms）\n\n%s", res.Scheme, res.Host, res.Port, f.StatusLine, f.ElapsedMS, f.Headers)
			if f.Body != "" {
				fmt.Fprintf(&sb, "\n\n%s", vulnPreview(f.Body, 4000))
			}
			if len(res.Hops) > 1 {
				fmt.Fprintf(&sb, "\n\n（跟随重定向 %d 跳）", len(res.Hops))
			}
			if f.Err != "" {
				fmt.Fprintf(&sb, "\n\n[错误] %s", f.Err)
			}
			return actool.Text(sb.String()), nil
		})
}

// repeaterCapture 发送报文并截取带时间取证页（请求|响应|北京时间面板），PNG 落
// evidence/repeater/。报告留证用：路径可直接引用进 report_finding 证据或 Word 报告。
func (t *ToolSet) repeaterCapture() actool.CoreTool {
	return writeTool("repeater_capture",
		"报告留证截图：发送原始 HTTP 报文并截取带时间取证页（请求|响应|北京时间取证面板），PNG 存 evidence/repeater/。用途：操作员要求截图、漏洞报告需要配图时调用；探测/调试请用 repeater_send 或 Bash curl。raw 为完整原始报文（\\n 自动补 \\r\\n）。note 必填（写明截图证明什么，显示在取证面板）。",
		obj(map[string]any{
			"raw":         str("完整原始请求报文"),
			"note":        str("这张截图要证明什么（显示在取证面板与审计里）"),
			"force_https": map[string]any{"type": "boolean", "description": "强制 https（默认 false）"},
			"max_body_kb": intp("响应截断上限 KB（默认 1024）"),
		}, "raw", "note"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Raw        string `json:"raw"`
				Note       string `json:"note"`
				ForceHTTPS bool   `json:"force_https"`
				MaxBodyKB  int    `json:"max_body_kb"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Raw) == "" {
				return actool.Errorf("raw 必填：完整原始请求报文"), nil
			}
			if strings.TrimSpace(a.Note) == "" {
				return actool.Errorf("note 不能为空：写明这张截图证明什么"), nil
			}
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			opt := repeater.DefaultOptions()
			opt.ForceHTTPS = a.ForceHTTPS
			if a.MaxBodyKB > 0 {
				opt.MaxBodyKB = a.MaxBodyKB
			}
			res, err := repeater.Send(a.Raw, opt)
			if err != nil {
				return actool.Errorf("发送失败: " + err.Error()), nil
			}
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
			stamp := time.Now().Format("0102-150405")
			outDir := filepath.Join(dir, "evidence", "repeater")
			htmlPath := filepath.Join(outDir, "capture-"+stamp+".html")
			pngPath := filepath.Join(outDir, "capture-"+stamp+".png")
			html := repeater.RenderEvidenceHTML(repeater.EvidenceInput{
				RawSent:  sent,
				Response: resp,
				Target:   target,
				Note:     a.Note,
				Capture:  time.Now(),
			})
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return actool.Errorf("建目录失败: " + err.Error()), nil
			}
			if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
				return actool.Errorf("写取证页失败: " + err.Error()), nil
			}
			size, err := repeater.CaptureScreenshot(htmlPath, pngPath, 1600, 1000)
			if err != nil {
				return actool.Errorf("截图失败: " + err.Error()), nil
			}
			return actool.Text(fmt.Sprintf(
				"✅ 留证截图: %s（%d KB）\n目的: %s\n结果: %s（%d ms）\n在 report_finding 证据里用 {\"kind\":\"screenshot\",\"path\":\"%s\"} 引用。",
				pngPath, size/1024, a.Note, res.Final.StatusLine, res.Final.ElapsedMS, pngPath)), nil
		})
}

func (t *ToolSet) repeaterTools() []actool.CoreTool {
	return []actool.CoreTool{t.repeaterSend(), t.repeaterCapture()}
}
