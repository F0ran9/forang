package agent

// tools_replay.go — replay_capture 工具（移植自哨兵 replay-tool.ts，MIT）：
// 发送原始报文 → replayd 渲染三栏留证页（请求|响应|北京时间面板）→ 截图 PNG
// 存 evidence/replay/。purpose 必填（显示在审计里）。经拦截审批（同 Bash）。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// ReplayCaptureReq 一次留证请求（agent 工具参数原样交给 server 回调）。
type ReplayCaptureReq struct {
	Raw               string
	Purpose           string
	Host              string
	Port              int
	Scheme            string
	HighlightRequest  []string
	HighlightResponse []string
}

// ReplayCaptureFunc server 注入的留证回调：发报文→截图→落盘，返回 (路径, 响应摘要, 错误)。
type ReplayCaptureFunc func(ctx context.Context, r ReplayCaptureReq) (path string, text string, err error)

// SetReplayCaptureFn 挂回调（避免 agent→server 循环依赖）。
func (t *ToolSet) SetReplayCaptureFn(fn ReplayCaptureFunc) { t.replayCaptureFn = fn }

func (t *ToolSet) replayCaptureTool() actool.CoreTool {
	return writeTool("replay_capture",
		"报告留证截图：发送原始 HTTP 报文并截取三栏留证页（请求|响应|北京时间面板），PNG 存 evidence/replay/。仅用于报告留证——操作员要求截图、或已确认漏洞需要配图时调用；探测/调试请用 Bash curl（同一审批链）。raw 为完整原始报文（换行 \\n 会自动补成 \\r\\n）。purpose 必填。highlight_request/highlight_response 高亮关键片段（如 token=、role=admin）。",
		obj(map[string]any{
			"purpose":            str("这张截图要证明什么（显示在审计里），如「未授权访问 /admin 的留证」"),
			"raw":                str("完整原始请求报文"),
			"host":               str("可选，覆盖目标主机"),
			"port":               intp("可选，覆盖目标端口"),
			"scheme":             str("可选，http/https"),
			"highlight_request":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "请求里要高亮的片段（最多 20 个）"},
			"highlight_response": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "响应里要高亮的片段（最多 20 个）"},
		}, "purpose", "raw"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.replayCaptureFn == nil {
				return actool.Errorf("replayd 留证服务不可用（未部署 replayd 二进制）"), nil
			}
			var a struct {
				Purpose           string   `json:"purpose"`
				Raw               string   `json:"raw"`
				Host              string   `json:"host"`
				Port              int      `json:"port"`
				Scheme            string   `json:"scheme"`
				HighlightRequest  []string `json:"highlight_request"`
				HighlightResponse []string `json:"highlight_response"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Purpose) == "" {
				return actool.Errorf("purpose 不能为空：写明这张截图证明什么"), nil
			}
			if strings.TrimSpace(a.Raw) == "" {
				return actool.Errorf("raw 必填：完整原始请求报文"), nil
			}
			if !strings.Contains(a.Raw, "\r") {
				a.Raw = strings.ReplaceAll(a.Raw, "\n", "\r\n")
			}
			req := ReplayCaptureReq{
				Raw:               a.Raw,
				Purpose:           a.Purpose,
				Host:              a.Host,
				Port:              a.Port,
				Scheme:            a.Scheme,
				HighlightRequest:  a.HighlightRequest,
				HighlightResponse: a.HighlightResponse,
			}
			path, text, err := t.replayCaptureFn(ctx, req)
			if err != nil {
				return actool.Errorf("留证失败: " + err.Error()), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "✅ 留证截图: %s\n", path)
			// 相对路径行是聊天/任务流内联渲染截图的锚点（transcript 按 evidence/replay/ 提取）。
			fmt.Fprintf(&sb, "截图已存证：evidence/replay/%s\n", filepath.Base(path))
			fmt.Fprintf(&sb, "目的: %s\n", a.Purpose)
			if text != "" {
				fmt.Fprintf(&sb, "\n响应摘要:\n%s", vulnPreview(text, 2000))
			}
			res := actool.Text(sb.String())
			// 内联截图块给模型（对齐哨兵 content.push(shot.image)）：模型可视觉自检
			// 留证页。≤4MB 才内联（哨兵上限 6MB，取保守值），超出只回路径。
			if data, rerr := os.ReadFile(path); rerr == nil && len(data) <= 4<<20 {
				res.Content = append(res.Content, llm.ImageBlock("image/png", base64.StdEncoding.EncodeToString(data)))
			}
			return res, nil
		})
}

func (t *ToolSet) replayTools() []actool.CoreTool {
	if t.replayCaptureFn == nil {
		return nil
	}
	return []actool.CoreTool{t.replayCaptureTool()}
}
