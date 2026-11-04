package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const reviewTextLimit = 4000

const BackgroundUserMessage = "user_message"

// ReviewBackground is explicitly bound from the current human message. Generated
// Worker summaries are not accepted. Background cannot override review policy.
type ReviewBackground struct {
	Source    string `json:"source"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ReviewInput contains only the current call and explicitly selected background.
// Execution history and call correlation belong to the separate audit record.
type ReviewInput struct {
	Version    int               `json:"version"`
	WorkingDir string            `json:"working_directory,omitempty"`
	Background *ReviewBackground `json:"background,omitempty"`
	Tool       string            `json:"tool_name"`
	Arguments  json.RawMessage   `json:"arguments"`
	// CleanupFingerprints 非空表示本调用来自「痕迹清理」任务，且这里列出的是该任务
	// 目标里声明要清除的测试数据指纹（内容特征/ID/文件名）。裁判看到指纹与本次
	// 删除操作匹配时，作用对象归属已明（任务声明的测试数据），可判 allow；
	// 不匹配仍按常规判据（真实业务数据）处理。
	CleanupFingerprints []string `json:"cleanup_fingerprints,omitempty"`
	// LocalScript 非空表示本次 Bash 命令执行的是本地脚本文件，这里附带其源码
	// 预览（工作目录内、头 8K+尾 4K 截断）——脚本副作用据此可判，不再
	// 「内容不可见只能 ASK」。读取失败时 ReadError 说明原因，仍按信息不足处理。
	LocalScript *LocalScriptRef `json:"local_script,omitempty"`
}

// LocalScriptRef 被执行脚本的源码引用（随裁判输入下发）。
type LocalScriptRef struct {
	Path      string `json:"path"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	ReadError string `json:"read_error,omitempty"`
}

type reviewContextKey struct{}
type reviewEnvironment struct {
	workingDir string
	background ReviewBackground
}

// WithReviewContext explicitly binds the permitted background for one run. Never
// fall back to the raw turn transcript: it may contain the full scheduler prompt.
// This is application wiring, not a model-callable tool.
func WithReviewContext(ctx context.Context, workingDir string, background ReviewBackground) context.Context {
	return context.WithValue(ctx, reviewContextKey{}, reviewEnvironment{workingDir, background})
}

// WithReviewWorkingDirectory preserves only explicitly selected background.
// Chat runs can be human-initiated or scheduled, so the Agent must not infer
// message provenance from the text it receives.
func WithReviewWorkingDirectory(ctx context.Context, workingDir string) context.Context {
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	env.workingDir = workingDir
	return context.WithValue(ctx, reviewContextKey{}, env)
}

func BuildReviewInput(ctx context.Context, tool string, arguments json.RawMessage) (ReviewInput, error) {
	if !json.Valid(arguments) {
		return ReviewInput{}, fmt.Errorf("工具参数不是有效 JSON")
	}
	in := ReviewInput{Version: 4, Tool: tool, Arguments: append(json.RawMessage(nil), arguments...)}
	if env, ok := ctx.Value(reviewContextKey{}).(reviewEnvironment); ok {
		in.WorkingDir = env.workingDir
		background := env.background
		if background.Source == BackgroundUserMessage && strings.TrimSpace(background.Text) != "" {
			var cut bool
			background.Text, cut = bounded(background.Text, reviewTextLimit)
			background.Truncated = background.Truncated || cut
			in.Background = &background
		}
	}
	// Bash 执行本地脚本 → 附带脚本源码（副作用可判，不再"内容不可见只能ASK"）
	AttachLocalScript(&in, arguments)
	return in, nil
}
