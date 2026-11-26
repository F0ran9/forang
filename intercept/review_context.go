package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
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
// ReviewScope 是任务的授权范围事实（来自平台 DB，不是模型生成的内容）。
// 裁判据此判断"这条命令打的是不是任务范围内、已获授权的目标"。
type ReviewScope struct {
	TaskID       string   `json:"task_id,omitempty"`
	Goal         string   `json:"goal,omitempty"`           // 人类写的任务目标（截断）
	InScope      []string `json:"in_scope,omitempty"`       // 在册目标（去重，限量）
	InScopeTotal int      `json:"in_scope_total,omitempty"` // 在册目标总数
	// Matched / Unknown 是"本次命令实际涉及的主机"的归属判定（按 DB 精确比对），
	// 比只看截断后的 in_scope 列表可靠——线上 #2628 就是因为目标不在前 12 个里，
	// 被裁判当成"不在授权范围"而 ASK。
	Matched []string `json:"matched,omitempty"`
	Unknown []string `json:"unknown,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// ScopeResolver 由 server 注入：按 task_id 返回任务范围事实。
// 未注入时（单测/无 DB）裁判输入里不带 scope。
var ScopeResolver func(taskID string) (ReviewScope, bool)

// ScopeTargetChecker 由 server 注入：判断某主机是否登记在任务范围内（精确查库）。
var ScopeTargetChecker func(taskID, host string) bool

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
	// LocalScripts 是本次命令涉及的全部脚本（复合命令可能跑多个）。
	// 保留 LocalScript 作首个元素的兼容字段，老提示词仍能读到。
	LocalScripts []LocalScriptRef `json:"local_scripts,omitempty"`
	// LocalWrite 非空表示本次是 Write/Edit 类本地落盘工具，这里给出目标路径、
	// 是否在工作目录内、是否已存在等事实——避免裁判把「本地写分析脚本」
	// 误判成「在目标系统写入后门/持久化」。
	LocalWrite *LocalWriteHint `json:"local_write,omitempty"`
	// Scope 非空表示本次调用属于某个任务的授权范围，用于避免把授权测试
	// 判成对陌生生产系统的攻击（线上 #1634：IMAP 认证探测被误判）。
	Scope *ReviewScope `json:"scope,omitempty"`
}

// LocalScriptRef 被执行脚本的源码引用（随裁判输入下发）。
type LocalScriptRef struct {
	Path      string `json:"path"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	ReadError string `json:"read_error,omitempty"`
	// Source 说明内容从哪来：file（磁盘原文）/ file-truncated（头尾截断）/
	// command-inline（命令里的 heredoc，审批时文件尚未落盘）。裁判据此判断
	// "看到的就是将要执行的全部内容"，而不是猜。
	Source string `json:"source,omitempty"`
	// GeneratedBy 非空表示该脚本是命令内派生出来的（如 sed 改写源脚本后重定向），
	// 这里给出派生命令，便于裁判判断"改写后的行为是否仍与原脚本一致"。
	GeneratedBy string `json:"generated_by,omitempty"`
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
	AttachLocalWrite(&in, tool, arguments)
	// 任务授权范围（平台事实，供裁判区分"授权测试"与"陌生攻击"）
	if tid := TaskIDFromContext(ctx); tid > 0 && ScopeResolver != nil {
		if sc, ok := ScopeResolver(fmt.Sprintf("%d", tid)); ok {
			attachScopeTargets(&sc, fmt.Sprintf("%d", tid), tool, arguments)
			in.Scope = &sc
		}
	}
	return in, nil
}

// WorkingDirFromContext 取出当前调用绑定的任务工作目录（供预筛判断"本地写"归属）。
func WorkingDirFromContext(ctx context.Context) string {
	if env, ok := ctx.Value(reviewContextKey{}).(reviewEnvironment); ok {
		return env.workingDir
	}
	return ""
}

// hostPattern 粗粒度提取命令行里的 IPv4 与域名（用于范围归属判定，不作精确解析）。
var hostPattern = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b`)

// attachScopeTargets 从本次命令里提取目标主机，按 DB 判定是否在册。
// 只解析 Bash 的 command 字段——其它工具的参数（脚本正文等）会引入大量噪音 IP。
func attachScopeTargets(sc *ReviewScope, taskID, tool string, arguments json.RawMessage) {
	if sc == nil || ScopeTargetChecker == nil || tool != "Bash" {
		return
	}
	var a struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(arguments, &a); err != nil {
		return
	}
	seen := map[string]bool{}
	for _, m := range hostPattern.FindAllString(a.Command, -1) {
		h := strings.ToLower(strings.TrimSpace(m))
		if seen[h] || len(h) < 4 {
			continue
		}
		// 过滤明显不是目标的常量
		switch h {
		case "127.0.0.1", "0.0.0.0", "localhost", "example.com":
			continue
		}
		seen[h] = true
		if len(sc.Matched)+len(sc.Unknown) >= 6 {
			break
		}
		if ScopeTargetChecker(taskID, h) {
			sc.Matched = append(sc.Matched, h)
		} else {
			sc.Unknown = append(sc.Unknown, h)
		}
	}
}
