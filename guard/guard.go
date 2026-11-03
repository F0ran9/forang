// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"strings"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.

// CleanupTaskResolver 由 server 注入：taskID → 是否「痕迹清理」任务
//（tasks.cleanup_mode）。清理任务里删除类规则的 deny 改道 AI 裁判，
// 裁判不放行再转人工——默认自动清理、AI 审批优先、人只是兜底。
var CleanupTaskResolver func(taskID int64) bool
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	g.record(ev.ToolName, "allow", "", cmd)
	return g.applyIntercept(ctx, ev)
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// 前缀白名单（哨兵语义）：简单命令首词放行，复合命令不适用。
		if g.interceptor.PrefixAllowed(ev.ToolName, ev.Input) {
			g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), intercept.Decision{Action: "allow", RuleName: "前缀白名单", Message: "[前缀白名单] 首词命中 intercept_allow_prefixes"}, ev.ToolName, ev.Input, "allowed")
			return hook.Result{}
		}
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 测试数据清理模式（settings cleanup_mode，默认关）：删除类规则命中时从
		// 「直接拒绝」降级为「人工审批」——清理被测站上测试痕迹需要调删除接口，
		// 但绝不放开：每一条删除仍要操作员在审批队列逐条确认（ask 超时即 deny）。
		// AI 裁判不参与降级路径——人工是最终关口，judge 的 D4「破坏业务数据」
		// 判据在清理场景必然误伤（删的就是测试数据），故清理模式只认人工。
		// 边界控制：只有「HTTP 删除类接口」规则（删除类接口路径/HTTP DELETE/清空删除
		// 路径）在清理任务里改道 AI 裁判；破坏性命令与数据库破坏规则（rm -rf、DROP、
		// TRUNCATE…）在任何任务里都保持硬拒绝——清测试痕迹永远用不到删库格式化。
		isHTTPDeleteRule := strings.Contains(dec.RuleName, "删除") && !strings.Contains(dec.RuleName, "破坏性")
		if isHTTPDeleteRule && CleanupTaskResolver != nil && CleanupTaskResolver(intercept.TaskIDFromContext(ctx)) {
			// 清理任务：删除类规则的 deny 不直接生效——先交 AI 裁判裁决。
			// 裁判 allow → 放行执行；ask/deny/失败（AI 定不了）→ 转人工审批队列。
			if d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input); judged && d.Action == "allow" {
				g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), d, ev.ToolName, ev.Input, "allowed")
				return hook.Result{}
			}
			d2 := dec
			d2.Action = "ask"
			d2.RuleName = dec.RuleName + "（清理任务·AI 裁判未放行→人工）"
			d2.Message = "【清理任务】" + dec.Message + " —— AI 裁判未能放行，转人工：请核对这是要清除的测试数据后批准"
			d2.TimeoutEnabled = true
			d2.TimeoutSeconds = 300
			d2.TimeoutAction = "deny"
			ok, edited := g.interceptor.HandleAsk(ctx, intercept.ConvIDFromContext(ctx), d2, ev.ToolName, ev.Input)
			if !ok {
				return g.block(ev.ToolName, systemBlockMessage("清理操作审批未通过（拒绝或超时）"), "")
			}
			if len(edited) > 0 {
				return hook.Result{UpdatedInput: edited}
			}
			return hook.Result{}
		}
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		ok, edited := g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input)
		if !ok {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		if len(edited) > 0 {
			// 用户改了参数放行：以修改稿替换原参数执行。
			return hook.Result{UpdatedInput: edited}
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
