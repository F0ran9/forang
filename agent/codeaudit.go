package agent

// codeaudit.go — 源码审计模式（按任务生效，移植自 CodeScan-Artex 的工具面收口思想）：
//   FORANG 是渗透平台，不能像纯审计平台那样全局删除出网/执行工具；审计任务通过
//   tasks.audit_mode 标记，worker/planner 装配工具时按黑名单过滤——审计任务里 agent
//   只有本地文件工具（Read/Grep/Glob/LS/Write/Edit）+ 平台登记工具（report_finding/
//   insert_assets/record_fact/kb_search 等），一切结论由源码证据支撑，不出网不执行。
//
//   判定入口是包级 resolver（server 启动时注入，查 tasks.audit_mode），
//   worker.Execute 按 taskID 查一次并缓存到 ToolSet。

import (
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// auditDeniedTools 审计任务工具黑名单（小写；带 * 前缀匹配）。
// 与渗透工具面的差集 = 审计任务里被移除的能力：命令执行、出网、流量、
// webshell/C2/扫描/模拟器/frida/自动升级/截图留证（审计不需要打目标）。
var auditDeniedTools = []string{
	// SDK：命令执行 / 出网 / 子代理（会递归带回上述能力）
	"bash", "shell", "shell_session", "sleep", "monitor",
	"webfetch", "websearch", "web_search", "fetch", "curl", "wget",
	"task", "taskoutput", "taskstop", "tasklist",
	// 平台渗透工具
	"mcp__*",
	"traffic_*",
	"repeater_*", "web_screenshot",
	"webshell_gen", "webshell_exec", "auto_escalate", "fingerprint",
	"port_scan", "dir_scan",
	"c2_*",
	"droid_*", "frida_*",
	// 自建可执行能力与 MCP 管理
	"command", "script",
	"create_custom_tool", "update_custom_tool", "create_mcp", "update_mcp", "test_custom_tool",
}

// auditModeResolver 由 server 注入：taskID → 是否审计任务。
var auditModeResolver func(taskID int64) bool

// SetAuditModeResolver server 启动时注入（对齐 SetTargetProxy 模式）。
func SetAuditModeResolver(f func(taskID int64) bool) { auditModeResolver = f }

// taskIsAudit 判定任务是否审计模式（resolver 缺省 = 否）。
func taskIsAudit(taskID int64) bool {
	if auditModeResolver == nil {
		return false
	}
	return auditModeResolver(taskID)
}

// auditDenied 命中黑名单即剔除。
func auditDenied(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, p := range auditDeniedTools {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(n, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if n == p {
			return true
		}
	}
	return false
}

// FilterAuditTools 过滤工具列表（审计任务装配时调用）。
func FilterAuditTools(tools []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if auditDenied(t.Name()) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// auditSystemBlock 审计任务的系统提示追加块：源码位置 + 静态审计纪律。
// sourceRel 是任务源码目录相对 data 根的路径（tasks/<id>/source）；worker 的
// 工作目录是 tasks/<id>/i<intent>，所以同级相对路径 ../source 即源码根。
func auditSystemBlock(sourceRel string) string {
	b := "\n\n━━ 源码审计模式（本任务为静态代码审计）━━\n"
	b += "- 被审源码已解压在 ../source（即 " + sourceRel + "）：先 LS ../source 看清结构，再 Glob 找入口（**/*Controller.java、**/routes/*.js、**/urls.py、**/*.php 等），Grep 搜模式，Read 精读——先定位再精读，不要整库乱读。\n"
	b += "- 只做静态分析：不发起任何网络请求、不执行任何命令、不做运行时验证（这些工具本任务里不存在）。结论必须由源码证据支撑：漏洞要给 文件:行号 + 代码片段。\n"
	b += "- 接口清点用 insert_assets（type=endpoint）：url/method/params/permission（公开/注册用户/登录用户/管理员权限/内部接口/其他，判定依据：鉴权注解>拦截器/中间件>路由分组）。\n"
	b += "- 数据流三步才算缺陷：① 入口参数可控 ② 中间校验确实缺失 ③ 到达危险 Sink（SQL/命令/反序列化/路径/SSRF）。仅「用了拼接」或「依赖版本命中 CVE」不算——记为存疑事实即可。\n"
	b += "- 对抗式自检：每个疑似漏洞先换一条证据链证伪一次（参数真可控？校验真缺失？路径真可达？），过了再 report_finding。\n"
	b += "- 只读纪律：不修改 ../source 下任何文件（Write/Edit 只用于自己的工作产物）。\n"
	return b
}
