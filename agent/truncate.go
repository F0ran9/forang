package agent

import "strings"

// truncateRunes 按 rune 截断字符串到 max 长度（原实现曾放在 tools_carriers.go，
// 三端载体模块下线后迁到这里，pocs 验证输出仍依赖）。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// vulnPreview 截断工具输出/报文预览（原实现曾放在 tools_vuln.go，漏洞中枢
// 下线后迁到这里，frida/apimodel/screenshot 等工具的错误预览仍依赖）。
func vulnPreview(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "…（截断）"
}
