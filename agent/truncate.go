package agent

// truncateRunes 按 rune 截断字符串到 max 长度（原实现曾放在 tools_carriers.go，
// 三端载体模块下线后迁到这里，pocs 验证输出仍依赖）。
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
