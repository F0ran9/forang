package intercept

// local_script.go — Bash 执行本地脚本时的源码附带：裁判只看命令行
// `python3 fetch_pages.py` 无法判断脚本副作用（只读 or 写删目标），只能
// ASK 转人工。这里在构建审查输入时提取脚本路径，读出源码（限任务工作
// 目录内）随 ReviewInput.local_script 下发给裁判。
//
// 2026-11-25 补充（线上反馈「AI 只能看到系统运行了某个脚本、看不到脚本内容」）：
// 真实命令经常是复合形态，早期实现只认 `python3 x.py` 这种"单命令 + 脚本参数"，
// 以下三类全部落空，裁判只能看到 `bash probe.sh` 干瞪眼：
//  1. 复合命令：`cd /work/i697 && bash probe.sh | tee round1.log`
//  2. shell 包装：`sh -c 'bash probe.sh'`
//  3. 同一条命令里现场生成脚本：`cat > probe.sh <<'EOF' … EOF && bash probe.sh`
// 现在按段扫描（&& / || / ; / | / 换行），递归展开 `-c`，并对"审批时文件还
// 不存在但命令自带 heredoc"的情况直接从命令里抽内联源码。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	scriptHeadLimit  = 8 << 10 // 头部 8K（imports + 主逻辑通常在前）
	scriptTailLimit  = 4 << 10 // 尾部 4K（删除/清理循环常在末尾）
	scriptTotalCap   = 32 << 10
	scriptMaxScripts = 3 // 一条命令最多附带 3 个脚本，避免提示词爆掉
)

// scriptRunners 命令行首程序 → 后续第一个非flag参数视为脚本路径。
var scriptRunners = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"node": true, "perl": true, "ruby": true, "php": true,
	"osascript": true, "pwsh": true,
}

// scriptExts 明确的脚本扩展名（无扩展名也可，靠 runner 判定）。
var scriptExts = map[string]bool{
	".py": true, ".pyw": true, ".sh": true, ".bash": true, ".zsh": true,
	".js": true, ".mjs": true, ".cjs": true, ".pl": true, ".pm": true,
	".rb": true, ".php": true, ".ps1": true, ".lua": true,
}

// ExtractScriptPath 从 Bash 命令里提取被执行的本地脚本路径（首个）。
// 保留旧签名供既有调用/测试使用；新代码请用 ExtractScriptPaths。
func ExtractScriptPath(command string) string {
	ps := ExtractScriptPaths(command)
	if len(ps) == 0 {
		return ""
	}
	return ps[0]
}

// ExtractScriptPaths 从（可能是复合的）Bash 命令里提取全部被执行脚本路径。
// 支持：`a && bash x.sh | tee log`、`sh -c 'bash y.sh'`、`(cd d; python z.py)`。
func ExtractScriptPaths(command string) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(cmd string, depth int)
	walk = func(cmd string, depth int) {
		if depth > 2 {
			return
		}
		for _, seg := range splitSegments(cmd) {
			if p := extractOne(seg); p != "" {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
				continue
			}
			// sh -c '...' / bash -c "..." → 递归展开内层命令
			if inner := extractInlineCommand(seg); inner != "" {
				walk(inner, depth+1)
			}
		}
	}
	walk(command, 0)
	return out
}

// splitSegments 按 shell 连接符切段（引号内的连接符不切）。
func splitSegments(s string) []string {
	var out []string
	var cur strings.Builder
	inS, inD := false, false
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inD:
			inS = !inS
			cur.WriteByte(c)
		case c == '"' && !inS:
			inD = !inD
			cur.WriteByte(c)
		case inS || inD:
			cur.WriteByte(c)
		case c == '\n' || c == ';':
			flush()
		case c == '&' || c == '|':
			flush()
			if i+1 < len(s) && (s[i+1] == '&' || s[i+1] == '|') {
				i++
			}
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// extractOne 从单个命令段里取出被执行的脚本路径。
func extractOne(seg string) string {
	fields := splitFields(seg)
	if len(fields) < 2 {
		return ""
	}
	// 剥掉 env / sudo / nohup / timeout 等前缀
	i := 0
	for i < len(fields) {
		f := fields[i]
		if f == "env" || f == "sudo" || f == "nohup" || f == "command" {
			i++
			for i < len(fields) && strings.Contains(fields[i], "=") && !strings.HasPrefix(fields[i], "-") {
				i++
			}
			continue
		}
		if f == "timeout" {
			i += 2 // timeout 30s bash x.sh
			continue
		}
		break
	}
	if i >= len(fields) {
		return ""
	}
	// 形态 A：脚本自身作为命令首令牌（`./dns_round.sh r1`、`/opt/x/probe.sh`），
	// 靠 shebang 执行，没有 bash/python 前缀——线上 1799 号审批就是这种。
	// 只认带脚本扩展名的（`./dns_round.sh`、`/opt/x/probe.sh`）；
	// 裸可执行文件（`./custom-runner`、`/usr/bin/curl`）不当脚本，避免把二进制读进来
	if !scriptRunners[filepath.Base(fields[i])] {
		if tok := unquote(fields[i]); scriptExts[strings.ToLower(filepath.Ext(tok))] && strings.Contains(tok, "/") {
			return tok
		}
	}
	if !scriptRunners[filepath.Base(fields[i])] {
		return ""
	}
	runner := filepath.Base(fields[i])
	skipNext := false
	for j := i + 1; j < len(fields); j++ {
		f := unquote(fields[j]) // 引号包裹的路径（python3 'my script.py'）要去壳
		if skipNext {
			skipNext = false
			continue
		}
		if f == "-c" || f == "-m" || f == "-W" || f == "-e" {
			skipNext = true // 这些 flag 的下一个参数是代码/模块名，不是文件
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		if strings.Contains(f, "=") && !strings.Contains(f, "/") {
			continue // 仍可能是 env 风格 KEY=VAL
		}
		// 重定向符不是脚本：`2>/dev/null`、`>/tmp/o`、`2>&1`、`<in`
		if strings.ContainsAny(f, "<>") || strings.HasPrefix(f, "/dev/") {
			continue
		}
		if !looksLikeScript(runner, f) {
			continue
		}
		return f
	}
	return ""
}

// extractInlineCommand 取 `sh -c '<payload>'` 的内层命令文本。
func extractInlineCommand(seg string) string {
	fields := splitFields(seg)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-c" {
			inner := strings.TrimSpace(unquote(fields[i+1]))
			if inner != "" && (strings.ContainsAny(inner, " \t/") || scriptRunners[filepath.Base(inner)]) {
				return inner
			}
		}
	}
	return ""
}

// looksLikeScript 参数像不像被执行的脚本文件：有脚本扩展名直接认；无扩展名时
// shell 系可跑裸名（bash runme），解释器系（python/node…）须带路径分隔符。
func looksLikeScript(runner, f string) bool {
	if f == "" || isAllDigits(f) {
		return false
	}
	if scriptExts[strings.ToLower(filepath.Ext(f))] {
		return true
	}
	switch runner {
	case "bash", "sh", "zsh", "dash":
		return !strings.Contains(f, "://") // 裸名/路径都认；URL 不认
	}
	return strings.Contains(f, "/")
}

// AttachLocalScript 为 Bash 调用附带脚本源码（工作目录内才读；越界记 ReadError）。
// 返回的 ref 恒非 nil（读不到也有 ReadError 说明），供裁判按信息不足处理。
func AttachLocalScript(in *ReviewInput, arguments json.RawMessage) {
	if in == nil || in.Tool != "Bash" {
		return
	}
	var args struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(arguments, &args); err != nil {
		return
	}
	paths := ExtractScriptPaths(args.Command)
	if len(paths) == 0 {
		// 没有脚本文件，但可能有"喂给解释器的内联代码"
		if refs := extractInlineCode(args.Command); len(refs) > 0 {
			in.LocalScript = &refs[0]
			in.LocalScripts = refs
		}
		return
	}
	if len(paths) > scriptMaxScripts {
		paths = paths[:scriptMaxScripts]
	}
	var refs []LocalScriptRef
	budget := scriptTotalCap
	for _, raw := range paths {
		refs = append(refs, loadScriptRef(in.WorkingDir, raw, args.Command, &budget))
	}
	// 同一条命令里可能既有脚本文件又有 stdin 内联代码，两者都带上
	refs = append(refs, extractInlineCode(args.Command)...)
	if len(refs) > scriptMaxScripts {
		refs = refs[:scriptMaxScripts]
	}
	first := refs[0]
	in.LocalScript = &first
	in.LocalScripts = refs
}

// extractInlineCode 抽「没有脚本文件、代码走 stdin/参数」的形态：
//
//	python3 - <<'EOF' … EOF      （stdin heredoc）
//	bash -s <<EOF … EOF
//	python3 -c '...'             （-c 内联代码）
//
// 这些代码在命令行里看得见，但旧实现当成"没有脚本"直接跳过，裁判只能 ASK。
func extractInlineCode(command string) []LocalScriptRef {
	var refs []LocalScriptRef
	lines := strings.Split(command, "\n")
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		seg := ln
		idx := strings.Index(ln, "<<")
		if idx >= 0 {
			seg = ln[:idx]
		}
		runner, marker := stdinRunner(seg)
		if runner == "" {
			continue
		}
		if marker == "stdin" && idx >= 0 {
			delim := parseHeredocDelimiter(ln[idx:])
			if delim == "" {
				continue
			}
			var body []string
			ok := false
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == delim {
					ok = true
					i = j
					break
				}
				body = append(body, lines[j])
			}
			if !ok || len(body) == 0 {
				continue
			}
			refs = append(refs, LocalScriptRef{
				Path:    "<stdin:" + runner + ">",
				Content: strings.Join(body, "\n"),
				Source:  "command-inline",
			})
			continue
		}
		if marker == "c" {
			// python3 -c "..." / node -e "..."：取 -c/-e 后面那段
			if code := flagCode(ln); code != "" {
				refs = append(refs, LocalScriptRef{
					Path:    "<-c:" + runner + ">",
					Content: code,
					Source:  "command-inline",
				})
			}
		}
	}
	return refs
}

// stdinRunner 判断这段命令是否「解释器 + 从 stdin 读代码」或「解释器 -c 内联」。
func stdinRunner(seg string) (runner, marker string) {
	fields := splitFields(seg)
	for i, f := range fields {
		base := filepath.Base(unquote(f))
		if !scriptRunners[base] {
			continue
		}
		// 解释器后的标记：`-`（stdin）、`-s`（bash 从 stdin）、`-c`/`-e`（内联）
		for j := i + 1; j < len(fields); j++ {
			t := unquote(fields[j])
			switch t {
			case "-":
				return base, "stdin"
			case "-s":
				return base, "stdin"
			case "-c", "-e":
				return base, "c"
			}
			if !strings.HasPrefix(t, "-") {
				break // 遇到文件参数就不是 stdin 形态
			}
		}
		return "", ""
	}
	return "", ""
}

// flagCode 取 `-c` / `-e` 后面的代码字符串。
func flagCode(line string) string {
	fields := splitFields(line)
	for i := 0; i+1 < len(fields); i++ {
		if t := unquote(fields[i]); t == "-c" || t == "-e" {
			return unquote(fields[i+1])
		}
	}
	return ""
}

// loadScriptRef 读取单个脚本：优先磁盘；磁盘没有时从命令里的 heredoc 抽内联源码。
func loadScriptRef(workingDir, raw, command string, budget *int) LocalScriptRef {
	ref := LocalScriptRef{Path: raw}

	p := raw
	if !filepath.IsAbs(p) {
		if workingDir == "" {
			if src, ok := extractInlineScript(command, raw); ok {
				ref.Content = clipScript(src, budget)
				ref.Source = "command-inline"
				return ref
			}
			ref.ReadError = "相对路径且无 working_directory，无法读取脚本文件"
			return ref
		}
		p = filepath.Join(workingDir, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		ref.ReadError = "路径解析失败"
		return ref
	}
	// 越界防护：只读工作目录子树（防审查通道变任意文件读取口）
	if workingDir != "" {
		wdAbs, werr := filepath.Abs(workingDir)
		if werr == nil && !strings.HasPrefix(abs+string(filepath.Separator), wdAbs+string(filepath.Separator)) && abs != wdAbs {
			ref.ReadError = "脚本路径不在任务工作目录内，不附带内容（防审查通道读取任意文件）"
			return ref
		}
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		// 文件还不存在（同一命令里现场生成）→ 从命令的 heredoc 抽正文
		if src, ok := extractInlineScript(command, raw); ok {
			ref.Content = clipScript(src, budget)
			ref.Source = "command-inline"
			return ref
		}
		ref.ReadError = "读取失败: " + err.Error()
		return ref
	}
	if len(data) > scriptTotalCap {
		ref.ReadError = fmt.Sprintf("脚本超过 %d 字节，不附带（疑似数据文件或误判）", scriptTotalCap)
		return ref
	}
	ref.Content = clipScript(string(data), budget)
	ref.Truncated = len(ref.Content) < len(data)
	if ref.Truncated {
		ref.Source = "file-truncated"
	} else {
		ref.Source = "file"
	}
	return ref
}

// clipScript 按"头 8K + 尾 4K"截断，并从共享预算里扣减。
func clipScript(s string, budget *int) string {
	if *budget <= 0 {
		return ""
	}
	if len(s) > *budget {
		s = s[:*budget]
	}
	out := s
	if len(s) > scriptHeadLimit+scriptTailLimit {
		head := s[:scriptHeadLimit]
		tail := s[len(s)-scriptTailLimit:]
		out = head + "\n……[中略 " + fmt.Sprint(len(s)-scriptHeadLimit-scriptTailLimit) + " 字节]……\n" + tail
	}
	*budget -= len(s)
	return out
}

// extractInlineScript 从命令里抽 `cat > <path> <<'EOF' … EOF` / `tee <path> <<EOF`
// 之类内联写入的脚本体。path 可按原值、相对名或 basename 匹配。
func extractInlineScript(command, path string) (string, bool) {
	lines := strings.Split(command, "\n")
	want := filepath.Base(path)
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		idx := strings.Index(ln, "<<")
		if idx < 0 || !redirectsTo(ln[:idx], path, want) {
			continue
		}
		delim := parseHeredocDelimiter(ln[idx:])
		if delim == "" {
			continue
		}
		var body []string
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == delim {
				return strings.Join(body, "\n"), true
			}
			body = append(body, lines[j])
		}
		return "", false // 没有结束符：不猜
	}
	return "", false
}

// redirectsTo 判断 heredoc 之前的那段里是否把输出重定向到了 path（或同名文件）。
func redirectsTo(prefix, path, base string) bool {
	for _, tok := range splitFields(prefix) {
		tok = strings.TrimSpace(strings.TrimLeft(tok, ">"))
		if tok == "" || tok == ">" {
			continue
		}
		if tok == path || filepath.Base(tok) == base {
			return true
		}
	}
	return false
}

// parseHeredocDelimiter 解析 `<<'EOF'` / `<<-EOF` / `<<"EOF"` 里的结束标记。
func parseHeredocDelimiter(s string) string {
	s = strings.TrimPrefix(s, "<<")
	s = strings.TrimPrefix(s, "-")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if q := s[0]; q == '\'' || q == '"' {
		end := strings.IndexByte(s[1:], q)
		if end < 0 {
			return ""
		}
		return s[1 : 1+end]
	}
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}

// unquote 去掉包裹的引号。
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// isAllDigits 全数字串（端口/数字参数）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// splitFields 简易命令分词（引号包裹作为一个字段；不展开通配/变量）。
func splitFields(s string) []string {
	var out []string
	var cur strings.Builder
	inS, inD := false, false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '\'' && !inD:
			inS = !inS
			cur.WriteRune(r)
		case r == '"' && !inS:
			inD = !inD
			cur.WriteRune(r)
		case (r == ' ' || r == '\t' || r == '\n') && !inS && !inD:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// ScriptExcerptFor 给「人工审批」用的脚本体摘要（判不了要人工时，人也要看得见）。
// 与裁判输入共用同一套提取逻辑，只取前 excerptLimit 字节。
func ScriptExcerptFor(toolName string, input json.RawMessage) string {
	const excerptLimit = 1200
	in := &ReviewInput{Tool: toolName}
	// 人工侧没有工作目录上下文时，仍可从命令 heredoc 里抽到正文
	AttachLocalScript(in, input)
	if in.LocalScripts == nil && in.LocalScript != nil {
		in.LocalScripts = []LocalScriptRef{*in.LocalScript}
	}
	var b strings.Builder
	for _, ref := range in.LocalScripts {
		if ref.Content == "" {
			continue
		}
		from := "脚本文件"
		if ref.Source == "command-inline" {
			from = "命令内联（heredoc，执行时现场生成）"
		}
		remain := excerptLimit
		fmt.Fprintf(&b, "\n\n📄 %s（%s）:\n```\n%s\n```", ref.Path, from, clipScript(ref.Content, &remain))
	}
	return b.String()
}
