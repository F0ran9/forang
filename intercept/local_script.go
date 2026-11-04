package intercept

// local_script.go — Bash 执行本地脚本时的源码附带：裁判只看命令行
// `python3 fetch_pages.py` 无法判断脚本副作用（只读 or 写删目标），只能
// ASK 转人工。这里在构建审查输入时提取脚本路径，读出源码（限任务工作
// 目录内）随 ReviewInput.local_script 下发给裁判。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	scriptHeadLimit = 8 << 10 // 头部 8K（imports + 主逻辑通常在前）
	scriptTailLimit = 4 << 10 // 尾部 4K（删除/清理循环常在末尾）
	scriptTotalCap  = 32 << 10
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

// ExtractScriptPath 从 Bash 命令里提取被执行的本地脚本路径。
// 匹配形态：`python3 x.py`、`bash ./x.sh`、`python3 -u dir/x.py args…`、
// `node --flag x.js`。返回空串表示命令不以脚本文件方式执行。
func ExtractScriptPath(command string) string {
	fields := splitFields(command)
	if len(fields) < 2 {
		return ""
	}
	// 剥掉 env / sudo 前缀
	i := 0
	for i < len(fields) && (fields[i] == "env" || fields[i] == "sudo") {
		i++
		// env 可能带 VAR=val
		for i < len(fields) && strings.Contains(fields[i], "=") && !strings.HasPrefix(fields[i], "-") {
			i++
		}
	}
	if i >= len(fields) || !scriptRunners[filepath.Base(fields[i])] {
		return ""
	}
	// runner 之后的第一个非 flag 参数即脚本；-c/-m 的取值（内联代码/模块名）跳过
	skipNext := false
	for j := i + 1; j < len(fields); j++ {
		f := fields[j]
		if skipNext {
			skipNext = false
			continue
		}
		if f == "-c" || f == "-m" || f == "-W" {
			skipNext = true // 这些 flag 的下一个参数是代码/模块名，不是文件
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		if strings.Contains(f, "=") && !strings.Contains(f, "/") {
			continue // 仍可能是 env 风格 KEY=VAL
		}
		if !looksLikeScript(filepath.Base(fields[i]), f) {
			continue // 数字/裸词等不像脚本的参数（如 python3 -m http.server 8000 的端口）
		}
		return f
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
	raw := ExtractScriptPath(args.Command)
	if raw == "" {
		return
	}
	ref := &LocalScriptRef{Path: raw}

	// 解析绝对路径（相对 working_directory）
	p := raw
	if !filepath.IsAbs(p) {
		if in.WorkingDir == "" {
			ref.ReadError = "相对路径且无 working_directory，无法读取"
			in.LocalScript = ref
			return
		}
		p = filepath.Join(in.WorkingDir, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		ref.ReadError = "路径解析失败"
		in.LocalScript = ref
		return
	}
	// 越界防护：只读工作目录子树（防审查通道变任意文件读取口）
	if in.WorkingDir != "" {
		wdAbs, werr := filepath.Abs(in.WorkingDir)
		if werr == nil && !strings.HasPrefix(abs+string(filepath.Separator), wdAbs+string(filepath.Separator)) && abs != wdAbs {
			ref.ReadError = "脚本路径不在任务工作目录内，不附带内容（防审查通道读取任意文件）"
			in.LocalScript = ref
			return
		}
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		ref.ReadError = "读取失败: " + err.Error()
		in.LocalScript = ref
		return
	}
	if len(data) > scriptTotalCap {
		data = nil // 超大脚本不附带（可能是数据文件被误判）
		ref.ReadError = fmt.Sprintf("脚本超过 %d 字节，不附带（疑似数据文件或误判）", scriptTotalCap)
		in.LocalScript = ref
		return
	}
	if len(data) > scriptHeadLimit+scriptTailLimit {
		head := data[:scriptHeadLimit]
		tail := data[len(data)-scriptTailLimit:]
		ref.Content = string(head) + "\n……[中略 " + fmt.Sprint(len(data)-scriptHeadLimit-scriptTailLimit) + " 字节]……\n" + string(tail)
		ref.Truncated = true
	} else {
		ref.Content = string(data)
	}
	in.LocalScript = ref
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
		case r == '"' && !inS:
			inD = !inD
		case (r == ' ' || r == '\t' || r == '\n') && !inS && !inD:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}
