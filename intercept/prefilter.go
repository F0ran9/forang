package intercept

// prefilter.go — 只读命令预筛：明显无副作用的命令不再消耗 AI 裁判。
//
// 线上观察（2026-11-26）：任务里 80% 的审批是 echo / sleep / curl -I / dig / cat
// 这类只读动作，全都跑一遍 AI 裁判，既慢又制造误判（模型偶尔把只读命令判成
// "行为不明"→ASK→阻塞 10 分钟）。这里在裁判之前加一道**规则层**：
// 只读白名单 + 危险特征黑名单，命中白名单即直接放行（标注 [预筛] 便于统计）。
//
// 设计原则（宁可漏过，不可错放）：
//   - 只认白名单里的程序名，解释器/未知程序一律交给裁判；
//   - 出现写重定向、-i/-o/-O/--data/上传/删除类参数，一律交给裁判；
//   - 出现命令替换 $( )、反引号、eval/exec/source、管道进 shell，一律交给裁判；
//   - 非 Bash 类工具（Write/Edit 等）不在此处判定。
//
// 关闭方式：设置 intercept.prefilter=false。

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
)

const settingPrefilter = "intercept.prefilter"

// readOnlyBins 只读命令白名单（程序名，不含路径）。
var readOnlyBins = map[string]bool{
	// 本地只读
	"echo": true, "printf": true, "true": true, "false": true, "sleep": true,
	"date": true, "whoami": true, "id": true, "hostname": true, "uname": true,
	"uptime": true, "pwd": true, "ls": true, "cat": true, "head": true, "tail": true,
	"wc": true, "sort": true, "uniq": true, "cut": true, "tr": true, "nl": true,
	"tac": true, "rev": true, "basename": true, "dirname": true, "realpath": true,
	"stat": true, "file": true, "du": true, "df": true, "diff": true, "comm": true,
	"sha256sum": true, "sha1sum": true, "md5sum": true, "md5": true, "cksum": true,
	"jq": true, "grep": true, "egrep": true, "fgrep": true, "zgrep": true, "rg": true,
	"awk": true, "sed": true, "expr": true, "seq": true, "test": true, "[": true,
	"which": true, "whereis": true, "type": true, "column": true, "fold": true,
	// 目录切换与分组：本身无副作用（后续段单独判定）
	"cd": true, "pushd": true, "popd": true, "{": true, "}": true, "(": true, ")": true,
	// shell 控制关键字：循环/条件本身不产生副作用，内部命令逐段判定
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"case": true, "esac": true, "in": true, "!": true, "time": true,
	// 网络只读
	"dig": true, "host": true, "nslookup": true, "ping": true, "ping6": true,
	"traceroute": true, "tracepath": true, "curl": true, "wget": true,
	"openssl": true, // s_client/x509 等只读探测；写文件走 -out，会被下面拦
	// 本机状态查看
	"ip": true, "ifconfig": true, "netstat": true, "ss": true, "ps": true,
	"route": true, "arp": true, "getent": true, "nproc": true, "free": true,
}

// writeRiskFlags 命中即不预筛（可能写盘/上传/改状态）的参数。
var writeRiskFlags = []string{
	"-o", "-O", "--output", "--remote-name", "--data", "-d", "--data-binary",
	"-X", "--request", "-F", "--form", "-T", "--upload-file", "--post-data",
	"--post-file", "-i", "--in-place", "--delete", "-exec", "-execdir", "-ok",
	"--remove-on-error", "-c", "--continue", "--output-document",
}

// PrefilterReadOnly 判断本次调用是否"明显只读"。返回 (是否放行, 说明)。
func PrefilterReadOnly(tool string, args json.RawMessage) (bool, string) {
	return PrefilterDecision(context.Background(), tool, args)
}

// PrefilterDecision 带上下文版本：能从 ctx 拿到任务工作目录时，
// 「只往工作目录里写本地产物」也算安全（A2：测试产物）。
func PrefilterDecision(ctx context.Context, tool string, args json.RawMessage) (bool, string) {
	if tool != "Bash" {
		return false, ""
	}
	var a struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return false, ""
	}
	return prefilterCmd(ctx, a.Command, 0)
}

// prefilterCmd 是判定主体（depth 用于 bash -c 递归，最多 2 层）。
func prefilterCmd(ctx context.Context, rawCmd string, depth int) (bool, string) {
	workdir := WorkingDirFromContext(ctx)
	cmd := strings.TrimSpace(rawCmd)
	if cmd == "" {
		return false, ""
	}
	// 命令替换 / 反引号 / 解释执行：一律交给裁判
	for _, bad := range []string{"`", "eval ", "exec ", "source ", ". /", "|sh", "| sh", "|bash", "| bash"} {
		if strings.Contains(cmd, bad) {
			return false, ""
		}
	}
	// 命令替换 $()：$(( )) 是算术运算无副作用；其余把内层命令递归判定，
	// 内层也安全才放行（线上常见 start=$(date +%s%N) 这类计时）。
	for i := 0; i+1 < len(cmd); i++ {
		if cmd[i] != '$' || cmd[i+1] != '(' {
			continue
		}
		if i+2 < len(cmd) && cmd[i+2] == '(' {
			continue
		}
		inner, ok := extractSubst(cmd, i+2)
		if !ok || depth >= 2 {
			return false, ""
		}
		if ok2, _ := prefilterCmd(ctx, inner, depth+1); !ok2 {
			return false, ""
		}
		i += len(inner) + 1
	}
	segs := splitSegments(cmd)
	if len(segs) == 0 {
		return false, ""
	}
	var bins []string
	for _, seg := range segs {
		seg = stripAssignments(seg)
		if strings.TrimSpace(seg) == "" {
			continue
		}
		fields := splitFields(seg)
		if len(fields) == 0 {
			return false, ""
		}
		// 剥掉 sudo/env 前缀
		i := 0
		for i < len(fields) && (fields[i] == "sudo" || fields[i] == "env" || fields[i] == "timeout") {
			if fields[i] == "timeout" && i+1 < len(fields) {
				i++ // 跳过时长参数
			}
			i++
			for i < len(fields) && strings.Contains(fields[i], "=") && !strings.HasPrefix(fields[i], "-") {
				i++
			}
		}
		if i >= len(fields) {
			return false, ""
		}
		bin := unquote(fields[i])
		if strings.Contains(bin, "/") {
			// 带路径的可执行文件：只接受白名单里的同名程序（如 /bin/ls、/usr/bin/dig）
			base := bin
			if j := strings.LastIndexAny(base, "/\\"); j >= 0 {
				base = base[j+1:]
			}
			if !readOnlyBins[base] {
				return false, ""
			}
			bin = base
		}
		if !readOnlyBins[bin] && !localArtifactBins[bin] {
			// bash -c '<payload>' / sh -c '<payload>'：对 payload 递归判定，
			// 通过才放行（线上都是 `bash -c 'echo > /dev/tcp/ip/port'` 这类端口探测）。
			if (bin == "bash" || bin == "sh") && depth < 2 && hasDashC(fields) {
				payload := dashCPayload(fields)
				if payload == "" {
					return false, ""
				}
				if ok, _ := prefilterDepth(ctx, payload, depth+1); !ok {
					return false, ""
				}
				bins = append(bins, bin)
				continue
			}
			return false, ""
		}
		// 本地产物类（mkdir/touch/tee/cp/mv）：所有非 flag 参数必须落在工作目录内
		if localArtifactBins[bin] {
			okAny := false
			for j := 1; j < len(fields); j++ {
				t := unquote(fields[j])
				if t == "" || strings.HasPrefix(t, "-") || strings.HasPrefix(t, "$") {
					continue
				}
				if !insideWorkdir(workdir, t) {
					return false, ""
				}
				okAny = true
			}
			if !okAny {
				return false, ""
			}
		}
		// 重定向到文件 = 写盘；2>/dev/null、>/dev/null 无实际写入，放行
		for j := 0; j < len(fields); j++ {
			f := unquote(fields[j])
			if f == ">" || f == ">>" {
				target := ""
				if j+1 < len(fields) {
					target = unquote(fields[j+1])
				}
				if target != "" && !safeWriteTarget(workdir, target) {
					return false, ""
				}
				continue
			}
			if strings.HasPrefix(f, ">>") && f != ">>/dev/null" {
				return false, ""
			}
			if strings.HasPrefix(f, ">") && f != ">/dev/null" && !strings.HasPrefix(f, ">&") && !strings.HasPrefix(f, "2>") {
				return false, ""
			}
			// curl -o /dev/null 只是丢弃响应体，等同于只读
			if bin == "curl" && (f == "-o" || f == "--output") {
				next := ""
				if j+1 < len(fields) {
					next = unquote(fields[j+1])
				}
				if safeWriteTarget(workdir, next) {
					continue
				}
				return false, ""
			}
			// 危险参数（curl -o / sed -i / find -exec 等）
			if isWriteRiskFlag(bin, f) {
				return false, ""
			}
		}
		bins = append(bins, bin)
	}
	return true, "只读命令（" + strings.Join(uniqBins(bins), ",") + "）"
}

// isWriteRiskFlag 判断某个参数是否带写风险。逐程序细化的只有 sed/find/curl/wget，
// 其它程序命中通用黑名单也算风险。
func isWriteRiskFlag(bin, f string) bool {
	// -d / -c 这类短参数含义因程序而异，只对已知危险的组合判定
	switch bin {
	case "curl":
		if f == "-d" || strings.HasPrefix(f, "--data") || f == "-F" || f == "-T" ||
			f == "-O" || f == "-X" || f == "--request" ||
			strings.HasPrefix(f, "-X") || f == "--json" || f == "-K" || f == "--config" ||
			strings.HasPrefix(f, "--json") {
			return true
		}
		return false
	case "wget":
		if f == "-O" || f == "--output-document" || strings.HasPrefix(f, "--post") ||
			f == "--method=POST" {
			return true
		}
		return false
	case "sed":
		return f == "-i" || strings.HasPrefix(f, "-i") || strings.HasPrefix(f, "--in-place")
	case "openssl":
		return f == "-out" || f == "-keyout"
	case "find":
		return f == "-delete" || f == "-exec" || f == "-execdir" || f == "-ok" || f == "-fprint"
	case "sort", "uniq", "grep", "awk":
		return f == "-o" || strings.HasPrefix(f, "--output")
	}
	// 通用：明确表示输出到文件/上传/删除的参数
	switch f {
	case "-o", "-O", "--output", "--output-document", "--upload-file", "-T",
		"--remove-on-error", "--delete", "-exec", "-execdir", "-ok":
		return true
	}
	return false
}

func uniqBins(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// localArtifactBins 会在本地产生文件的程序：目标必须落在任务工作目录内才预筛，
// 否则交给裁判（例如往 /etc 或用户家目录写就属于越界）。
var localArtifactBins = map[string]bool{
	"mkdir": true, "touch": true, "tee": true, "cp": true, "mv": true,
}

// insideWorkdir 判断路径是否落在任务工作目录内（相对路径按工作目录解析）。
//
// 统一按 "/" 归一化比较：被测环境是 Linux，而单测/开发机是 Windows，
// 用 filepath.IsAbs 会把 Linux 绝对路径 "/etc/motd" 当相对路径拼到工作目录下，
// 造成"目录外写入被误判为目录内"的严重误放行。
func insideWorkdir(workdir, p string) bool {
	if workdir == "" || p == "" {
		return false
	}
	slash := func(x string) string { return strings.ReplaceAll(x, "\\", "/") }
	wd := strings.TrimRight(slash(filepath.Clean(workdir)), "/")
	var abs string
	if strings.HasPrefix(p, "/") || filepath.IsAbs(p) {
		abs = slash(filepath.Clean(p))
	} else {
		abs = slash(filepath.Clean(filepath.Join(workdir, p)))
	}
	return abs == wd || strings.HasPrefix(abs+"/", wd+"/")
}

// hasDashC 判断参数里是否有 -c。
func hasDashC(fields []string) bool {
	for _, f := range fields {
		if unquote(f) == "-c" {
			return true
		}
	}
	return false
}

// dashCPayload 取 -c 后面的那段命令。
func dashCPayload(fields []string) string {
	for i, f := range fields {
		if unquote(f) == "-c" && i+1 < len(fields) {
			return unquote(fields[i+1])
		}
	}
	return ""
}

// safeWriteTarget 判断"写目标"是否无副作用：
//   - /dev/null：丢弃输出
//   - /dev/tcp/<host>/<port>、/dev/udp/…：bash 的端口探测语法（不落盘）
//   - /tmp、/dev/shm：一次性中间产物（A2）
//   - 任务工作目录内：测试产物
func safeWriteTarget(workdir, target string) bool {
	t := strings.TrimSpace(target)
	if t == "" || t == "/dev/null" {
		return true
	}
	for _, p := range []string{"/dev/tcp/", "/dev/udp/", "/tmp/", "/dev/shm/", "/var/tmp/"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return insideWorkdir(workdir, t)
}

// prefilterDepth 带递归深度的判定入口。
func prefilterDepth(ctx context.Context, cmd string, depth int) (bool, string) {
	return prefilterCmd(ctx, cmd, depth)
}

// extractSubst 从 start（"$(" 之后）取出配平的括号内容与结束位置。
func extractSubst(s string, start int) (string, bool) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[start:i], true
			}
		}
	}
	return "", false
}

// stripAssignments 去掉命令段开头的 shell 变量赋值（NAME=value / NAME=$(cmd)），
// 它们不产生副作用，但会把后续字段切碎（start=$(date +%s%N) 会被切成两段）。
func stripAssignments(seg string) string {
	for {
		t := strings.TrimLeft(seg, " \t")
		eq := strings.Index(t, "=")
		if eq <= 0 {
			return t
		}
		name := t[:eq]
		if strings.ContainsAny(name, "/ \t$'\"`") {
			return t
		}
		rest := t[eq+1:]
		// 值以 $( 或 $(( 开头：跳到配平的右括号
		if strings.HasPrefix(rest, "$(") {
			if _, ok := extractSubst(rest, 2); ok {
				i := 2
				depth := 1
				for i < len(rest) && depth > 0 {
					switch rest[i] {
					case '(':
						depth++
					case ')':
						depth--
					}
					i++
				}
				seg = rest[i:]
				continue
			}
		}
		// 普通值：吃到第一个空白
		if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
			seg = rest[sp:]
			continue
		}
		return ""
	}
}
