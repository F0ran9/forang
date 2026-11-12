package webshell

// privesc.go — 提权面分析。
//
// 为什么不内置 Potato / 各种 exp 二进制：
//   - 第三方 exp 的授权状态大多不明，塞进 AGPL 仓库会污染整个项目的分发授权；
//   - 这类二进制是杀软的重点照顾对象，一落地基本必被查杀，反而降低成功率。
//
// 这里做的是「把目标的可提权面结构化」，交给 Agent 判断该走哪条路：
// 令牌权限、SUID、sudo 配置、可写敏感路径、服务路径引号、AlwaysInstallElevated 等。
// 平台的价值在判断与编排，不在攒 exp 大全。
//
// 所有命令都是只读查询，不改目标任何状态；单条命令失败只影响该项判定。

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PrivescFinding 一条提权线索。
type PrivescFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Risk     string `json:"risk"` // critical / high / medium / low / info
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
}

// PrivescProbe 一条原始采集（便于人工复核与 Agent 二次推理）。
type PrivescProbe struct {
	Cmd    string `json:"cmd"`
	Output string `json:"output"`
	Err    string `json:"err,omitempty"`
}

// PrivescReport 提权面分析结果。
type PrivescReport struct {
	OS       string           `json:"os"` // linux / windows / unknown
	User     string           `json:"user"`
	Host     string           `json:"host"`
	Summary  string           `json:"summary"`
	Findings []PrivescFinding `json:"findings"`
	Probes   []PrivescProbe   `json:"probes"`
	// 便于 Agent 直接读的纯文本视图
	Text string `json:"text"`
}

// 单条命令输出上限：某些 find 会吐几万行，留着只会把上下文撑爆。
const privescMaxOut = 6000

// RunPrivesc 采集并分析提权面。c 必须是可用的目标连接。
func RunPrivesc(c *Client) (*PrivescReport, error) {
	rep := &PrivescReport{}
	probe := func(cmd string) string {
		res, err := c.ExecCmd(cmd)
		p := PrivescProbe{Cmd: cmd}
		if err != nil {
			p.Err = err.Error()
			rep.Probes = append(rep.Probes, p)
			return ""
		}
		if !res.OK {
			p.Err = res.Error
			p.Output = truncate(privescMaxOut, res.Output)
			rep.Probes = append(rep.Probes, p)
			return res.Output
		}
		p.Output = truncate(privescMaxOut, res.Output)
		rep.Probes = append(rep.Probes, p)
		return res.Output
	}

	// 先判平台：uname 在 Windows 上不存在，回落到 ver
	osOut := strings.ToLower(probe("uname -s 2>/dev/null || ver"))
	switch {
	case strings.Contains(osOut, "linux"):
		rep.OS = "linux"
	case strings.Contains(osOut, "windows") || strings.Contains(osOut, "microsoft"):
		rep.OS = "windows"
	default:
		rep.OS = "unknown"
	}

	switch rep.OS {
	case "linux":
		analyzeLinux(rep, probe)
	case "windows":
		analyzeWindows(rep, probe)
	default:
		// 未知平台仍给出基础身份信息，避免完全空手
		rep.User = firstLine(probe("id 2>/dev/null || whoami"))
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "unknown-os", Title: "未能识别目标操作系统", Risk: "info",
			Detail: "uname 与 ver 均无有效输出，提权面分析未展开。",
		})
	}

	sortFindings(rep.Findings)
	rep.Summary = summarize(rep.Findings)
	rep.Text = renderText(rep)
	return rep, nil
}

func analyzeLinux(rep *PrivescReport, probe func(string) string) {
	idOut := probe("id 2>/dev/null")
	rep.User = firstLine(idOut)
	if h := firstLine(probe("hostname 2>/dev/null")); h != "" {
		rep.Host = h
	}

	if strings.Contains(idOut, "uid=0(") {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "already-root", Title: "当前已是 root", Risk: "info",
			Detail:   "进程以 uid=0 运行，无需提权；后续应考虑留驻与横向。",
			Evidence: rep.User,
		})
	} else {
		// 非 root 才继续找提权路径，否则后面的判定没有意义
		groups := idOut
		if strings.Contains(groups, "docker") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "docker-group", Title: "当前用户在 docker 组", Risk: "critical",
				Detail:   "docker 组成员可挂载宿主根目录启动容器，等价于 root。",
				Evidence: rep.User,
			})
		}

		sudo := probe("sudo -n -l 2>&1")
		if strings.Contains(sudo, "NOPASSWD") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "sudo-nopasswd", Title: "sudo 免密可执行", Risk: "critical",
				Detail:   "存在 NOPASSWD 规则，可直接以 root 执行被授权的命令；若授权范围含 shell 解释器即完全提权。",
				Evidence: truncate(1200, sudo),
			})
		} else if strings.Contains(sudo, "(ALL") || strings.Contains(sudo, "(root") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "sudo-allowed", Title: "sudo 有可用授权（需密码）", Risk: "medium",
				Detail:   "sudo -l 列出了可执行范围；若拿到当前用户密码即可利用。",
				Evidence: truncate(1200, sudo),
			})
		}

		if w := probe("test -w /etc/passwd && echo WRITABLE || echo -"); strings.Contains(w, "WRITABLE") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "passwd-writable", Title: "/etc/passwd 可写", Risk: "critical",
				Detail:   "可直接写入 uid=0 的新账户（或改现有账户 shell）后 su 提权。",
				Evidence: "/etc/passwd writable",
			})
		}
		if w := probe("test -w /etc/shadow && echo WRITABLE || echo -"); strings.Contains(w, "WRITABLE") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "shadow-writable", Title: "/etc/shadow 可写", Risk: "critical",
				Detail:   "可替换 root 口令哈希，随后 su 提权。",
				Evidence: "/etc/shadow writable",
			})
		} else if r := probe("test -r /etc/shadow && echo READABLE || echo -"); strings.Contains(r, "READABLE") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "shadow-readable", Title: "/etc/shadow 可读", Risk: "high",
				Detail:   "可离线爆破 root 口令哈希。",
				Evidence: "/etc/shadow readable",
			})
		}

		// SUID：命中常见 GTFOBins 才有意义，全量列出交给人工
		suid := probe("find / -xdev -perm -4000 -type f 2>/dev/null | head -60")
		hits := matchGTFOBins(suid)
		if len(hits) > 0 {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "suid-gtfobins", Title: "存在可滥用的 SUID 程序", Risk: "high",
				Detail:   "这些 SUID 程序在 GTFOBins 有已知提权用法（视版本而定），优先尝试。",
				Evidence: strings.Join(hits, ", "),
			})
		} else if len(strings.Split(strings.TrimSpace(suid), "\n")) > 1 {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "suid-list", Title: "存在 SUID 程序（未见常见滥用项）", Risk: "low",
				Detail:   "已列出 SUID 文件，需按版本逐个核对 GTFOBins。",
				Evidence: truncate(1200, suid),
			})
		}

		pathW := probe(`for d in $(echo "$PATH" | tr ':' ' '); do [ -n "$d" ] && [ -w "$d" ] && echo "$d"; done`)
		if strings.TrimSpace(pathW) != "" && !strings.Contains(pathW, "ERROR") {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "path-writable", Title: "PATH 中存在可写目录", Risk: "high",
				Detail:   "可在可写目录放同名程序劫持 root 定时任务/脚本调用的命令。",
				Evidence: truncate(800, pathW),
			})
		}

		cron := probe("ls -ld /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null; crontab -l 2>/dev/null | head -20")
		if cw := writableCron(cron); cw != "" {
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: "cron-writable", Title: "定时任务目录可写", Risk: "high",
				Detail:   "可在该目录投放 root 执行的定时任务。",
				Evidence: cw,
			})
		}
	}

	if s := probe("ls -l /var/run/docker.sock 2>/dev/null"); strings.Contains(s, "docker.sock") {
		risk := "medium"
		if strings.Contains(s, "rw-rw-rw") || strings.Contains(s, "rw-rw----") {
			risk = "high"
		}
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "docker-sock", Title: "存在 docker.sock", Risk: risk,
			Detail:   "只要能写 socket 就能起特权容器挂载宿主根目录。",
			Evidence: strings.TrimSpace(s),
		})
	}

	if caps := probe("getcap -r / 2>/dev/null | head -20"); strings.Contains(caps, "cap_setuid") || strings.Contains(caps, "cap_sys_admin") {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "file-caps", Title: "发现高权限 file capabilities", Risk: "high",
			Detail:   "cap_setuid/cap_sys_admin 可绕过 SUID 限制直接提权。",
			Evidence: truncate(1000, caps),
		})
	}

	rep.Findings = append(rep.Findings, PrivescFinding{
		ID: "kernel", Title: "内核版本（供本地提权 exp 匹配）", Risk: "info",
		Detail:   "版本本身不是漏洞，需按发行版补丁级核对可用 exp。",
		Evidence: firstLine(probe("uname -r 2>/dev/null")),
	})
}

func analyzeWindows(rep *PrivescReport, probe func(string) string) {
	rep.User = firstLine(probe("whoami 2>nul"))
	if h := firstLine(probe("hostname 2>nul")); h != "" {
		rep.Host = h
	}

	low := strings.ToLower(rep.User)
	if strings.Contains(low, "system") || strings.Contains(low, "nt authority\\system") {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "already-system", Title: "当前已是 SYSTEM", Risk: "info",
			Detail:   "进程以 SYSTEM 运行，无需提权。",
			Evidence: rep.User,
		})
		return
	}

	// 逐行判断：整段输出里出现 Enabled 不代表某条权限已启用
	// （SeAssignPrimaryTokenPrivilege 常见为 Disabled，误判会让人白跑一趟 Potato）
	priv := probe("whoami /priv 2>nul")
	enabled := map[string]bool{}
	for _, line := range strings.Split(priv, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(strings.ToLower(line), "enabled") &&
			!strings.Contains(strings.ToLower(line), "enabled") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			enabled[fields[0]] = true
		}
	}
	// 这组令牌权限是 Potato 家族的前提，命中就要优先考虑
	for _, p := range []struct{ name, desc string }{
		{"SeImpersonatePrivilege", "可模拟令牌 → Potato 家族（Juicy/Rogue/PrintSpoofer）"},
		{"SeAssignPrimaryTokenPrivilege", "可替换进程令牌 → Potato 家族"},
		{"SeBackupPrivilege", "可备份任意文件 → 读取 SAM/SYSTEM 离线取哈希"},
		{"SeRestorePrivilege", "可还原任意文件 → 覆盖系统文件"},
		{"SeTakeOwnershipPrivilege", "可夺取文件所有权 → 替换服务二进制"},
		{"SeDebugPrivilege", "可调试任意进程 → 注入 SYSTEM 进程"},
		{"SeLoadDriverPrivilege", "可加载驱动 → 内核态提权"},
	} {
		if enabled[p.name] {
			risk := "high"
			if p.name == "SeImpersonatePrivilege" || p.name == "SeAssignPrimaryTokenPrivilege" {
				risk = "critical"
			}
			rep.Findings = append(rep.Findings, PrivescFinding{
				ID: strings.ToLower(p.name), Title: p.name, Risk: risk,
				Detail: p.desc, Evidence: p.name,
			})
		}
	}

	if g := probe("whoami /groups 2>nul"); strings.Contains(strings.ToLower(g), "administrators") {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "local-admin", Title: "当前账号在本地管理员组", Risk: "high",
			Detail:   "若 UAC 未限制，可直接提权到高完整性；配合令牌权限更稳。",
			Evidence: "Administrators",
		})
	}

	// AlwaysInstallElevated：两个注册表位置都为 1 时，任意用户可用 msi 以 SYSTEM 执行
	aie1 := probe(`reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul`)
	aie2 := probe(`reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul`)
	if strings.Contains(aie1, "0x1") && strings.Contains(aie2, "0x1") {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "always-install-elevated", Title: "AlwaysInstallElevated 已开启", Risk: "critical",
			Detail:   "任意用户安装 msi 即以 SYSTEM 权限执行，可直接生成管理员账号。",
			Evidence: "HKLM+HKCU AlwaysInstallElevated=1",
		})
	}

	// 未加引号的服务路径：路径含空格且未引号 → 可劫持中间目录里的同名 exe
	svc := probe(`wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "Auto"`)
	if bad := unquotedServicePaths(svc); len(bad) > 0 {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "unquoted-service", Title: "服务路径未加引号", Risk: "high",
			Detail:   "路径含空格且未加引号，可在中间目录投放同名 exe 被服务以高权限加载（需目录可写）。",
			Evidence: strings.Join(bad, "\n"),
		})
	}

	if qfe := probe(`wmic qfe get HotFixID 2>nul`); strings.Count(qfe, "KB") > 0 {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "patches", Title: "补丁情况（供 exp 匹配）", Risk: "info",
			Detail:   fmt.Sprintf("已安装补丁条目约 %d 条，需按缺失的热修补丁判断可用本地提权 exp。", strings.Count(qfe, "KB")),
			Evidence: truncate(600, qfe),
		})
	} else {
		rep.Findings = append(rep.Findings, PrivescFinding{
			ID: "patches", Title: "无法枚举补丁（wmic 可能被移除）", Risk: "info",
			Detail: "Win10 21H1+ 常移除 wmic，可改用 PowerShell Get-HotFix。",
		})
	}
}

// ---------- 解析辅助 ----------

var gtfobins = []string{
	"nmap", "find", "vim", "vi", "less", "more", "bash", "sh", "dash", "zsh",
	"python", "python3", "perl", "ruby", "lua", "php", "node", "awk", "gawk",
	"tar", "cp", "mv", "install", "env", "systemctl", "journalctl", "mount",
	"umount", "docker", "pkexec", "xxd", "ed", "nano", "ftp", "strace", "gdb",
}

// matchGTFOBins 从 SUID 列表里挑出有已知滥用的程序名。
func matchGTFOBins(suidOut string) []string {
	seen := map[string]bool{}
	var hits []string
	for _, line := range strings.Split(suidOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "/") {
			continue
		}
		base := line
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		for _, g := range gtfobins {
			if base == g && !seen[base] {
				seen[base] = true
				hits = append(hits, line)
			}
		}
	}
	sort.Strings(hits)
	return hits
}

// writableCron 从 ls -ld 结果里挑出组/其他人可写的定时任务目录。
func writableCron(out string) string {
	var hits []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "d") || len(line) < 10 {
			continue
		}
		perm := line[:10]
		// 组或其他人的 w 位（第 6、9 个字符）
		if perm[5] == 'w' || perm[8] == 'w' {
			hits = append(hits, line)
		}
	}
	return strings.Join(hits, "\n")
}

var reWinExe = regexp.MustCompile(`(?i)[a-z]:\\[^"|]*?\.exe`)

// unquotedServicePaths 找「路径含空格且未加引号」的服务。
// 不从行首按列切分：wmic 的列宽随内容浮动，displayname 本身可能含空格，
// 按可执行文件路径反查更稳。
func unquotedServicePaths(out string) []string {
	var bad []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "name") {
			continue
		}
		// 已加引号的跳过
		if strings.Contains(line, `"`) {
			continue
		}
		p := reWinExe.FindString(line)
		if p == "" {
			continue
		}
		if strings.Contains(p, " ") {
			bad = append(bad, line)
		}
	}
	return bad
}

func sortFindings(fs []PrivescFinding) {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, ok := rank[fs[i].Risk]
		if !ok {
			ri = 9
		}
		rj, ok := rank[fs[j].Risk]
		if !ok {
			rj = 9
		}
		return ri < rj
	})
}

func summarize(fs []PrivescFinding) string {
	n := map[string]int{}
	for _, f := range fs {
		n[f.Risk]++
	}
	if len(fs) == 0 {
		return "未发现明显提权面"
	}
	var parts []string
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		if n[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, n[k]))
		}
	}
	return strings.Join(parts, " / ")
}

func renderText(rep *PrivescReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "提权面分析：%s  user=%s  host=%s\n", rep.OS, rep.User, rep.Host)
	fmt.Fprintf(&b, "结论：%s\n", rep.Summary)
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "\n[%s] %s\n  %s\n", strings.ToUpper(f.Risk), f.Title, f.Detail)
		if f.Evidence != "" {
			for _, l := range strings.Split(truncate(600, f.Evidence), "\n") {
				fmt.Fprintf(&b, "  > %s\n", l)
			}
		}
	}
	return b.String()
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

func truncate(n int, s string) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…（已截断）"
}
