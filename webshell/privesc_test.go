package webshell

// privesc_test.go — 提权面分析的解析逻辑与端到端采集。
//
// 解析函数单独测（纯函数，样本来自真实命令输出），RunPrivesc 再用一个假目标
// 走完整链路：假目标按「请求体里的 base64 命令」查表返回输出，因此不依赖命令
// 执行顺序——将来调整采集顺序不会把测试打红。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatchGTFOBins(t *testing.T) {
	out := strings.Join([]string{
		"/usr/bin/passwd",
		"/usr/bin/sudo",
		"/usr/bin/find",
		"/usr/bin/vim.basic",
		"/usr/local/bin/docker",
		"/bin/mount",
		"",
	}, "\n")
	got := matchGTFOBins(out)
	want := []string{"/bin/mount", "/usr/bin/find", "/usr/local/bin/docker"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("命中项不符: %v", got)
	}
	// vim.basic 是变体名，不该被当成 vim 命中（避免误报）
	for _, g := range got {
		if strings.Contains(g, "vim") {
			t.Fatalf("变体名不应命中: %s", g)
		}
	}
}

func TestWritableCron(t *testing.T) {
	out := "drwxr-xr-x 2 root root 4096 /etc/cron.d\n" +
		"drwxrwxrwt 2 root root 4096 /etc/cron.daily\n" +
		"drwx------ 2 root root 4096 /etc/cron.hourly"
	got := writableCron(out)
	if !strings.Contains(got, "/etc/cron.daily") {
		t.Fatalf("应识别组/其他人可写目录: %q", got)
	}
	if strings.Contains(got, "/etc/cron.d\n") || strings.HasSuffix(got, "/etc/cron.d") {
		t.Fatalf("不该把常规权限目录算作可写: %q", got)
	}
}

func TestUnquotedServicePaths(t *testing.T) {
	out := strings.Join([]string{
		`Name        DisplayName   PathName                                      StartMode`,
		`Svc1        Some Service  C:\Program Files\Vendor App\agent.exe           Auto`,
		`Svc2        Quoted        "C:\Program Files\Q\q.exe"                     Auto`,
		`Svc3        NoSpace       C:\Windows\system32\svc.exe                    Auto`,
	}, "\n")
	got := unquotedServicePaths(out)
	if len(got) != 1 || !strings.Contains(got[0], "Vendor App") {
		t.Fatalf("应只命中未加引号且路径含空格的项: %v", got)
	}
}

// fakeShell 按请求体里出现的 base64 命令查表返回输出，模拟一台 Linux 目标。
func fakeShell(t *testing.T, table map[string]string) *httptest.Server {
	t.Helper()
	// 预先把命令转成 base64，命中时比对
	enc := map[string]string{}
	for cmd, out := range table {
		enc[base64.StdEncoding.EncodeToString([]byte(cmd))] = out
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		// raw 编码器会把整个 payload 再 base64 一次，命令的 base64 就不再是
		// 请求体的子串了，所以先解一层再查表。
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body)); err == nil {
			body = string(dec)
		}
		for b, out := range enc {
			if strings.Contains(body, b) {
				// 真实载荷在回显末尾追加 CWD/END 标记，这里保持一致：
				// 少了标记，"READABLE" / "/tmp" 这类恰好是合法 base64 的输出
				// 会被 raw 编码器的兜底解密还原成二进制乱码。
				fmt.Fprintf(w, "%s\n%s/\n%s", out, CWDMarker, EndMarker)
				return
			}
		}
		fmt.Fprintf(w, "\n%s/\n%s", CWDMarker, EndMarker)
	}))
}

func TestRunPrivescLinux(t *testing.T) {
	table := map[string]string{
		"uname -s 2>/dev/null || ver":                             "Linux",
		"id 2>/dev/null":                                          "uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)",
		"hostname 2>/dev/null":                                    "web01",
		"sudo -n -l 2>&1":                                         "Matching Defaults entries:\n    env_reset\n\nUser www-data may run the following commands:\n    (root) NOPASSWD: /usr/bin/vim",
		"test -w /etc/passwd && echo WRITABLE || echo -":          "-",
		"test -w /etc/shadow && echo WRITABLE || echo -":          "-",
		"test -r /etc/shadow && echo READABLE || echo -":          "READABLE",
		"find / -xdev -perm -4000 -type f 2>/dev/null | head -60": "/usr/bin/sudo\n/usr/bin/find\n/usr/bin/passwd",
		`for d in $(echo "$PATH" | tr ':' ' '); do [ -n "$d" ] && [ -w "$d" ] && echo "$d"; done`:            "/tmp",
		"ls -ld /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null; crontab -l 2>/dev/null | head -20": "drwxrwxr-x 2 root root 4096 /etc/cron.d\nno crontab for www-data",
		"ls -l /var/run/docker.sock 2>/dev/null":                                                             "srw-rw---- 1 root docker 0 Nov 12 09:00 /var/run/docker.sock",
		"getcap -r / 2>/dev/null | head -20":                                                                 "/usr/bin/python3 cap_setuid+ep",
		"uname -r 2>/dev/null":                                                                               "5.15.0-91-generic",
	}
	srv := fakeShell(t, table)
	defer srv.Close()

	c := &Client{URL: srv.URL, Encoder: "raw", ScriptType: "php", Password: "x"}
	rep, err := RunPrivesc(c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OS != "linux" {
		t.Fatalf("平台判定错误: %s", rep.OS)
	}
	if !strings.Contains(rep.User, "uid=1000") {
		t.Fatalf("用户信息未采集: %q", rep.User)
	}

	ids := map[string]string{}
	for _, f := range rep.Findings {
		ids[f.ID] = f.Risk
	}
	for _, want := range []string{"sudo-nopasswd", "shadow-readable", "suid-gtfobins", "path-writable", "docker-sock", "file-caps", "kernel"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("缺少线索 %s（实际 %v）", want, ids)
		}
	}
	if ids["sudo-nopasswd"] != "critical" {
		t.Errorf("sudo 免密应判 critical，实际 %s", ids["sudo-nopasswd"])
	}
	// 排序：critical 必须排在 info 之前
	if len(rep.Findings) > 1 && rep.Findings[0].Risk != "critical" {
		t.Errorf("排序异常，首条不是 critical: %s", rep.Findings[0].Risk)
	}
	if !strings.Contains(rep.Text, "提权面分析：linux") {
		t.Errorf("文本视图缺失: %s", rep.Text)
	}
	// JSON 可序列化（API 直接返回它）
	if _, err := json.Marshal(rep); err != nil {
		t.Fatalf("报告无法序列化: %v", err)
	}
}

func TestRunPrivescAlreadyRoot(t *testing.T) {
	srv := fakeShell(t, map[string]string{
		"uname -s 2>/dev/null || ver": "Linux",
		"id 2>/dev/null":              "uid=0(root) gid=0(root) groups=0(root)",
		"hostname 2>/dev/null":        "dc01",
		"uname -r 2>/dev/null":        "5.15.0",
	})
	defer srv.Close()
	c := &Client{URL: srv.URL, Encoder: "raw", ScriptType: "php", Password: "x"}
	rep, err := RunPrivesc(c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.ID == "already-root" {
			found = true
		}
		// 已是 root 就不该再去跑 sudo/SUID 这类判断
		if f.ID == "sudo-nopasswd" || f.ID == "suid-gtfobins" {
			t.Errorf("root 下不该继续判定 %s", f.ID)
		}
	}
	if !found {
		t.Fatal("root 目标应给出 already-root 结论")
	}
}

func TestRunPrivescWindows(t *testing.T) {
	table := map[string]string{
		"uname -s 2>/dev/null || ver": "Microsoft Windows [Version 10.0.19045.3803]",
		"whoami 2>nul":                "iis apppool\\defaultapppool",
		"hostname 2>nul":              "WEB-PROD",
		"whoami /priv 2>nul": `PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeAssignPrimaryTokenPrivilege Replace a process level token            Disabled
SeShutdownPrivilege           Shut down the system                     Disabled`,
		"whoami /groups 2>nul": "BUILTIN\\Users  Alias  S-1-5-32-545  Mandatory group, Enabled by default, Enabled group",
		`reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul`: "    AlwaysInstallElevated    REG_DWORD    0x1",
		`reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul`: "    AlwaysInstallElevated    REG_DWORD    0x0",
		`wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "Auto"`:                "Svc  App  C:\\Program Files\\App\\svc.exe  Auto",
		`wmic qfe get HotFixID 2>nul`: "HotFixID\nKB5034441\nKB5034123",
	}
	srv := fakeShell(t, table)
	defer srv.Close()
	c := &Client{URL: srv.URL, Encoder: "raw", ScriptType: "php", Password: "x"}
	rep, err := RunPrivesc(c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OS != "windows" {
		t.Fatalf("平台判定错误: %s", rep.OS)
	}
	ids := map[string]string{}
	for _, f := range rep.Findings {
		ids[f.ID] = f.Risk
	}
	if ids["seimpersonateprivilege"] != "critical" {
		t.Errorf("SeImpersonate 应判 critical，实际 %q（%v）", ids["seimpersonateprivilege"], ids)
	}
	// Disabled 的权限不该算数
	if _, ok := ids["seassignprimarytokenprivilege"]; ok {
		t.Error("Disabled 的令牌权限不该产生线索")
	}
	if _, ok := ids["unquoted-service"]; !ok {
		t.Errorf("未识别未加引号服务路径: %v", ids)
	}
	// 只在 HKCU 为 1 时才成立，这里是 0x0，不该误报
	if _, ok := ids["always-install-elevated"]; ok {
		t.Error("AlwaysInstallElevated 单边开启不该判为可利用")
	}
	if _, ok := ids["patches"]; !ok {
		t.Errorf("缺少补丁信息线索: %v", ids)
	}
}
