package agent

import (
	"strings"
	"testing"
)

// poc_packet_test.go — POC 请求包归一化/校验回归：模型常见的坏输入形态
// （curl / 裸 URL / 缺版本 / 缺空行 / 描述文字）都必须被救回或明确拒绝。

func TestNormalizeCurlToRaw(t *testing.T) {
	got := NormalizePocPacket(`curl -X POST 'http://127.0.0.1:18992/api/login' -H 'Content-Type: application/json' -d '{"user":"admin","pass":"123"}'`)
	want := "POST /api/login HTTP/1.1\nHost: 127.0.0.1:18992\nContent-Type: application/json\n\n{\"user\":\"admin\",\"pass\":\"123\"}\n"
	if got != want {
		t.Fatalf("curl 转换失败:\n got: %q\nwant: %q", got, want)
	}
}

func TestNormalizeBareURL(t *testing.T) {
	got := NormalizePocPacket("http://target.com/a/b?x=1")
	want := "GET /a/b?x=1 HTTP/1.1\nHost: target.com\n"
	if got != want {
		t.Fatalf("裸 URL 转换失败:\n got: %q\nwant: %q", got, want)
	}
}

func TestNormalizeMissingBlankLine(t *testing.T) {
	got := NormalizePocPacket("POST /x HTTP/1.1\nHost: a.com\nContent-Type: application/x-www-form-urlencoded\nuser=admin&pass=1")
	if validatePocPacket(got) != "" || got == "" {
		t.Fatalf("缺空行应被自动补齐并校验通过: %q", got)
	}
	// 头体之间必须有空行（Repeater 直粘要求）
	if !containsBlankLine(got) {
		t.Fatalf("归一化后头体间仍无空行: %q", got)
	}
}

func TestValidateRejectsProse(t *testing.T) {
	if msg := validatePocPacket("该接口存在 SQL 注入，参数 orderId 未过滤"); msg == "" {
		t.Fatal("描述文字必须被拒绝（返回格式说明）")
	}
	if msg := validatePocPacket(""); msg != "" {
		t.Fatal("空 packet（非 HTTP 漏洞省略）必须放行")
	}
}

func TestValidateGoodPacketPasses(t *testing.T) {
	pkt := "GET /api/order/detail?orderId=1%27 HTTP/1.1\nHost: 127.0.0.1:18992\n"
	if msg := validatePocPacket(pkt); msg != "" {
		t.Fatalf("标准 GET 包应通过: %s", msg)
	}
	pkt2 := "POST /api/order/cancel HTTP/1.1\nHost: 127.0.0.1:18992\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 9\n\norderId=1"
	if msg := validatePocPacket(pkt2); msg != "" {
		t.Fatalf("标准 POST 包应通过: %s", msg)
	}
}

func containsBlankLine(s string) bool {
	lines := pocSplitLines(s)
	for i := 1; i < len(lines); i++ { // 跳过请求行
		if lines[i] == "" {
			return true
		}
	}
	return false
}

func pocSplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func TestExtractFromEvidence(t *testing.T) {
	ev := "验证命令（Repeater 原始报文重放）：\n```\nGET /?cmd=id HTTP/1.1\nHost: 127.0.0.1:18992\nUser-Agent: curl/8.5.0\n\n```\n回显 uid=0(root)。"
	got := ExtractPacketFromEvidence(ev)
	if got == "" || !strings.Contains(got, "GET /?cmd=id HTTP/1.1") || !strings.Contains(got, "Host: 127.0.0.1:18992") {
		t.Fatalf("evidence 提取失败: %q", got)
	}
	// 无包文本应返回空
	if ExtractPacketFromEvidence("接口存在注入，建议修复") != "" {
		t.Fatal("无原始包的 evidence 不应提取出内容")
	}
}
