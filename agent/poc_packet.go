package agent

// poc_packet.go — POC 请求包校验与归一化：
//   report_finding 的 packet 字段必须是完整原始 HTTP 请求包（可直接粘进
//   Repeater 重放）。模型常犯的错：给 curl 命令、给裸 URL、给描述文字、
//   头和体之间没空行。这里宽容归一化（补 HTTP 版本/Host 空行/去掉 curl
//   前缀），无法救的返回明确格式说明让模型自纠——绝不能让半成品包入库
//   让用户再手调。

import (
	"fmt"
	"net/url"
	"strings"
)

// httpMethods 校验首行用。
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	"HEAD": true, "OPTIONS": true,
}

// NormalizePocPacket 归一化 POC 请求包：
//  1. curl 命令 → 原始包（-X 方法 / -H 头 / -d 体 / URL 解析）；
//  2. 裸 URL（http://host/path）→ GET 包；
//  3. 首行缺 HTTP 版本 → 补 " HTTP/1.1"；
//  4. 有请求体但头体间无空行 → 补空行；
//  5. 无 Host 头且能从首行/URL 推出 → 补 Host。
//
// 返回归一化后的包；不是 HTTP 形态返回原样（由调用方决定是否拒绝）。
func NormalizePocPacket(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// ① curl 命令
	if strings.HasPrefix(s, "curl ") {
		if conv := curlToRawPacket(s); conv != "" {
			return conv
		}
		return s
	}
	// ② 裸 URL
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if u, err := url.Parse(strings.Fields(s)[0]); err == nil && u.Host != "" {
			path := u.Path
			if path == "" {
				path = "/"
			}
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
			return fmt.Sprintf("GET %s HTTP/1.1\nHost: %s\n", path, u.Host)
		}
	}
	// ③ 首行补版本
	lines := strings.Split(s, "\n")
	first := strings.TrimSpace(lines[0])
	if _, _, ok := splitRequestLine(first); ok && !strings.Contains(first, "HTTP/") {
		lines[0] = first + " HTTP/1.1"
		s = strings.Join(lines, "\n")
		lines = strings.Split(s, "\n")
	}
	// ④ 头体间空行：找最后一个像头的行（xxx: yyy），其后若直接是非空非头内容则插空行
	sep := findHeaderBodySplit(lines)
	if sep >= 0 && sep < len(lines) {
		// 已有空行则不动；否则在头块后插
		hasBlank := false
		for _, l := range lines[sep:] {
			if strings.TrimSpace(l) == "" {
				hasBlank = true
				break
			}
		}
		if !hasBlank {
			out := append([]string{}, lines[:sep]...)
			out = append(out, "", strings.TrimSpace(strings.Join(lines[sep:], "\n")))
			s = strings.Join(out, "\n")
		}
	}
	// ⑤ Host 头
	if !hasHostLine(s) {
		if host := guessHost(s); host != "" {
			parts := strings.SplitN(s, "\n", 2)
			if len(parts) == 2 {
				s = parts[0] + "\nHost: " + host + "\n" + parts[1]
			} else {
				s = parts[0] + "\nHost: " + host + "\n"
			}
		}
	}
	return strings.TrimRight(s, "\n") + "\n"
}

// ValidatePocPacketFor 报告前的校验：空返回 ""（合法或非 HTTP 漏洞省略）；
// 内容不像原始包返回格式说明（模型据此重发）。
func validatePocPacket(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "" // 非 HTTP 漏洞允许省略
	}
	norm := NormalizePocPacket(s)
	first := strings.TrimSpace(strings.SplitN(norm, "\n", 2)[0])
	method, _, ok := splitRequestLine(first)
	if !ok || !httpMethods[method] {
		return "packet 格式不对：必须是完整原始 HTTP 请求包，首行形如 'GET /path HTTP/1.1' 或 'POST /path HTTP/1.1'，随后是 Host 等请求头，空一行后接请求体。不要给 curl 命令、裸 URL 或描述文字（这些我会自动转换，但你的包必须本身完整）。示例：\nPOST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nuser=admin&pass=123456"
	}
	if !hasHostLine(norm) {
		return "packet 缺 Host 头：第二行必须是 'Host: 目标主机'，否则无法直接重放。请补全后重发 report_finding。"
	}
	return ""
}

// ---- 归一化辅助 ----

func splitRequestLine(line string) (method, path string, ok bool) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return "", "", false
	}
	m := strings.ToUpper(f[0])
	if !httpMethods[m] {
		return "", "", false
	}
	return m, f[1], true
}

func hasHostLine(s string) bool {
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(t), "host:") {
			return true
		}
	}
	return false
}

// guessHost 从请求行路径（//host/path 形态）或包内 URL 推 Host。
func guessHost(s string) string {
	first := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	f := strings.Fields(first)
	if len(f) >= 2 {
		p := f[1]
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			if u, err := url.Parse(p); err == nil {
				return u.Host
			}
		}
	}
	// 绝对 URI 形态（代理请求）：GET http://host/path HTTP/1.1
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if u, err := url.Parse(t); err == nil && u.Host != "" && (strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://")) {
			return u.Host
		}
	}
	return ""
}

// findHeaderBodySplit 找头块结束行号（其后是 body）：从上往下最后一个 "k: v" 行的下一行。
func findHeaderBodySplit(lines []string) int {
	lastHeader := -1
	for i, l := range lines[1:] {
		t := strings.TrimSpace(l)
		if t == "" {
			break // 已有空行
		}
		if strings.Contains(t, ":") && !strings.HasPrefix(t, "\"") {
			lastHeader = i + 1
		} else if lastHeader >= 0 {
			// 头块后第一个非头行 = body 起点
			return i + 1
		}
	}
	return -1
}

// curlToRawPacket 把 curl 命令转原始包（常见形态；转不动返回 ""）。
func curlToRawPacket(s string) string {
	method := "GET"
	var headers []string
	var body string
	var rawURL string
	fields := splitShellFields(s)
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "-X" && i+1 < len(fields):
			method = strings.ToUpper(fields[i+1])
			i++
		case f == "-H" && i+1 < len(fields):
			headers = append(headers, fields[i+1])
			i++
		case (f == "-d" || f == "--data" || f == "--data-raw" || f == "--data-binary") && i+1 < len(fields):
			body = fields[i+1]
			if method == "GET" {
				method = "POST"
			}
			i++
		case strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://"):
			rawURL = strings.Trim(f, "'\"")
		}
	}
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\nHost: %s\n", method, path, u.Host)
	hasCT := false
	for _, h := range headers {
		b.WriteString(h + "\n")
		if strings.HasPrefix(strings.ToLower(h), "content-type:") {
			hasCT = true
		}
	}
	if body != "" {
		if !hasCT {
			b.WriteString("Content-Type: application/x-www-form-urlencoded\n")
		}
		b.WriteString("\n" + body + "\n")
	}
	return b.String()
}

// splitShellFields 简易 shell 分词（单/双引号）。
func splitShellFields(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t' || c == '\n':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ExtractPacketFromEvidence 从 evidence 文本里提取 POC 请求包（report_finding
// 的兜底层）：模型有时把完整原始包写进 evidence 而没传 packet 字段——用户
// 要的是"拿到就能重放"，所以这里宽容提取：
//  1. 优先找 ``` 围栏代码块中形如原始包的内容；
//  2. 否则找首个 "METHOD /path HTTP/1.x" 行到包尾（空行+体或下一个标题行前）。
//
// 返回 "" 表示 evidence 里没有可提取的原始包。
func ExtractPacketFromEvidence(evidence string) string {
	if evidence == "" {
		return ""
	}
	// ① 围栏代码块
	var fenceBest string
	inFence := false
	var buf []string
	for _, line := range strings.Split(evidence, "\n") {
		if strings.TrimSpace(line) == "```" {
			if inFence {
				cand := strings.Join(buf, "\n")
				if n := NormalizePocPacket(cand); validatePocPacket(n) == "" && looksRawHTTP(n) {
					if len(n) > len(fenceBest) {
						fenceBest = n
					}
				}
				inFence = false
				buf = nil
				continue
			}
			inFence = true
			buf = nil
			continue
		}
		if inFence {
			buf = append(buf, line)
		}
	}
	if fenceBest != "" {
		return fenceBest
	}
	// ② 找原始包起点行（GET/POST/... /path HTTP/1.x）
	lines := strings.Split(evidence, "\n")
	start := -1
	for i, l := range lines {
		if isRawRequestLine(l) {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	// 收集到包尾：连续的请求行+头行+空行+体行，遇到空行后的"标题式"行（=== /【】/#）或第二个请求行即止
	var out []string
	blank := false
	for i := start; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			if !blank {
				out = append(out, "")
				blank = true
				continue
			}
			break // 连续第二个空行 = 包结束
		}
		if blank && isHeadingLine(l) {
			break
		}
		if !blank && i > start && isRawRequestLine(l) {
			break // 第二个请求行 = 新段落
		}
		out = append(out, l)
	}
	cand := strings.Join(out, "\n")
	if n := NormalizePocPacket(cand); validatePocPacket(n) == "" && looksRawHTTP(n) {
		return n
	}
	return ""
}

// isRawRequestLine 匹配 "GET /path HTTP/1.1" 形态（行首，无前缀文字）。
func isRawRequestLine(l string) bool {
	t := strings.TrimLeft(l, " 	")
	f := strings.Fields(t)
	if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/") {
		return false
	}
	return httpMethods[strings.ToUpper(f[0])]
}

// isHeadingLine 标题/分隔线形态（说明文字，不是包体）。
func isHeadingLine(l string) bool {
	t := strings.TrimSpace(l)
	return strings.HasPrefix(t, "===") || strings.HasPrefix(t, "---") ||
		strings.HasPrefix(t, "【") || strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "**") || strings.HasPrefix(t, "（")
}

// looksRawHTTP 归一化后仍是标准请求行才认为提取成功。
func looksRawHTTP(s string) bool {
	first := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	_, _, ok := splitRequestLine(first)
	return ok && hasHostLine(s)
}
