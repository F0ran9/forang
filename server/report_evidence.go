package server

// report_evidence.go — 报告期的证据/POC 数据整形（渗透版增强）。
// 解决三类实际观察到的问题（2026-11-20 任务3 报告实测）：
//  1. evidence 存的是结构化 JSON 原文（{"by":"work#2","poc":"..."}），
//     直接排进报告是一坨带转义的字符串——解包取 poc 字段输出可读文本。
//  2. packet 是"多个请求 + 中文注释行"拼在一起（----（随后…）----），
//     粘进 Burp/Yakit 无法重放——拆成独立请求块，每块单独成段，剔除注释行。
//  3. 部分 finding 的 packet 为空（worker 只在 evidence 里写了 curl 命令）——
//     从 evidence 文本中提取 curl 命令，转换为可重放的原始 HTTP 请求包。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// cleanFindingEvidence 把 evidence 字段转为可读文本。
// 结构化 JSON（{"by":..,"poc":..}）→ 只取 poc；纯文本原样返回。
// 输出做排版增强（附录可读性）：
//   - 「N) 步骤」行前加空行分组
//   - 「 → 输出」拆行缩进（命令与响应分离，方便逐条复制）
func cleanFindingEvidence(ev string) string {
	s := strings.TrimSpace(ev)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(s), &obj); err == nil {
			if poc, ok := obj["poc"].(string); ok && strings.TrimSpace(poc) != "" {
				s = poc
			}
		}
	}
	return reflowEvidence(s)
}

// reflowEvidence 排版增强：步骤分组 + 命令/输出分离。
func reflowEvidence(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	stepRe := regexp.MustCompile(`^\s*\d+\)`)
	for _, l := range lines {
		l = strings.TrimRight(l, "\r")
		if stepRe.MatchString(l) {
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "") // 步骤间空行
			}
		}
		// 「curl … → 输出」拆两行：命令一行，响应缩进一行
		if i := strings.Index(l, " →"); i > 8 && strings.Contains(l[:i], "http") {
			cmd := strings.TrimSpace(l[:i])
			output := strings.TrimSpace(l[i+len(" →"):])
			out = append(out, cmd, "    ↳ "+output)
			continue
		}
		out = append(out, l)
	}
	// 收尾去多余空行
	var compact []string
	for i, l := range out {
		if l == "" && i > 0 && out[i-1] == "" {
			continue
		}
		compact = append(compact, l)
	}
	return strings.Join(compact, "\n")
}

// packetCommentLine 识别"注释行"：分隔线（----）、中文括注（----（…）----）、
// 步骤标号行（1) 2)）出现在空行之后且不像 HTTP 头的。
var packetNoiseRe = regexp.MustCompile(`^\s*-+\s*[（(]?[^)）]*[)）]?\s*-+\s*$`)

func isPacketNoise(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	// 纯分隔线 / 带括注的分隔线
	if packetNoiseRe.MatchString(t) {
		return true
	}
	// 纯中文括注行（…）且不含 ASCII 冒号头的 HTTP 头形态
	if strings.HasPrefix(t, "（") && strings.HasSuffix(t, "）") && !strings.Contains(t, ": ") {
		return true
	}
	return false
}

var rawRequestRe = regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/[0-9.]+$`)
var curlLineRe = regexp.MustCompile(`^\s*curl\s+`)

// cleanFindingPacket 把脏 packet 整形为"一个或多个独立可重放请求块"。
// 返回空串表示无可输出内容。
func cleanFindingPacket(pkt string) string {
	s := strings.TrimSpace(pkt)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	var blocks []string
	var cur []string
	hasRequestLine := false

	flush := func() {
		if len(cur) > 0 && hasRequestLine {
			blk := strings.Join(cur, "\n")
			if strings.TrimSpace(blk) != "" {
				blocks = append(blocks, blk)
			}
		}
		cur = nil
		hasRequestLine = false
	}

	for _, l := range lines {
		t := strings.TrimSpace(l)
		if isPacketNoise(t) {
			continue // 剔除注释/分隔行
		}
		if rawRequestRe.MatchString(t) {
			if hasRequestLine {
				flush() // 第二个请求行：上一块结束
			}
			cur = append(cur, t)
			hasRequestLine = true
			continue
		}
		if hasRequestLine {
			cur = append(cur, l)
		}
	}
	flush()

	// 整块都是 curl 命令（未转换的）→ 转原始包
	for i, b := range blocks {
		if curlLineRe.MatchString(b) {
			blocks[i] = curlBlockToPacket(b)
		}
	}

	out := make([]string, 0, len(blocks))
	for _, b := range blocks {
		if strings.TrimSpace(b) != "" {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return ""
	}
	if len(out) == 1 {
		return out[0] + "\n"
	}
	// 多请求：编号标注（两步链：先签发票据→再带票访问）
	var sb strings.Builder
	for i, b := range out {
		fmt.Fprintf(&sb, "── 请求 %d/%d ──\n%s\n", i+1, len(out), b)
		if i < len(out)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// splitShellQuote 按空白切分但保留成对单/双引号内的完整词。
func splitShellQuote(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
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
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// curlBlockToPacket 把一条（或多行续命名的）curl 命令转成原始 HTTP 请求包。
// 这里做简版：-X 方法、-H 头、-d 体、URL 位置参数。
func curlBlockToPacket(cmd string) string {
	fields := splitShellQuote(cmd)
	if len(fields) < 2 || fields[0] != "curl" {
		return cmd
	}
	method := "GET"
	var targetURL string
	var headers []string
	var body string
	var bodyParts []string
	i := 1
	for i < len(fields) {
		f := fields[i]
		switch {
		case f == "-X" && i+1 < len(fields):
			method = fields[i+1]
			i += 2
		case (f == "-H" || f == "--header") && i+1 < len(fields):
			headers = append(headers, fields[i+1])
			i += 2
		case (f == "-d" || f == "--data" || f == "--data-raw" || f == "--data-binary") && i+1 < len(fields):
			bodyParts = append(bodyParts, fields[i+1])
			i += 2
		case strings.HasPrefix(f, "-"):
			i++ // 忽略其它开关
		default:
			if targetURL == "" {
				targetURL = strings.Trim(fields[i], `"'`)
			}
			i++
		}
	}
	if targetURL == "" {
		return cmd
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return cmd
	}
	if len(bodyParts) > 0 {
		body = strings.Join(bodyParts, " ")
		if method == "GET" {
			method = "POST"
		}
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\n", method, path)
	fmt.Fprintf(&sb, "Host: %s\n", u.Host)
	for _, h := range headers {
		sb.WriteString(h + "\n")
	}
	if body != "" {
		if !hasHeaderLineI(headers, "content-type") {
			sb.WriteString("Content-Type: application/x-www-form-urlencoded\n")
		}
		sb.WriteString("\n")
		sb.WriteString(body + "\n")
	} else {
		sb.WriteString("\n")
	}
	return sb.String()
}

func hasHeaderLineI(headers []string, name string) bool {
	for _, h := range headers {
		if i := strings.Index(h, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(h[:i]), name) {
			return true
		}
	}
	return false
}

// synthesizePacketFromEvidence evidence 里没有 packet 时，从文本中提取 curl
// 命令合成可重放请求包。找不到返回空串。
func synthesizePacketFromEvidence(evText string) string {
	if evText == "" {
		return ""
	}
	var curls []string
	for _, l := range strings.Split(evText, "\n") {
		t := strings.TrimSpace(l)
		// 剥常见步骤前缀：1) 2) … 与「中文说明：」前缀（描述文字后接 curl 命令）
		for _, p := range []string{"1) ", "2) ", "3) ", "4) ", "5) ", "1)\t", "2)\t", "3)\t"} {
			t = strings.TrimPrefix(t, p)
		}
		if i := strings.Index(t, "curl "); i >= 0 {
			t = strings.TrimSpace(t[i:]) // 从 curl 起始截断（丢弃前面的中文说明）
		}
		if curlLineRe.MatchString(t) && strings.Contains(t, "http") {
			// 截掉命令尾部的中文/箭头输出描述（→ … 之后）
			if j := strings.Index(t, " →"); j > 0 {
				t = strings.TrimSpace(t[:j])
			} else if j := strings.Index(t, "→"); j > 0 && j < len(t)-1 && isHan(t[j+len("→")]) {
				t = strings.TrimSpace(t[:j])
			}
			// 去尾部中文括注（（…）结尾）
			if strings.HasSuffix(t, "）") {
				if k := strings.LastIndex(t, "（"); k > 0 {
					t = strings.TrimSpace(t[:k])
				}
			}
			curls = append(curls, t)
		}
	}
	if len(curls) == 0 {
		return ""
	}
	// 最多取 3 条（链式 PoC 通常 2-3 步）
	if len(curls) > 3 {
		curls = curls[:3]
	}
	var blocks []string
	for _, c := range curls {
		b := curlBlockToPacket(c)
		if b != c { // 转换成功
			blocks = append(blocks, b)
		}
	}
	if len(blocks) == 0 {
		return ""
	}
	if len(blocks) == 1 {
		return blocks[0]
	}
	var sb strings.Builder
	for i, b := range blocks {
		fmt.Fprintf(&sb, "── 请求 %d/%d ──\n%s\n", i+1, len(blocks), b)
		if i < len(blocks)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// finalizeFindingForReport 报告期统一整形入口：
// pktClean = 整形后的 packet；evClean = 可读 evidence；
// pktSynth = packet 为空时从 evidence 合成的请求包（空串=无）。
func finalizeFindingForReport(pkt, evRaw string) (pktClean, evClean, pktSynth string) {
	evClean = cleanFindingEvidence(evRaw)
	pktClean = cleanFindingPacket(pkt)
	if strings.TrimSpace(pktClean) == "" {
		pktSynth = synthesizePacketFromEvidence(evClean)
	}
	return
}

func isHan(b byte) bool { return b >= 0xe4 && b <= 0xe9 } // UTF-8 中文首字节

// plainVerdict 给非技术读者的"发生了什么"一句话。
// 从 summary/evidence 提炼：优先用 vulnerability 概括句；技术细节（URL/参数/响应码）
// 不进这句——那是附录的事。长度上限 ~110 字。
func plainVerdict(f *db.DBFinding) string {
	base := strings.TrimSpace(f.Summary)
	if base == "" {
		if _, ec, _ := finalizeFindingForReport(f.Packet, f.Evidence); ec != "" {
			base = ec
		}
	}
	if base == "" {
		return "验证过程见技术附录。"
	}
	// 截到第一个句号/分号后的完整句（通常第一句就是"是什么"）
	for _, sep := range []string{"。", "；", ";"} {
		if i := strings.Index(base, sep); i > 20 && i < 120 {
			base = base[:i+len("。")]
			break
		}
	}
	r := []rune(base)
	if len(r) > 110 {
		r = r[:110]
		base = string(r) + "……（详见技术附录）"
	}
	return base
}
