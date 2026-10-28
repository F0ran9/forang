// Package repeater — 手工重放内核：原始报文忠实重放（TCP 直写）、取证页渲染、
// Chromium 截图。服务端 API（工具箱 Repeater 页）与 agent 工具共用。
// 截图汲取 replayd 的带时间取证能力（北京时间面板 + 响应头 Date + 抓取时间），
// 但不再依赖独立 replayd 服务：取证页由本包渲染成 HTML，平台自带 Chromium 截图。
package repeater

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxBodyBytes 解压后正文上限（8MB）。
const maxBodyBytes = 8 << 20

// Options 一次重放的选项。
type Options struct {
	ForceHTTPS     bool // 把请求行/Host 之外的目标 scheme 强制为 https
	FollowRedirect bool // 3xx 自动跟随（最多 5 跳，方法降为 GET）
	MaxBodyKB      int  // 响应体截断上限（KB）
	TimeoutSec     int  // 连接+读取总超时
}

// Hop 一次跳变的请求/响应记录（跟随重定向时 >1 条）。
type Hop struct {
	RequestSent string `json:"request_sent"` // 实际发出的原始报文（补 Connection: close 后）
	StatusLine  string `json:"status_line"`
	Headers     string `json:"headers"`
	Body        string `json:"body"`
	ElapsedMS   int64  `json:"elapsed_ms"`
	Err         string `json:"err,omitempty"`
}

// Result 一次重放的完整结果。
type Result struct {
	Scheme  string `json:"scheme"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Hops    []Hop  `json:"hops"`
	Final   Hop    `json:"final"` // 最后一跳（等价 hops[len-1]）
	TotalMS int64  `json:"total_ms"`
}

// DefaultOptions 返回与 UI 默认控件一致的选项。
func DefaultOptions() Options {
	return Options{FollowRedirect: true, MaxBodyKB: 1024, TimeoutSec: 30}
}

// NormalizeRaw 规整原始报文：LF→CRLF、去掉开头多余空行；返回规整文本。
func NormalizeRaw(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	raw = strings.TrimLeft(raw, "\n")
	return strings.ReplaceAll(raw, "\n", "\r\n")
}

// Target 从原始报文解析目标（Host 头优先，缺省补 Host: —报文本身必须可发）。
func Target(raw string, forceHTTPS bool) (scheme, host string, port int, err error) {
	scheme = "http"
	port = 80
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	headLines := strings.Split(head, "\r\n")
	if len(headLines) == 0 || !strings.Contains(headLines[0], " ") {
		return "", "", 0, fmt.Errorf("请求行不合法（应为 METHOD PATH HTTP/x.x）")
	}
	reqLine := strings.Fields(headLines[0])
	if len(reqLine) >= 2 {
		if strings.HasPrefix(reqLine[1], "https://") {
			scheme = "https"
		}
	}
	for _, l := range headLines[1:] {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			h := strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
			if strings.Contains(h, ":") {
				hp := strings.SplitN(h, ":", 2)
				host = strings.TrimSpace(hp[0])
				if n, e := strconv.Atoi(strings.TrimSpace(hp[1])); e == nil {
					port = n
				}
			} else {
				host = strings.TrimSpace(h)
			}
			break
		}
	}
	if host == "" {
		return "", "", 0, fmt.Errorf("报文缺少 Host 头")
	}
	if forceHTTPS {
		scheme = "https"
	}
	if scheme == "https" && port == 80 {
		port = 443
	}
	return scheme, host, port, nil
}

// sendOnce 连接目标并写入原始字节，读取响应（Content-Length/chunked/EOF 自适应，
// 总字节受 maxBodyKB 限制）。
func sendOnce(ctx context.Context, scheme, host string, port int, raw []byte, timeout time.Duration, maxBody int) (status, headers, body string, elapsed int64, err error) {
	start := time.Now()
	var conn net.Conn
	dialer := &net.Dialer{Timeout: timeout}
	if scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)),
			&tls.Config{InsecureSkipVerify: true, ServerName: host}) // 渗透重放场景：不校验证书链
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	if err != nil {
		return "", "", "", 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	// 停止观察者：ctx 取消立即断连接（读阻塞也能退出）
	stopClose := make(chan struct{})
	defer close(stopClose)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
			_ = conn.Close()
		case <-stopClose:
		}
	}()
	if _, err = conn.Write(raw); err != nil {
		return "", "", "", time.Since(start).Milliseconds(), err
	}
	buf := make([]byte, 32*1024)
	var all bytes.Buffer
	for {
		n, e := conn.Read(buf)
		if n > 0 {
			all.Write(buf[:n])
			if all.Len() >= maxBody {
				all.Truncate(maxBody)
				break
			}
		}
		if e != nil {
			break // EOF 或超时：响应已取到能取到的部分
		}
	}
	elapsed = time.Since(start).Milliseconds()
	out := all.Bytes()
	sep := bytes.Index(out, []byte("\r\n\r\n"))
	if sep < 0 {
		return "", string(out), "", elapsed, nil
	}
	head := string(out[:sep])
	rest := out[sep+4:]
	lines := strings.SplitN(head, "\r\n", 2)
	status = lines[0]
	if len(lines) > 1 {
		headers = lines[1]
	}
	// chunked 简易还原：解码后更可读
	if strings.Contains(strings.ToLower(headers), "transfer-encoding: chunked") {
		rest = dechunk(rest)
	}
	rest = decompress(headers, rest)
	body = string(rest)
	return status, headers, body, elapsed, nil
}

// decompress 按响应头 Content-Encoding 还原 gzip/deflate 正文（显示用；失败原样返回）。
func decompress(headers string, body []byte) []byte {
	enc := ""
	for _, l := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "content-encoding:") {
			enc = strings.ToLower(strings.TrimSpace(strings.SplitN(l, ":", 2)[1]))
		}
	}
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		out, err := io.ReadAll(io.LimitReader(zr, int64(maxBodyBytes)))
		if err != nil {
			return body
		}
		return out
	case "deflate":
		zr := flate.NewReader(bytes.NewReader(body))
		out, err := io.ReadAll(io.LimitReader(zr, int64(maxBodyBytes)))
		if err != nil || len(out) == 0 {
			zr2, zerr := zlib.NewReader(bytes.NewReader(body))
			if zerr != nil {
				return body
			}
			out2, err2 := io.ReadAll(io.LimitReader(zr2, int64(maxBodyBytes)))
			if err2 != nil {
				return body
			}
			return out2
		}
		return out
	default:
		return body
	}
}

// dechunk 按 RFC2616 还原 chunked 响应体（尽力而为，容忍截断）。
func dechunk(b []byte) []byte {
	var out bytes.Buffer
	for len(b) > 0 {
		nl := bytes.Index(b, []byte("\r\n"))
		if nl < 0 {
			out.Write(b)
			break
		}
		sizeHex := strings.TrimSpace(string(b[:nl]))
		if i := strings.IndexByte(sizeHex, ';'); i >= 0 {
			sizeHex = sizeHex[:i]
		}
		size, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil || size < 0 {
			out.Write(b) // 不是 chunked 结构，原样返回
			break
		}
		b = b[nl+2:]
		if size == 0 {
			break
		}
		if int64(len(b)) < size {
			out.Write(b)
			break
		}
		out.Write(b[:size])
		b = b[size:]
		if bytes.HasPrefix(b, []byte("\r\n")) {
			b = b[2:]
		}
	}
	return out.Bytes()
}

// Send 忠实重放原始报文（自动补 Connection: close 保证能读到响应尾），
// 可选跟随重定向。返回全部跳与末跳详情。
func Send(raw string, opt Options) (*Result, error) {
	return SendCtx(context.Background(), raw, opt)
}

// SendCtx 同 Send，但可被 ctx 取消（停止按钮）：取消时立即断开底层连接。
func SendCtx(ctx context.Context, raw string, opt Options) (*Result, error) {
	if opt.MaxBodyKB <= 0 {
		opt.MaxBodyKB = 1024
	}
	if opt.TimeoutSec <= 0 {
		opt.TimeoutSec = 30
	}
	timeout := time.Duration(opt.TimeoutSec) * time.Second
	raw = NormalizeRaw(raw)
	res := &Result{}
	current := raw
	var curScheme, curHost string
	var curPort int
	for hop := 0; hop < 6; hop++ {
		var scheme, host string
		var port int
		var err error
		if hop == 0 {
			scheme, host, port, err = Target(current, opt.ForceHTTPS)
			if err != nil {
				return res, err
			}
		} else {
			scheme, host, port = curScheme, curHost, curPort
		}
		res.Scheme, res.Host, res.Port = scheme, host, port
		// 未显式声明 Connection 时补 close，保证按 EOF 读完整响应
		b := []byte(current)
		if !strings.Contains(strings.ToLower(current), "connection:") {
			if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
				b = append(b[:i], append([]byte("\r\nConnection: close"), b[i:]...)...)
			}
		}
		var h Hop
		h.RequestSent = string(b)
		st, hd, bd, el, serr := sendOnce(ctx, scheme, host, port, b, timeout, opt.MaxBodyKB*1024)
		h.StatusLine, h.Headers, h.Body, h.ElapsedMS = st, hd, bd, el
		if serr != nil {
			h.Err = serr.Error()
		}
		res.Hops = append(res.Hops, h)
		res.Final = h
		res.TotalMS += h.ElapsedMS
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !opt.FollowRedirect || h.Err != "" {
			break
		}
		if !strings.HasPrefix(h.StatusLine, "HTTP/1.") || !strings.ContainsAny(h.StatusLine[:13], "3") {
			break // 非 3xx
		}
		loc := headerValue(h.Headers, "Location")
		if loc == "" {
			break
		}
		next, ns, nh, np, err := redirectRaw(current, scheme, host, port, loc)
		if err != nil {
			break
		}
		current = next
		curScheme, curHost, curPort = ns, nh, np
	}
	return res, nil
}

func headerValue(headers, name string) string {
	for _, l := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), strings.ToLower(name)+":") {
			return strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
	}
	return ""
}

// redirectRaw 基于 Location 构造下一跳报文（跨域改 Host，方法降 GET）。
func redirectRaw(prev string, prevScheme, prevHost string, prevPort int, location string) (string, string, string, int, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", "", "", 0, err
	}
	scheme, host, port := prevScheme, prevHost, prevPort
	if u.IsAbs() {
		scheme = u.Scheme
		host = u.Hostname()
		port = 80
		if scheme == "https" {
			port = 443
		}
		if u.Port() != "" {
			port, _ = strconv.Atoi(u.Port())
		}
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	// 请求行替换为绝对路径；删 body（30x 跟随按规范降 GET）
	lines := strings.Split(prev, "\r\n")
	req := strings.Fields(lines[0])
	if len(req) == 0 {
		return "", "", "", 0, fmt.Errorf("原报文请求行不合法")
	}
	method := "GET"
	if req[0] == "HEAD" {
		method = "HEAD"
	}
	var body string
	if idx := strings.Index(prev, "\r\n\r\n"); idx >= 0 {
		body = prev[idx+4:]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, path)
	inHost := false
	for _, l := range lines[1:] {
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "host:") {
			if port == 80 && scheme == "http" || port == 443 && scheme == "https" {
				fmt.Fprintf(&sb, "Host: %s\r\n", host)
			} else {
				fmt.Fprintf(&sb, "Host: %s:%d\r\n", host, port)
			}
			inHost = true
			continue
		}
		if strings.HasPrefix(ll, "content-length:") || strings.HasPrefix(ll, "transfer-encoding:") {
			continue // body 已随 30x 丢弃
		}
		sb.WriteString(l + "\r\n")
	}
	if !inHost {
		fmt.Fprintf(&sb, "Host: %s\r\n", host)
	}
	_ = body
	sb.WriteString("\r\n")
	return sb.String(), scheme, host, port, nil
}

// --- 取证页渲染 + 截图 ---

// EvidenceInput 生成带时间取证页所需的材料。
type EvidenceInput struct {
	RawSent  string // 实际发送的请求
	Response string // 状态行+头+体（已截断）
	Target   string
	Note     string // 留证目的/备注
	Capture  time.Time
}

// RenderEvidenceHTML 渲染三栏取证页（请求|响应|时间面板），返回 HTML。
// 时间面板汲取 replayd：北京时间 + 服务器响应头 Date + 本机抓取时间 + 目标与备注。
func RenderEvidenceHTML(in EvidenceInput) string {
	loc := time.FixedZone("CST", 8*3600)
	now := in.Capture.In(loc)
	serverDate := headerValueAll(in.Response, "Date")
	respHead, respBody := splitResponse(in.Response)
	return fmt.Sprintf(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<style>
 body{margin:0;background:#0b0f14;color:#e5e7eb;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
 header{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;border-bottom:1px solid #1f2a37}
 header .t{font-size:16px;font-weight:700;color:#34d399}
 main{display:flex;gap:1px;background:#1f2a37;height:calc(100vh-49px)}
 .col{flex:1;min-width:0;background:#0b0f14;display:flex;flex-direction:column}
 .col h2{margin:0;padding:8px 12px;font-size:12px;color:#93c5fd;border-bottom:1px solid #1f2a37;background:#0d1420}
 pre{flex:1;margin:0;padding:12px;overflow:hidden;white-space:pre-wrap;word-break:break-all;color:#d1d5db}
 .panel{padding:14px 16px;font-family:ui-sans-serif,system-ui,sans-serif}
 .panel b{color:#34d399}
 .kv{margin:6px 0}
 .kv span{color:#94a3b8;display:inline-block;width:120px}
 .big{font-size:26px;color:#fbbf24;margin:8px 0}
 .watermark{margin-top:18px;padding-top:10px;border-top:1px dashed #1f2a37;color:#6b7280;font-size:11px}
</style></head><body>
<header><div class="t">FORANG · Repeater 留证</div><div>%s</div></header>
<main>
 <div class="col"><h2>请求（实际发送）</h2><pre>%s</pre></div>
 <div class="col"><h2>响应</h2><pre>%s</pre></div>
 <div class="col"><h2>取证 · 实时校验</h2><div class="panel">
   <div class="kv"><span>目标</span><b>%s</b></div>
   <div class="kv"><span>北京时间</span><div class="big">%s</div></div>
   <div class="kv"><span>服务器响应头 Date</span>%s</div>
   <div class="kv"><span>本机抓取时间</span>%s</div>
   <div class="kv"><span>备注</span>%s</div>
   <div class="watermark">FORANG 取证快照 · 截图即证据 · 北京时间取自抓取主机时钟（UTC+8）</div>
 </div></div>
</main></body></html>`,
		now.Format("2006-01-02 15:04:05 MST"),
		html.EscapeString(in.RawSent),
		html.EscapeString(respHead+"\n\n"+respBody),
		html.EscapeString(in.Target),
		now.Format("2006-01-02 15:04:05 -07:00"),
		html.EscapeString(serverDate),
		now.Format("2006-01-02 15:04:05.000"),
		html.EscapeString(in.Note),
	)
}

func headerValueAll(response, name string) string {
	head, _, _ := strings.Cut(response, "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), strings.ToLower(name)+":") {
			return strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
	}
	return "（响应无该头）"
}

func splitResponse(resp string) (head, body string) {
	h, b, _ := strings.Cut(resp, "\r\n\r\n")
	return h, b
}

// CaptureScreenshot 用 Chromium headless 截取取证页，返回 PNG 字节数。
func CaptureScreenshot(htmlPath, pngPath string, width, height int) (int, error) {
	return CaptureScreenshotCtx(context.Background(), htmlPath, pngPath, width, height)
}

// CaptureScreenshotCtx 同 CaptureScreenshot，可被 ctx 取消。
func CaptureScreenshotCtx(ctx context.Context, htmlPath, pngPath string, width, height int) (int, error) {
	if width <= 0 {
		width = 1600
	}
	if height <= 0 {
		height = 1000
	}
	os.MkdirAll(filepath.Dir(pngPath), 0o755)
	args := []string{
		"--headless", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
		fmt.Sprintf("--window-size=%d,%d", width, height),
		"--virtual-time-budget=4000",
		fmt.Sprintf("--screenshot=%s", pngPath),
		"file://" + htmlPath,
	}
	cmd := exec.CommandContext(ctx, "chromium", args...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("chromium 截图失败: %v；%s", err, strings.TrimSpace(out.String()))
	}
	st, err := os.Stat(pngPath)
	if err != nil {
		return 0, err
	}
	return int(st.Size()), nil
}
