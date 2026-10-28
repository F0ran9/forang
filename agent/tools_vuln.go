package agent

// tools_vuln.go — 漏洞中枢 agent 工具（移植自全链哨兵 vuln-tool.ts，MIT）。
// vuln_submit：验证一条漏洞即提交（CVSS 必填 + 原始数据包逐字保存），落库为
// 待确认，由 LLM 评审员重定级、操作员复核；vuln_list/vuln_get 供二遍查重。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/artex/cvss"
	"github.com/Autumn-27/artex/db"
)

// vulnPreview 截断长文本（agent 包内自带，避免依赖 server）。
func vulnPreview(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…（截断）"
}

// SetVulnStore wires the vuln-hub store (nil = vuln tools unavailable).
func (t *ToolSet) SetVulnStore(vs *db.VulnStore) { t.vulns = vs }

func (t *ToolSet) needVulns() error {
	if t.vulns == nil {
		return fmt.Errorf("漏洞中枢不可用（本 agent 未接通 vuln store）")
	}
	return nil
}

// 哨兵原版：剥掉标题开头的【计划编号】/序号/列表标记；结尾标点也清掉。
var vulnTitleLead = regexp.MustCompile(`^(?:[【\[（(][^】\]）)]{0,60}[】\]）)]|\d+\s*[.、)）]|[-*#])\s*`)
var vulnTitleTail = regexp.MustCompile(`[。．.；;，,、：:\s]+$`)

// NormalizeVulnTitle 把提交标题清洗成一行标签（≤40 字）。
func NormalizeVulnTitle(raw string) string {
	title := strings.Join(strings.Fields(raw), " ")
	for {
		next := strings.TrimSpace(vulnTitleLead.ReplaceAllString(title, ""))
		if next == title || next == "" {
			return strings.TrimRight(strings.TrimSpace(title), "。．.；;，,、：: \t")
		}
		title = next
	}
}

func vulnSeverityRank(s string) int { return db.VulnSeverityRank(s) }

func (t *ToolSet) vulnTools() []actool.CoreTool {
	return []actool.CoreTool{t.vulnSubmitTool(), t.vulnListTool(), t.vulnGetTool()}
}

func (t *ToolSet) vulnSubmitTool() actool.CoreTool {
	return writeTool("vuln_submit",
		`Submit one confirmed finding to the vulnerability hub. Call it once per finding, as soon as the finding is validated, instead of waiting for the final summary. The record lands as 待确认 for the operator to reproduce, so state the evidence you actually have. 必填：severity、cvss(0.0-10.0)、target、原始数据包 packet（逐字）。android 客户端发现填 platform=android + appPackage/appVersion。评审员会按 CVSS v3.1 重定级，存疑记录封顶中危。`,
		obj(map[string]any{
			"title":        str("一行标题：漏洞类别+受影响对象，≤40 字（如「后台登录处 SQL 注入」）。不要带【】前缀/计划编号/轮次/结论，那些放 description"),
			"severity":     str("critical / high / medium / low / info，须与 CVSS 档位一致"),
			"cvss":         map[string]any{"type": "number", "description": "CVSS 基准分 0.0-10.0"},
			"cvss_vector":  str("可选 CVSS 向量串"),
			"target":       str("受影响目标：host / URL / IP:port / 服务"),
			"category":     str("可选漏洞类别，如「SQL 注入」「未授权访问」"),
			"description":  str("漏洞是什么、能让攻击者做什么"),
			"packet":       str("证明该漏洞的原始请求或报文，逐字粘贴（HTTP 请求/响应或报文字节）"),
			"repro":        str("可选复现步骤"),
			"remediation":  str("可选修复建议"),
			"references":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选 CVE/CWE/参考链接"},
			"platform":     str("可选：web（默认）/ android"),
			"app_package":  str("android 时目标包名"),
			"app_version":  str("android 时版本号"),
			"evidence":     map[string]any{"type": "array", "description": "可选证据列表", "items": obj(map[string]any{
				"kind": str("command / file"), "command": str("产生证据的命令"), "output": str("关键输出"),
				"path": str("工作目录内文件路径"), "note": str("这条证据说明什么"),
			})},
		}, "title", "severity", "cvss", "target", "description", "packet"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if err := t.needVulns(); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				Title, Severity, CvssVector, Target, Category string
				Description, Packet, Repro, Remediation       string
				Platform, AppPackage, AppVersion              string
				References []string                            `json:"references"`
				Evidence   []struct{ Kind, Command, Output, Path, Note string }
				Cvss       float64
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			title := NormalizeVulnTitle(a.Title)
			if title == "" || utf8.RuneCountInString(title) > 40 {
				return actool.Errorf(fmt.Sprintf("title 必须是 1-40 字的一行标签（清洗后得到 %d 字）", utf8.RuneCountInString(title))), nil
			}
			if vulnSeverityRank(a.Severity) == 0 {
				return actool.Errorf("severity 仅支持 critical/high/medium/low/info"), nil
			}
			if a.Cvss < 0 || a.Cvss > 10 {
				return actool.Errorf(fmt.Sprintf("CVSS 分数必须在 0.0-10.0 之间，收到 %.1f", a.Cvss)), nil
			}
			if strings.TrimSpace(a.Packet) == "" {
				return actool.Errorf("packet 必填：逐字粘贴证明该漏洞的原始请求/报文"), nil
			}
			mismatch := ""
			if cvss.SeverityForCvss(a.Cvss) != a.Severity {
				mismatch = fmt.Sprintf("（注意：%.1f 对应档位 %s，与你提交的 %s 不一致，评审员会重定级）", a.Cvss, cvss.SeverityForCvss(a.Cvss), a.Severity)
			}
			ev := make([]db.VulnEvidence, 0, len(a.Evidence))
			for _, e := range a.Evidence {
				if e.Kind != "command" && e.Kind != "file" {
					e.Kind = "command"
				}
				ev = append(ev, db.VulnEvidence{Kind: e.Kind, Command: e.Command, Output: e.Output, Path: e.Path, Note: e.Note})
			}
			v, err := t.vulns.CreateVuln(db.VulnCreate{
				TaskID: t.taskID, Source: t.worker, Title: title, Severity: a.Severity, Cvss: a.Cvss,
				CvssVector: a.CvssVector, Target: a.Target, Category: a.Category,
				Platform: a.Platform, AppPackage: a.AppPackage, AppVersion: a.AppVersion,
				Description: a.Description, Packet: a.Packet, Repro: a.Repro, Remediation: a.Remediation,
				Refs: a.References, Evidence: ev,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("漏洞入库失败: %v", err)), nil
			}
			return actool.Text(fmt.Sprintf("✅ %s 已提交漏洞中枢（状态 待确认，评审员将按 CVSS v3.1 重定级）%s", v.Label, mismatch)), nil
		})
}

func (t *ToolSet) vulnListTool() actool.CoreTool {
	return readTool("vuln_list",
		"列出本任务/全局已提交的漏洞（提交前先查，避免重复提交同一漏洞）。可按 status/severity/target 子串/search 过滤。",
		obj(map[string]any{
			"status":   str("可选：pending / confirmed / false_positive / fixed"),
			"severity": str("可选：critical / high / medium / low / info"),
			"target":   str("可选，目标子串"),
			"search":   str("可选，label/标题/类别/描述子串"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if err := t.needVulns(); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var f db.VulnFilters
			_ = json.Unmarshal(in, &f)
			if f.TaskID = t.taskID; f.TaskID == 0 {
				f.TaskID = 0 // 对话模式看全局
			}
			vs, err := t.vulns.ListVulns(f)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("查询失败: %v", err)), nil
			}
			if len(vs) == 0 {
				return actool.Text("（漏洞中枢暂无记录）"), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "共 %d 条：\n", len(vs))
			for _, v := range vs {
				rev := ""
				if v.Review != nil && v.Review.State == "done" {
					rev = fmt.Sprintf(" · 评审: CVSS %.1f %s", v.Review.Cvss, v.Review.Vector)
					if v.Review.Dubious {
						rev += "（存疑）"
					}
				}
				fmt.Fprintf(&sb, "- %s [%s/%s] %s → %s%s\n", v.Label, v.Severity, v.Status, v.Title, v.Target, rev)
			}
			return actool.Text(sb.String()), nil
		})
}

func (t *ToolSet) vulnGetTool() actool.CoreTool {
	return readTool("vuln_get",
		"按 label（如 VULN-0003）或数字 id 取一条漏洞的完整记录（含原始数据包/证据/评审结论/复核时间线）。",
		obj(map[string]any{"id": str("label 或数字 id")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if err := t.needVulns(); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			key := droidString(in, "id")
			id := int64(0)
			if n := strings.TrimPrefix(strings.ToUpper(key), "VULN-"); n != strings.ToUpper(key) {
				fmt.Sscanf(n, "%d", &id)
			} else {
				fmt.Sscanf(key, "%d", &id)
			}
			if id == 0 {
				return actool.Errorf("id 需是 VULN-XXXX 或数字"), nil
			}
			v, err := t.vulns.GetVuln(id)
			if err != nil || v == nil {
				return actool.Errorf("记录不存在"), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s %s\n等级: %s CVSS %.1f %s\n状态: %s\n目标: %s\n来源: %s\n提交: %s\n",
				v.Label, v.Title, v.Severity, v.Cvss, v.CvssVector, v.Status, v.Target, v.Source, v.CreatedAt.Format("01-02 15:04"))
			if v.Review != nil {
				fmt.Fprintf(&sb, "评审[%s]: dubious=%v %s\n", v.Review.State, v.Review.Dubious, v.Review.Reason)
			}
			sb.WriteString("\n漏洞详情:\n" + v.Description + "\n\n原始数据包:\n" + vulnPreview(v.Packet, 3000))
			if len(v.Repro) > 0 {
				sb.WriteString("\n\n复现步骤:\n" + v.Repro)
			}
			if len(v.Evidence) > 0 {
				sb.WriteString("\n\n证据:")
				for i, e := range v.Evidence {
					fmt.Fprintf(&sb, "\n  %d. [%s] %s", i+1, e.Kind, e.Note)
					if e.Command != "" {
						sb.WriteString("\n     命令: " + vulnPreview(e.Command, 300))
					}
					if e.Path != "" {
						sb.WriteString("\n     文件: " + e.Path)
					}
				}
			}
			if len(v.Notes) > 0 {
				sb.WriteString("\n\n处理时间线:")
				for _, n := range v.Notes {
					fmt.Fprintf(&sb, "\n  - %s %s: %s", n.At.Format("01-02 15:04"), n.Author, n.Text)
				}
			}
			return actool.Text(sb.String()), nil
		})
}
