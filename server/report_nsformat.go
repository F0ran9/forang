package server

// report_nsformat.go — FORANG 渗透测试报告（参照行业交付模板：封面表 + 目录域 +
// 页眉密级 + 页脚页码 + 品牌色标题 + 等级配色漏洞小节 + 漏洞汇总表 + 攻击动作留痕）。
// 结构对齐真实交付报告：目标信息 → 测试内容（五类方法论）→ 漏洞信息（汇总+逐项）→
// 攻击动作痕迹 → 建议总结。无第三方品牌标识。

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

var sevLabelCN = map[string]string{"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息"}

// buildNSReport 组装行业模板格式的 Word 报告。
func (s *Server) buildNSReport(t *Task, fs []*db.DBFinding) *Docx {
	doc := NewDocx()

	target := t.Description
	// 封面要素可配（设置页「报告封面」卡）：org=机构署名、密级、编号前缀。
	org := "FORANG 自主渗透测试平台"
	classification := "内部资料"
	prefix := "FORANG"
	if v, ok, _ := s.m.pg.GetSetting("report.cover_org"); ok && strings.TrimSpace(v) != "" {
		org = strings.TrimSpace(v)
	}
	if v, ok, _ := s.m.pg.GetSetting("report.cover_classification"); ok && strings.TrimSpace(v) != "" {
		classification = strings.TrimSpace(v)
	}
	if v, ok, _ := s.m.pg.GetSetting("report.cover_prefix"); ok && strings.TrimSpace(v) != "" {
		prefix = strings.TrimSpace(v)
	}
	sysName := target
	if sysName == "" {
		sysName = "目标系统"
	}
	doc.SetHeader("密级：" + classification)
	doc.CoverPage(sysName, "渗透测试报告", [][2]string{
		{"文档编号", prefix + "-" + t.ID + "-" + time.Now().Format("20060102")},
		{"密级", classification},
		{"版本编号", "V1.0"},
		{"日期", time.Now().Format("2006-01-02")},
	}, "© "+time.Now().Format("2006")+" "+org)

	// ===== 目录 =====
	doc.TOCPage()

	// ===== 一. 目标信息 =====
	doc.Heading(1, "1. 目标信息")
	doc.Heading(2, "1.1 资产列表")
	doc.Table([]string{"序号", "资产"}, [][]string{{"1", target}})
	if t.Goal != "" {
		doc.Heading(2, "1.2 测试范围与目标")
		goalLines(doc, t.Goal)
	}

	// ===== 二. 测试内容 =====
	doc.Heading(1, "2. 测试内容")
	doc.Paragraph("本次测试参照 OWASP Testing Guide 方法论，覆盖以下五大类测试项：")
	contents := [][2]string{
		{"2.1 配置管理测试", "基础配置管理测试、应用管理界面测试、HTTP方法测试、SSL/TLS测试、应用配置管理测试、过期/备份页面测试"},
		{"2.2 认证测试", "认证模式绕过测试、用户枚举测试、暴力破解测试、竞争条件测试、图形验证码测试、密码修改点测试、密码重置点测试、用户注册点测试、注销登录测试"},
		{"2.3 会话管理测试", "Cookie测试、会话固定测试、会话变量泄露测试、CSRF测试"},
		{"2.4 授权测试", "绕过授权模式测试、提权测试、路径遍历测试、业务逻辑测试"},
		{"2.5 数据验证测试", "SQL注入测试、XSS测试、命令执行测试、文件上传/下载测试、信息泄露测试"},
	}
	for _, c := range contents {
		doc.Heading(2, c[0])
		doc.Paragraph(c[1])
	}

	// ===== 三. 漏洞信息（汇总 + 逐项）=====
	sorted := append([]*db.DBFinding(nil), fs...)
	sort.Slice(sorted, func(i, j int) bool {
		return sevOrder[sorted[i].Severity] < sevOrder[sorted[j].Severity]
	})
	doc.Heading(1, "3. 漏洞信息")

	// 3.1 风险概览：等级分布表
	doc.Heading(2, "3.1 风险概览")
	dist := map[string]int{}
	for _, f := range sorted {
		sev := sevLabelCN[f.Severity]
		if sev == "" {
			sev = f.Severity
		}
		dist[sev]++
	}
	order := []string{"严重", "高", "中", "低", "信息"}
	var distRows [][]CellSpec
	total := 0
	for _, sev := range order {
		if dist[sev] > 0 {
			distRows = append(distRows, []CellSpec{
				{Text: sev, Color: sevColorOf(sev), Bold: true},
				{Text: fmt.Sprintf("%d", dist[sev])},
			})
			total += dist[sev]
		}
	}
	doc.TableRich([]string{"危险等级", "数量"}, distRows)
	doc.Paragraph(fmt.Sprintf("共发现 **%d** 项安全问题，按危险等级汇总如上，逐项详情见下。", total))

	// 3.2 漏洞汇总表
	doc.Heading(2, "3.2 漏洞汇总")
	var sumRows [][]CellSpec
	for i, f := range sorted {
		sev := sevLabelCN[f.Severity]
		if sev == "" {
			sev = f.Severity
		}
		title := f.Name
		if title == "" {
			title = f.VulnClass
		}
		url := firstURL(f)
		if len(url) > 60 {
			url = url[:60] + "…"
		}
		sumRows = append(sumRows, []CellSpec{
			{Text: fmt.Sprintf("3.%d", i+3)}, // 汇总表为 3.2，逐项小节从 3.3 起
			{Text: title},
			{Text: sev, Color: sevColorOf(sev), Bold: true},
			{Text: url},
		})
	}
	doc.TableRich([]string{"编号", "漏洞名称", "危险等级", "相关URL"}, sumRows)

	// 逐项漏洞小节（3.3 起，每项独立分页）
	for i, f := range sorted {
		doc.PageBreak()
		s.buildNSVulnSection(doc, i+3, f)
	}

	// ===== 四. 攻击动作痕迹 =====
	doc.PageBreak()
	doc.Heading(1, "4. 攻击动作痕迹")
	actions := s.taskActionRows(t)
	if len(actions) == 0 {
		doc.Paragraph("本任务无记录在案的攻击动作（纯侦察/人工验证类任务）。")
	} else {
		doc.Paragraph(fmt.Sprintf("以下为本任务执行链路上的关键攻击动作（探索链路图自动留痕，含 webshell 落地/命令执行/C2 指挥/扫描侦察等），共 %d 条，按时间排列：", len(actions)))
		rows := make([][]string, 0, len(actions))
		for _, a := range actions {
			rows = append(rows, []string{a.TS, a.Type, a.Summary, a.Detail, a.Result})
		}
		doc.Table([]string{"时间", "动作类型", "动作内容", "目标", "结果"}, rows)
	}

	// ===== 五. 建议总结 =====
	doc.PageBreak()
	doc.Heading(1, "5. 建议总结")
	doc.Paragraph("针对本次测试发现的安全问题，建议从以下方面加强系统安全防护：")
	doc.Paragraph("1. 及时修复本报告列出的各漏洞项，优先处理高危与严重等级问题；对涉及默认凭据、未授权访问的服务，立即收紧访问控制并轮换相关凭据。")
	doc.Paragraph("2. 部署 WAF/IDS 等防护设备并对管理后台、运维接口（如 Actuator、Druid、Derby 等诊断端点）实施访问隔离，仅允许受信网段访问。")
	doc.Paragraph("3. 建立配置基线：关闭未使用的诊断端点，移除或轮换默认凭据（如 serverIdentity 等框架默认身份头），禁用前端硬编码口令。")
	doc.Paragraph("4. 完善日志审计与备份策略，将关键日志外发至独立日志服务器，防止单点破坏。")
	doc.Paragraph("注：Web 漏洞会随时间推移而变化，基于评估严谨性考虑，本报告仅具备两个月的时效性。")
	return doc
}

// goalLines 把任务目标文本逐行渲染为独立段落：换行在 Word 里不会被单个 <w:p>
// 保留（旧版整段硬塞导致 1)~6) 步骤全糊成一段、字距被两端对齐撑开）。
// 编号行（1) 2)…/1. 2.…/-、•）加左缩进，视觉上分条。
func goalLines(doc *Docx, goal string) {
	for _, ln := range strings.Split(goal, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		doc.GoalLine(ln)
	}
}

// findingShotCount 统计可嵌入的截图证据数（文件存在才算）。
func (s *Server) findingShotCount(f *db.DBFinding) int {
	n := 0
	if evs, err := s.ListFindingEvidence(f.ID); err == nil {
		for _, e := range evs {
			if e.Kind == "screenshot" && e.Path != "" {
				if _, serr := os.Stat(e.Path); serr == nil {
					n++
				}
			}
		}
	}
	return n
}

// firstURL 取漏洞第一个流量绑定 URL（汇总表展示用）。
func firstURL(f *db.DBFinding) string {
	for _, b := range f.TrafficBindings {
		if b.Snapshot.URL != "" {
			return b.Snapshot.URL
		}
	}
	return "-"
}

// actionRow 报告里的攻击动作行。
type actionRow struct {
	TS      string
	Type    string
	Summary string
	Detail  string
	Result  string
}

// actionLabelCN action 类型 → 中文标签（与前端 ACTION_LABELS 一致）。
var actionLabelCN = map[string]string{
	"webshell_gen":     "WebShell 生成",
	"webshell_exec":    "WebShell 执行",
	"webshell_privesc": "提权面分析",
	"webshell_plugin":  "WebShell 插件",
	"auto_escalate":    "自动升级",
	"c2_exec":          "C2 指挥",
	"c2_beacon":        "C2 Beacon",
	"fingerprint":      "指纹识别",
	"port_scan":        "端口扫描",
	"dir_scan":         "目录扫描",
}

// taskActionRows 读取本任务探索图的攻击动作节点（kind=action），按时间升序。
// 上限 80 条——webshell_exec 密集任务防表格失控，超出部分截断标注。
func (s *Server) taskActionRows(t *Task) []actionRow {
	rows, err := s.m.PG().Query(
		`SELECT payload, created_at FROM exploration_nodes
		 WHERE exploration_id=$1 AND kind='action' ORDER BY id ASC LIMIT 80`, t.ExpID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []actionRow{}
	for rows.Next() {
		var payload []byte
		var ts time.Time
		if err := rows.Scan(&payload, &ts); err != nil {
			continue
		}
		var p struct {
			Action  string `json:"action"`
			Summary string `json:"summary"`
			Target  string `json:"target"`
			Result  string `json:"result"`
		}
		_ = json.Unmarshal(payload, &p)
		label := actionLabelCN[p.Action]
		if label == "" {
			label = p.Action
		}
		res := p.Result
		switch res {
		case "ok", "":
			res = "成功"
		case "fail":
			res = "失败"
		case "pending":
			res = "进行中"
		}
		out = append(out, actionRow{
			TS: ts.Format("01-02 15:04:05"), Type: label,
			Summary: p.Summary, Detail: truncateStr(p.Target, 60), Result: res,
		})
	}
	return out
}

// buildNSVulnSection 单个漏洞小节：等级色标题 + 字段行 + POC 代码框 + 截图 + 建议。
func (s *Server) buildNSVulnSection(doc *Docx, idx int, f *db.DBFinding) {
	title := f.Name
	if title == "" {
		title = f.VulnClass
	}
	sev := sevLabelCN[f.Severity]
	if sev == "" {
		sev = f.Severity
	}
	doc.VulnHeading(idx, sev, title)

	// 评审信息（CVSS）
	cvssLine := ""
	if upg, err := s.GetFindingUpgrade(f.ID); err == nil && upg != nil {
		if upg.Cvss > 0 {
			cvssLine = fmt.Sprintf("CVSS %.1f（%s）", upg.Cvss, upg.CvssVector)
		}
		if upg.Review != nil && upg.Review.Reason != "" {
			if cvssLine != "" {
				cvssLine += "。"
			}
			cvssLine += "评审结论: " + upg.Review.Reason
		}
	}

	// 漏洞描述
	desc := strings.TrimSpace(f.Summary)
	if desc == "" {
		desc = f.Evidence
	}
	doc.FieldLine("漏洞描述：", desc)
	if cvssLine != "" {
		doc.FieldLine("定级依据：", cvssLine)
	}

	// 相关 URL（流量绑定快照去重）
	urls := map[string]bool{}
	var urlList []string
	for _, b := range f.TrafficBindings {
		u := b.Snapshot.URL
		if u != "" && !urls[u] {
			urls[u] = true
			urlList = append(urlList, u)
		}
	}
	if len(urlList) > 0 { // 无流量绑定的源码审计类发现不输出空字段行
		doc.FieldLine("相关URL：", "")
		for _, u := range urlList {
			doc.Paragraph(u)
		}
	}

	// POC 请求包：可直粘 Repeater/Burp 重放的完整原始 HTTP 请求（packet 列）。
	if pkt := strings.TrimSpace(f.Packet); pkt != "" {
		doc.FieldLine("POC请求包：", "以下为可直接重放的原始 HTTP 请求（复制进 Repeater/Burp 即可复现）")
		doc.CodeBlock(pkt)
	}

	// 相关截图：结构化截图实际嵌入；既无截图也无证据文本时不输出空字段行
	if shotCount := s.findingShotCount(f); shotCount > 0 || strings.TrimSpace(f.Evidence) != "" {
		doc.FieldLine("相关截图：", "")
	}
	shotCount := 0
	if evs, err := s.ListFindingEvidence(f.ID); err == nil {
		for _, e := range evs {
			if e.Kind == "screenshot" && e.Path != "" {
				if _, serr := os.Stat(e.Path); serr != nil {
					continue
				}
				caption := firstNonEmpty(e.Note, "相关截图")
				doc.Image(e.Path, caption)
				shotCount++
			}
		}
	}
	if shotCount == 0 && f.Evidence != "" {
		doc.CodeBlock(f.Evidence)
	}

	// 加固建议
	doc.FieldLine("加固建议：", remediationFor(f))
}

// remediationFor 按漏洞类别给出加固建议（类内通用建议 + 具体线索）。
func remediationFor(f *db.DBFinding) string {
	cls := f.VulnClass + " " + f.Name
	switch {
	case strings.Contains(cls, "未授权") || strings.Contains(cls, "认证绕过") || strings.Contains(cls, "serverIdentity"):
		return "为相关接口启用强认证与访问控制；移除或轮换框架默认凭据（如 serverIdentity 默认身份头）；管理端点仅对受信网段开放；对已暴露的凭据立即轮换。"
	case strings.Contains(cls, "Actuator") || strings.Contains(cls, "heapdump") || strings.Contains(cls, "env"):
		return "关闭或鉴权保护 Actuator 等诊断端点（仅暴露 health 且限内网）；heapdump/env 端点禁止对外；轮换 heapdump 中可能泄露的数据库口令、云 AK、JWT 密钥等全部凭据。"
	case strings.Contains(cls, "弱口令") || strings.Contains(cls, "默认口令") || strings.Contains(cls, "默认密码"):
		return "立即修改相关账号口令；启用口令复杂度策略与登录失败锁定；删除或禁用默认账号。"
	case strings.Contains(cls, "泄露") || strings.Contains(cls, "密钥") || strings.Contains(cls, "AccessKey"):
		return "轮换泄露的密钥与凭据；从代码与配置中移除硬编码凭据，改用密钥管理服务；对已泄露凭据做访问审计确认是否被滥用。"
	case strings.Contains(cls, "Derby") || strings.Contains(cls, "SQL"):
		return "对运维查询接口实施认证与白名单限制；禁止任意 SQL 执行；数据库与服务进程权限最小化。"
	case strings.Contains(cls, "Druid"):
		return "为 Druid 监控台配置强口令或直接禁用其对外暴露；限内网访问。"
	default:
		return "限制相关接口的访问权限；对输入与输出做严格校验；修复后进行复测确认。"
	}
}
