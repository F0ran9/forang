package server

// report_nsformat.go — FORANG 渗透测试报告（参照行业通用交付模板）：
// 封面（标题/文档编号/密级/日期）→ 目标信息/资产列表 → 测试内容（五类方法论概述）→
// 漏洞信息（每漏洞一表：【等级】标题 | 漏洞描述 | 相关URL | 相关截图（页面图+接口取证图）
// | 加固建议）→ 建议总结。无第三方品牌标识。

import (
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

	// ===== 封面 =====
	for i := 0; i < 6; i++ {
		doc.Paragraph("")
	}
	doc.Heading(1, "渗透测试报告")
	doc.Paragraph("")
	target := t.Description
	doc.Heading(2, target)
	doc.Paragraph("文档编号: FORANG-" + t.ID + "-" + time.Now().Format("20060102"))
	doc.Paragraph("密级: 内部资料")
	doc.Paragraph("版本编号: V1.0")
	doc.Paragraph("日期: " + time.Now().Format("2006-01-02"))
	doc.Paragraph("© " + time.Now().Format("2006") + " FORANG 自主渗透测试平台")
	doc.PageBreak()

	// ===== 一. 目标信息 =====
	doc.Heading(1, "一. 目标信息")
	doc.Heading(2, "1.1 资产列表")
	doc.Paragraph("资产: " + target)
	if t.Goal != "" {
		doc.Heading(2, "1.2 测试目标")
		doc.Paragraph(t.Goal)
	}

	// ===== 二. 测试内容 =====
	doc.Heading(1, "二. 测试内容")
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

	// ===== 三. 漏洞信息（按等级排序，每漏洞一张表）=====
	doc.Heading(1, "三. 漏洞信息")
	sorted := append([]*db.DBFinding(nil), fs...)
	sort.Slice(sorted, func(i, j int) bool {
		return sevOrder[sorted[i].Severity] < sevOrder[sorted[j].Severity]
	})
	for i, f := range sorted {
		doc.PageBreak()
		s.buildNSVulnSection(doc, i+1, f)
	}

	// ===== 四. 建议总结 =====
	doc.PageBreak()
	doc.Heading(1, "四. 建议总结")
	doc.Paragraph("针对本次测试发现的安全问题，建议从以下方面加强系统安全防护：")
	doc.Paragraph("1. 及时修复本报告列出的各漏洞项，优先处理高危与严重等级问题；对涉及默认凭据、未授权访问的服务，立即收紧访问控制并轮换相关凭据。")
	doc.Paragraph("2. 部署 WAF/IDS 等防护设备并对管理后台、运维接口（如 Actuator、Druid、Derby 等诊断端点）实施访问隔离，仅允许受信网段访问。")
	doc.Paragraph("3. 建立配置基线：关闭未使用的诊断端点，移除或轮换默认凭据（如 serverIdentity 等框架默认身份头），禁用前端硬编码口令。")
	doc.Paragraph("4. 完善日志审计与备份策略，将关键日志外发至独立日志服务器，防止单点破坏。")
	doc.Paragraph("注: Web 漏洞会随时间推移而变化，基于评估严谨性考虑，本报告仅具备两个月的时效性。")
	return doc
}

// buildNSVulnSection 单个漏洞章节：标题 + 字段表 + 截图。
func (s *Server) buildNSVulnSection(doc *Docx, idx int, f *db.DBFinding) {
	title := f.Name
	if title == "" {
		title = f.VulnClass
	}
	sev := sevLabelCN[f.Severity]
	if sev == "" {
		sev = f.Severity
	}
	doc.Heading(1, fmt.Sprintf("%d.【%s】%s", idx, sev, title))

	// 评审信息并入描述前缀
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
	doc.Heading(3, "漏洞描述")
	doc.Paragraph(desc)
	if cvssLine != "" {
		doc.Paragraph("定级依据: " + cvssLine)
	}

	// 相关 URL（从流量绑定快照取）
	doc.Heading(3, "相关URL")
	urls := map[string]bool{}
	if len(f.TrafficBindings) == 0 {
		doc.Paragraph("（见漏洞描述与截图）")
	} else {
		for _, b := range f.TrafficBindings {
			u := b.Snapshot.URL
			if u == "" {
				continue
			}
			if !urls[u] {
				urls[u] = true
				doc.Paragraph(u)
			}
		}
	}

	// 相关截图：先结构化截图（页面图），再接口取证图，最后报文文本
	doc.Heading(3, "相关截图")
	shotCount := 0
	if evs, err := s.ListFindingEvidence(f.ID); err == nil {
		for _, e := range evs {
			if e.Kind == "screenshot" && e.Path != "" {
				if _, serr := os.Stat(e.Path); serr != nil {
					continue
				}
				doc.Image(e.Path, firstNonEmpty(e.Note, "相关截图"))
				shotCount++
			}
		}
	}
	// 绑定的流量快照：报文作为文本证据
	for _, b := range f.TrafficBindings {
		if b.Snapshot.ReqHead == "" {
			continue
		}
		var blk strings.Builder
		blk.WriteString("> " + b.Snapshot.Method + " " + b.Snapshot.URL + "\n")
		blk.WriteString(b.Snapshot.ReqHead)
		doc.CodeBlock(blk.String())
		shotCount++
	}
	// 无结构化截图时退回 evidence 文本
	if shotCount == 0 && f.Evidence != "" {
		doc.CodeBlock(f.Evidence)
	}

	// 加固建议
	doc.Heading(3, "加固建议")
	doc.Paragraph(remediationFor(f))
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
