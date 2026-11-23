package server

// report_findings.go — 漏洞中台报告：基于 findings 表（而非探索图旧链路）生成
// 渗透测试报告。Word 版嵌入 finding_evidence 里的截图（repeater_capture /
// web_screenshot / droid 截图），并附评审 CVSS 与结论。

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

var sevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// GET /api/tasks/{id}/report/markdown — 漏洞中台附录 Markdown（findings 表发现）。
func (s *Server) taskReportMarkdown(w http.ResponseWriter, r *http.Request) {
	md := s.findingsAppendixMarkdown(r.PathValue("id"))
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write([]byte(md))
}

func sortFindingsBySeverity(fs []*db.DBFinding) {
	sort.Slice(fs, func(i, j int) bool {
		return sevOrder[fs[i].Severity] < sevOrder[fs[j].Severity]
	})
}

func (s *Server) buildFindingsDocx(t *Task, fs []*db.DBFinding) (doc *Docx) {
	doc = NewDocx()
	doc.Heading(1, "渗透测试报告")
	doc.Paragraph("目标系统: " + firstNonEmpty(cleanCoverName(t.Description), "目标系统"))
	doc.Paragraph("生成时间: " + time.Now().Format("2006-01-02 15:04:05"))
	doc.Paragraph(fmt.Sprintf("发现总数: %d", len(fs)))

	// 统计表
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	rows := make([][]string, 0, 5)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		label := map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}[sev]
		rows = append(rows, []string{label, strconv.Itoa(counts[sev])})
	}
	doc.Heading(2, "风险统计（按评审后等级）")
	doc.Table([]string{"等级", "数量"}, rows)

	for i, f := range fs {
		doc.PageBreak()
		title := f.Name
		if title == "" {
			title = f.VulnClass
		}
		doc.Heading(2, fmt.Sprintf("%d. %s", i+1, title))

		// 评审/CVSS 信息
		upg, uerr := s.GetFindingUpgrade(f.ID)
		rev := ""
		cvssTxt := "未评审"
		if uerr == nil && upg != nil {
			if upg.Cvss > 0 {
				cvssTxt = fmt.Sprintf("CVSS %.1f（%s）", upg.Cvss, upg.CvssVector)
			}
			if upg.Review != nil && upg.Review.State == "done" {
				tag := "评审通过"
				if upg.Review.Dubious {
					tag = "评审存疑（证据缺口，等级已封顶中危）"
				}
				rev = fmt.Sprintf("%s：%s", tag, upg.Review.Reason)
			}
		}
		statusLabel := map[string]string{"pending": "待处理", "in_progress": "处理中", "confirmed": "已确认",
			"resolved": "已处理", "fixed": "已修复", "false_positive": "误报", "ignored": "忽略",
			"duplicate": "重复", "risk_accepted": "风险接受"}[f.Status]
		doc.Paragraph(fmt.Sprintf("等级: %s ｜ %s ｜ 状态: %s ｜ 发现者: %s ｜ 时间: %s",
			strings.ToUpper(f.Severity), cvssTxt, statusLabel, f.Worker, f.CreatedAt.Format("2006-01-02 15:04")))
		if rev != "" {
			doc.Paragraph("评审结论: " + rev)
		}
		if f.Summary != "" {
			doc.Heading(3, "描述")
			writeSummaryDocx(doc, parseSummary(f.Summary))
		}
		if _, ec, _ := finalizeFindingForReport(f.Packet, f.Evidence); ec != "" {
			doc.Heading(3, "验证结论")
			doc.Paragraph(plainVerdict(f))
			doc.Heading(3, "验证过程")
			doc.CodeBlock(ec)
		}
		// 结构化证据（截图嵌图 / 命令输出）
		if evs, err := s.ListFindingEvidence(f.ID); err == nil {
			var shots []db.FindingEvidence
			for _, e := range evs {
				if e.Kind == "screenshot" {
					shots = append(shots, e)
					continue
				}
				var blk strings.Builder
				if e.Command != "" {
					blk.WriteString("命令: " + e.Command + "\n")
				}
				if e.Output != "" {
					blk.WriteString("输出:\n" + e.Output)
				}
				if blk.Len() > 0 {
					doc.Heading(3, "证据: "+firstNonEmpty(e.Note, e.Kind))
					doc.CodeBlock(blk.String())
				}
			}
			for _, e := range shots {
				if _, err := os.Stat(e.Path); err != nil {
					continue
				}
				caption := firstNonEmpty(e.Note, "证据截图")
				doc.Heading(3, "证据截图: "+caption)
				doc.Image(e.Path, caption)
			}
		}
		// 流量样本（已绑定的 HTTP 证据）
		if len(f.TrafficBindings) > 0 {
			doc.Heading(3, "流量证据")
			for _, b := range f.TrafficBindings {
				doc.Paragraph(fmt.Sprintf("[%s] %s %s", b.Role, b.Snapshot.Method, b.Snapshot.URL))
				if b.Snapshot.ReqHead != "" {
					doc.CodeBlock("> " + b.Snapshot.ReqHead)
				}
			}
		}
	}
	return doc
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// findingsAppendixMarkdown 漏洞中台附录：本任务 findings 表发现。
// 2026-11-23 重排版（用户反馈"导出的 md 格式不太美观"）：
//   - 报告头：标题 + 任务元信息 + 风险统计表 + 目录（HTML 锚点，渲染器无关）
//   - 等级用 emoji 徽标（🔴 严重…），状态中文化
//   - CVSS 与评审结论拆开：定级行只留分数，结论独立成引用块
//   - 验证过程里的 A/B 对照矩阵（| 开头行）自动提出代码块渲染成真表格
//   - 截图链接拼接 public_base_url（导出后平台外可看）
func (s *Server) findingsAppendixMarkdown(tID string) string {
	pid, err := strconv.ParseInt(tID, 10, 64)
	if err != nil || pid <= 0 {
		return ""
	}
	fs, err := s.m.pg.ListFindingsForExport(db.FindingFilter{}, nil)
	if err != nil {
		return ""
	}
	var own []*db.DBFinding
	for _, f := range fs {
		if f.TaskID != nil && *f.TaskID == pid {
			own = append(own, f)
		}
	}
	// 0 findings 但有攻击动作的任务（纯扫描类）也要出动作留痕附录。
	actionMD := s.taskActionRowsMarkdown(pid)
	if len(own) == 0 {
		return actionMD
	}
	sortFindingsBySeverity(own)

	sevLabel := map[string]string{
		"critical": "🔴 严重", "high": "🟠 高危", "medium": "🟡 中危",
		"low": "🔵 低危", "info": "⚪ 信息",
	}
	statusLabel := map[string]string{"pending": "待处理", "in_progress": "处理中", "confirmed": "已确认",
		"resolved": "已处理", "fixed": "已修复", "false_positive": "误报", "ignored": "忽略",
		"duplicate": "重复", "risk_accepted": "风险接受"}
	baseURL := s.notifyPublicBaseURL()

	var sb strings.Builder
	sb.WriteString("# 漏洞中台 · 渗透测试报告\n\n")
	if t := s.taskMetaLine(pid); t != "" {
		sb.WriteString(t + "\n\n")
	}

	// 风险统计
	counts := map[string]int{}
	for _, f := range own {
		counts[f.Severity]++
	}
	sb.WriteString("## 风险统计\n\n")
	sb.WriteString("| 等级 | 数量 |\n|---|---|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		fmt.Fprintf(&sb, "| %s | %d |\n", sevLabel[sev], counts[sev])
	}
	fmt.Fprintf(&sb, "| **合计** | **%d** |\n\n", len(own))

	// 目录（锚点用 <a id>，不依赖渲染器的中文锚点规则）
	sb.WriteString("## 目录\n\n")
	for i, f := range own {
		title := f.Name
		if title == "" {
			title = f.VulnClass
		}
		fmt.Fprintf(&sb, "%d. [%s](#f%d) `%s`\n", i+1, clipRunes(title, 60), i+1, sevLabel[strings.ToLower(f.Severity)])
	}
	sb.WriteString("\n---\n\n")

	for i, f := range own {
		title := f.Name
		if title == "" {
			title = f.VulnClass
		}
		sev := strings.ToLower(f.Severity)
		fmt.Fprintf(&sb, "<a id=\"f%d\"></a>\n\n### %d. %s %s\n\n", i+1, i+1, sevLabel[sev], title)

		// 元信息表
		cvssTxt := "未评审"
		review := ""
		if upg, uerr := s.GetFindingUpgrade(f.ID); uerr == nil && upg != nil {
			if upg.Cvss > 0 {
				cvssTxt = fmt.Sprintf("CVSS %.1f（%s）", upg.Cvss, upg.CvssVector)
			}
			if upg.Review != nil && upg.Review.Reason != "" {
				tag := "评审结论"
				if upg.Review.Dubious {
					tag = "评审存疑（等级封顶中危）"
				}
				review = fmt.Sprintf("**%s**：%s", tag, upg.Review.Reason)
			}
		}
		worker := f.Worker
		if worker == "" {
			worker = "-"
		}
		sb.WriteString("| 等级 | 定级 | 状态 | 发现者 | 时间 |\n|---|---|---|---|---|\n")
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n\n",
			sevLabel[sev], cvssTxt, statusLabel[f.Status], worker, f.CreatedAt.Format("01-02 15:04"))
		if review != "" {
			fmt.Fprintf(&sb, "> %s\n\n", review)
		}
		if f.Summary != "" {
			sb.WriteString("**描述**\n\n")
			fmt.Fprintf(&sb, "%s\n\n", reformatSummary(f.Summary))
		}
		pktClean, evClean, pktSynth := finalizeFindingForReport(f.Packet, f.Evidence)
		if pkt := strings.TrimSpace(pktClean); pkt != "" {
			fmt.Fprintf(&sb, "**POC 请求包**（复制进 Yakit/Burp Repeater 复现）：\n\n```http\n%s\n```\n\n", pkt)
		} else if pkt := strings.TrimSpace(pktSynth); pkt != "" {
			fmt.Fprintf(&sb, "**POC 请求包**（由验证命令转换，可直接重放）：\n\n```http\n%s\n```\n\n", pkt)
		}
		if evClean != "" {
			sb.WriteString("**验证过程与输出**\n\n")
			writeEvSegments(&sb, evClean)
		}
		if evs, eerr := s.ListFindingEvidence(f.ID); eerr == nil {
			for _, e := range evs {
				if e.Kind == "screenshot" && e.Path != "" {
					u := "/api/evidence/file?path=" + url.QueryEscape(e.Path)
					if baseURL != "" {
						u = baseURL + u
					}
					fmt.Fprintf(&sb, "![证据截图](%s)\n\n*证据截图：%s*\n\n", u, firstNonEmpty(e.Note, "repeater 捕获"))
				}
			}
		}
		if i < len(own)-1 {
			sb.WriteString("---\n\n")
		}
	}
	sb.WriteString("\n")
	if rows := s.taskActionRowsMarkdown(pid); rows != "" {
		sb.WriteString(rows)
	}
	return sb.String()
}

// writeEvSegments 把验证过程文本分段渲染：| 开头的连续行是 A/B 对照矩阵，
// 提出代码块按 markdown 表格渲染（此前整段包在 ``` 里，表格显示为纯文本）。
func writeEvSegments(sb *strings.Builder, ev string) {
	lines := strings.Split(ev, "\n")
	var codeBuf, tableBuf []string
	flushCode := func() {
		if len(codeBuf) > 0 {
			fmt.Fprintf(sb, "```\n%s\n```\n\n", strings.Join(codeBuf, "\n"))
			codeBuf = nil
		}
	}
	flushTable := func() {
		if len(tableBuf) > 0 {
			// 表体第二行若不是 |---| 分隔行，按首行列数自动补（否则渲染不出表格）
			if len(tableBuf) > 1 && !strings.HasPrefix(strings.TrimSpace(tableBuf[1]), "|---") {
				cols := strings.Count(tableBuf[0], "|") - 1
				if cols < 1 {
					cols = 1
				}
				sep := "|"
				for k := 0; k < cols; k++ {
					sep += "---|"
				}
				tableBuf = append(tableBuf[:1], append([]string{sep}, tableBuf[1:]...)...)
			}
			sb.WriteString(strings.Join(tableBuf, "\n") + "\n\n")
			tableBuf = nil
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "|") {
			flushCode()
			tableBuf = append(tableBuf, l)
		} else {
			flushTable()
			codeBuf = append(codeBuf, l)
		}
	}
	flushCode()
	flushTable()
}

// clipRunes 按字符数截断（中文安全）。
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// summaryParts 是 finding 描述的结构化拆解（md/word 共用）。
type summaryParts struct {
	Core   string   // 核心结论（一句）
	Body   []string // 主体要点
	Chain  []string // 攻击链步骤
	Advice []string // 修复建议
	Audit  []string // 审计细节（md 折叠 / word 小字灰段）
}

// parseSummary 把 agent 的机器审计体长描述拆成 summaryParts。
// agent 写法有固定模式（"升级链：A → B"、"修复建议：①…②…"、审计套话），
// 按标记词提取；主体长句按全角分号拆；结论性最强（含证明/定性动词）的
// 句子作核心；<200 字的短描述不折腾，Core 原样。
func parseSummary(s string) summaryParts {
	var p summaryParts
	if len([]rune(s)) < 200 {
		p.Core = s
		return p
	}
	if i := strings.Index(s, "升级链"); i >= 0 {
		seg := sentenceFrom(s[i:])
		if c := strings.TrimPrefix(strings.TrimPrefix(seg, "升级链"), "："); c != seg {
			p.Chain = splitChain(c)
			s = strings.Replace(s, seg, "", 1)
		}
	}
	if i := strings.Index(s, "修复建议"); i >= 0 {
		seg := sentenceFrom(s[i:])
		if c := strings.TrimPrefix(strings.TrimPrefix(seg, "修复建议"), "："); c != seg {
			p.Advice = splitCircled(c)
			s = strings.Replace(s, seg, "", 1)
		}
	}
	// 主体：先按句号拆，超长句再按全角分号拆
	var sents []string
	for _, sent := range splitSentences(s) {
		if len([]rune(sent)) > 120 && strings.Contains(sent, "；") {
			sents = append(sents, strings.Split(sent, "；")...)
		} else {
			sents = append(sents, sent)
		}
	}
	coreScore := func(t string) int {
		score := 0
		for _, kw := range []string{"证明", "等价于", "定性", "构成", "返回业务", "形成对照", "success:true"} {
			if strings.Contains(t, kw) {
				score++
			}
		}
		return score
	}
	best, bestScore := -1, -1
	for idx, t := range sents {
		if isAuditLine(strings.TrimSpace(t)) {
			continue
		}
		if sc := coreScore(t); sc > bestScore {
			best, bestScore = idx, sc
		}
	}
	for idx, t := range sents {
		t = strings.TrimRight(strings.TrimSpace(t), "；;")
		if t == "" {
			continue
		}
		if isAuditLine(t) {
			p.Audit = append(p.Audit, t)
		} else if idx == best {
			p.Core = t
		} else {
			p.Body = append(p.Body, t)
		}
	}
	if p.Core == "" && len(p.Body) > 0 {
		p.Core = p.Body[0]
		p.Body = p.Body[1:]
	}
	return p
}

// sentenceFrom 取从 s 开头到第一个句号（含）的片段；无句号取整串。
func sentenceFrom(s string) string {
	if i := strings.Index(s, "。"); i >= 0 {
		return s[:i+1]
	}
	return s
}

// splitChain 把 "A → B → C" 拆成步骤切片。
func splitChain(s string) []string {
	s = strings.TrimRight(strings.TrimSpace(s), "。")
	parts := strings.Split(s, "→")
	var out []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// splitCircled 按带圈序号（①②③…）拆条。
func splitCircled(s string) []string {
	markers := []string{"①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧"}
	start := -1
	for _, m := range markers {
		if i := strings.Index(s, m); i >= 0 && (start < 0 || i < start) {
			start = i
		}
	}
	if start < 0 {
		return []string{strings.TrimSpace(s)}
	}
	rest := s[start:]
	var out []string
	for _, m := range markers {
		i := strings.Index(rest, m)
		if i < 0 {
			continue
		}
		end := len(rest)
		for _, m2 := range markers {
			if j := strings.Index(rest[i+len(m):], m2); j >= 0 {
				if k := i + len(m) + j; k < end {
					end = k
				}
			}
		}
		out = append(out, strings.TrimSpace(rest[i+len(m):end]))
	}
	return out
}

// splitSentences 按句号切句（保留句号）。
func splitSentences(s string) []string {
	var out []string
	for _, part := range strings.Split(s, "。") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		out = append(out, part+"。")
	}
	return out
}

// isAuditLine 判别审计/红线/交接类语句（人类阅读时可折叠/弱化）。
func isAuditLine(t string) bool {
	for _, kw := range []string{"全程仅判别", "红线遵守", "红线", "占位", "留点交", "已向 running", "交接",
		"预算耗尽", "未触碰", "未提交任何", "探测共", "零写入", "无 traffic ID", "流量库无记录", "流量证据说明", "旁证"} {
		if strings.Contains(t, kw) {
			return true
		}
	}
	return false
}

// reformatSummary 渲染 md 版（结构化拆解 → markdown）。
func reformatSummary(s string) string {
	p := parseSummary(s)
	var sb strings.Builder
	if p.Core != "" {
		fmt.Fprintf(&sb, "**核心**：%s\n\n", p.Core)
	}
	for _, b := range p.Body {
		fmt.Fprintf(&sb, "- %s\n", b)
	}
	if len(p.Body) > 0 {
		sb.WriteString("\n")
	}
	if len(p.Chain) > 0 {
		sb.WriteString("**攻击链**\n\n")
		for i, step := range p.Chain {
			if i < len(p.Chain)-1 {
				fmt.Fprintf(&sb, "%s **→**\n", step)
			} else {
				fmt.Fprintf(&sb, "**%s**\n", step)
			}
		}
		sb.WriteString("\n")
	}
	if len(p.Advice) > 0 {
		sb.WriteString("**修复建议**\n\n")
		for _, a := range p.Advice {
			fmt.Fprintf(&sb, "- %s\n", a)
		}
		sb.WriteString("\n")
	}
	if len(p.Audit) > 0 {
		sb.WriteString("<details>\n<summary>技术判别细节（审计用）</summary>\n\n")
		for _, a := range p.Audit {
			fmt.Fprintf(&sb, "- %s\n", a)
		}
		sb.WriteString("\n</details>\n\n")
	}
	return sb.String()
}

// writeSummaryDocx 把结构化描述渲染进 Word：核心结论 + 要点 + 攻击链 +
// 修复建议；审计细节用代码块小字呈现（弱化但保留可审计性）。
func writeSummaryDocx(doc *Docx, p summaryParts) {
	if p.Core != "" {
		doc.FieldLine("核心结论", p.Core)
	}
	for _, b := range p.Body {
		doc.Paragraph("· " + b)
	}
	if len(p.Chain) > 0 {
		doc.Heading(4, "攻击链")
		for i, step := range p.Chain {
			if i < len(p.Chain)-1 {
				doc.Paragraph(step + " →")
			} else {
				doc.Paragraph(step)
			}
		}
	}
	if len(p.Advice) > 0 {
		doc.Heading(4, "修复建议")
		for _, a := range p.Advice {
			doc.Paragraph("· " + a)
		}
	}
	if len(p.Audit) > 0 {
		doc.Heading(4, "技术判别细节（审计用）")
		var b strings.Builder
		for _, a := range p.Audit {
			b.WriteString(a + "\n")
		}
		doc.CodeBlock(b.String())
	}
}

// taskMetaLine 报告头元信息（任务名/目标/时间）。
func (s *Server) taskMetaLine(pid int64) string {
	var name, goal string
	if err := s.m.PG().QueryRow(`SELECT name, COALESCE(goal,'') FROM tasks WHERE id=$1`, pid).Scan(&name, &goal); err != nil {
		return ""
	}
	if name == "" {
		name = "未命名任务"
	}
	out := fmt.Sprintf("**任务**：%s（#%d） · **生成时间**：%s", name, pid, time.Now().Format("2006-01-02 15:04"))
	if goal != "" {
		out += fmt.Sprintf(" · **目标**：%s", clipRunes(goal, 80))
	}
	return out
}

// taskActionRowsMarkdown 攻击动作留痕（markdown 版）：按任务 id 查探索图
// kind=action 节点，输出与 Word 报告同源的时间线表格。
func (s *Server) taskActionRowsMarkdown(pid int64) string {
	var expID int64
	if err := s.m.PG().QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, pid).Scan(&expID); err != nil {
		return ""
	}
	t := &Task{ExpID: expID}
	rows := s.taskActionRows(t)
	if len(rows) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("## 攻击动作留痕\n\n")
	fmt.Fprintf(&sb, "本任务执行链路上的关键攻击动作（自动留痕），共 %d 条：\n\n", len(rows))
	sb.WriteString("| 时间 | 动作类型 | 动作内容 | 目标 | 结果 |\n|---|---|---|---|---|\n")
	for _, r := range rows {
		summary := strings.ReplaceAll(r.Summary, "|", "\\|")
		detail := strings.ReplaceAll(r.Detail, "|", "\\|")
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n", r.TS, r.Type, summary, detail, r.Result)
	}
	sb.WriteString("\n")
	return sb.String()
}

// evidenceFile 服务证据文件：GET /api/evidence/file?path=...
// 限 data 目录内 + 扩展名白名单（截图/文本类），杜绝路径穿越。
func (s *Server) evidenceFile(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" {
		writeErr(w, 400, "path 必填")
		return
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		writeErr(w, 400, "path 非法")
		return
	}
	root, rerr := filepath.Abs(s.m.dir)
	if rerr != nil || !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		writeErr(w, 400, "path 越界")
		return
	}
	ext := strings.ToLower(filepath.Ext(abs))
	allowed := map[string]string{
		".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".html": "text/html; charset=utf-8", ".txt": "text/plain; charset=utf-8",
		".log": "text/plain; charset=utf-8",
	}
	ct, ok := allowed[ext]
	if !ok {
		writeErr(w, 400, "不支持的证据类型")
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		writeErr(w, 404, "证据文件不存在")
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(data)
}
