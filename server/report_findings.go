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
	doc.Paragraph("任务: " + t.Description)
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
			doc.Paragraph(f.Summary)
		}
		if f.Evidence != "" {
			doc.Heading(3, "证据/PoC")
			doc.CodeBlock(f.Evidence)
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

// findingsAppendixMarkdown 漏洞中台附录：本任务 findings 表发现
// （评审 CVSS/结论 + 截图证据以 /api/evidence/file 链接内嵌）。
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
	if len(own) == 0 {
		return ""
	}
	sortFindingsBySeverity(own)
	var sb strings.Builder
	sb.WriteString("## 漏洞中台 · 发现明细\n\n")
	for i, f := range own {
		title := f.Name
		if title == "" {
			title = f.VulnClass
		}
		fmt.Fprintf(&sb, "### %d. %s\n\n", i+1, title)
		cvssTxt := "未评审"
		if upg, uerr := s.GetFindingUpgrade(f.ID); uerr == nil && upg != nil {
			if upg.Cvss > 0 {
				cvssTxt = fmt.Sprintf("CVSS %.1f（%s）", upg.Cvss, upg.CvssVector)
			}
			if upg.Review != nil && upg.Review.Reason != "" {
				cvssTxt += " — 评审结论: " + upg.Review.Reason
			}
		}
		fmt.Fprintf(&sb, "- 等级: %s\n- 定级: %s\n- 状态: %s\n\n", strings.ToUpper(f.Severity), cvssTxt, f.Status)
		if f.Summary != "" {
			fmt.Fprintf(&sb, "%s\n\n", f.Summary)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&sb, "```\n%s\n```\n\n", f.Evidence)
		}
		if evs, eerr := s.ListFindingEvidence(f.ID); eerr == nil {
			for _, e := range evs {
				if e.Kind == "screenshot" && e.Path != "" {
					fmt.Fprintf(&sb, "![证据截图](/api/evidence/file?path=%s)\n\n", url.QueryEscape(e.Path))
				}
			}
		}
	}
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
