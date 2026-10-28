package server

// vulns.go — 漏洞中枢 HTTP API 与 Markdown 导出（渲染格式移植自
// Full-Chain-Sentinel-System vulnerability-markdown.ts，MIT：等级行标注
// 「代理自评/评审存疑」，代码块 fence 长度自适应防破版）。

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) vulnStore() *db.VulnStore {
	if s.m == nil || s.m.PG() == nil {
		return nil
	}
	return s.m.pg.Vulns()
}

func (s *Server) registerVulnRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/vulns", s.vulnList)
	mux.HandleFunc("POST /api/vulns", s.vulnCreateByOperator)
	mux.HandleFunc("GET /api/vulns/export", s.vulnExport)
	mux.HandleFunc("GET /api/vulns/{id}", s.vulnGet)
	mux.HandleFunc("PATCH /api/vulns/{id}", s.vulnPatch)
	mux.HandleFunc("POST /api/vulns/{id}/notes", s.vulnAddNote)
	mux.HandleFunc("POST /api/vulns/{id}/review", s.vulnRequeueReview)
}

func (s *Server) vulnList(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	if vs == nil {
		writeErr(w, 503, "数据库不可用")
		return
	}
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
	list, err := vs.ListVulns(db.VulnFilters{
		TaskID: taskID, Status: q.Get("status"), Severity: q.Get("severity"),
		Target: q.Get("target"), Search: q.Get("q"),
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []*db.Vuln{}
	}
	writeJSON(w, 200, map[string]any{"items": list, "count": len(list)})
}

func (s *Server) vulnGet(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	v, err := vs.GetVuln(id)
	if err != nil || v == nil {
		writeErr(w, 404, "记录不存在")
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) vulnPatch(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body struct{ Status, Note string }
	if err := decode(r, &body); err != nil || body.Status == "" {
		writeErr(w, 400, "status 必填")
		return
	}
	switch body.Status {
	case "pending", "confirmed", "false_positive", "fixed":
	default:
		writeErr(w, 400, "status 仅支持 pending/confirmed/false_positive/fixed")
		return
	}
	if err := vs.PatchVulnStatus(id, body.Status, "操作员", body.Note); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	v, _ := vs.GetVuln(id)
	writeJSON(w, 200, v)
}

func (s *Server) vulnAddNote(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body struct{ Text string }
	if err := decode(r, &body); err != nil || strings.TrimSpace(body.Text) == "" {
		writeErr(w, 400, "text 必填")
		return
	}
	if err := vs.AddVulnNote(id, "操作员", body.Text); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) vulnRequeueReview(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := vs.RequeueReview(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// vulnCreateByOperator 允许操作员手工补录（无 agent 场景），字段同 vuln_submit。
func (s *Server) vulnCreateByOperator(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	var v db.VulnCreate
	if err := decode(r, &v); err != nil || v.Title == "" || v.Severity == "" {
		writeErr(w, 400, "title/severity 必填")
		return
	}
	created, err := vs.CreateVuln(v)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, created)
}

// ---------- Markdown 导出 ----------

var vulnStatusLabels = map[string]string{
	"pending": "待确认", "confirmed": "已确认", "false_positive": "误报", "fixed": "已修复",
}
var vulnSeverityLabels = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
}

// fence 生成比正文最长反引号串更长的围栏（哨兵原版逻辑）。
func fence(body, lang string) string {
	longest := 0
	run := 0
	for _, c := range body {
		if c == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n) + lang + "\n" + strings.TrimRight(body, " \t\n") + "\n" + strings.Repeat("`", n)
}

func vulnRatingNote(v *db.Vuln) string {
	if v.Review == nil {
		return "代理自评（未评审）"
	}
	switch v.Review.State {
	case "failed":
		return "代理自评（未评审）"
	case "queued", "running":
		return "代理自评（评审中）"
	}
	if v.Review.Dubious {
		return "评审存疑"
	}
	return ""
}

func (s *Server) vulnExport(w http.ResponseWriter, r *http.Request) {
	vs := s.vulnStore()
	q := r.URL.Query()
	taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
	list, err := vs.ListVulns(db.VulnFilters{TaskID: taskID})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var sb strings.Builder
	sb.WriteString("# 渗透测试漏洞报告\n\n")
	title := "全部记录"
	if taskID != 0 {
		title = fmt.Sprintf("任务 #%d", taskID)
	}
	fmt.Fprintf(&sb, "- 范围：%s（%d 条）\n\n---\n\n", title, len(list))
	for i, row := range list {
		v, err := vs.GetVuln(row.ID)
		if err != nil || v == nil {
			continue
		}
		fmt.Fprintf(&sb, "## %d. %s %s\n\n", i+1, v.Label, v.Title)
		line := fmt.Sprintf("- 等级：%s（%s）· CVSS %.1f", vulnSeverityLabels[v.Severity], v.Severity, v.Cvss)
		if note := vulnRatingNote(v); note != "" {
			line += " · " + note
		}
		if v.CvssVector != "" {
			line += " · " + v.CvssVector
		}
		sb.WriteString(line + "\n")
		fmt.Fprintf(&sb, "- 状态：%s\n", vulnStatusLabels[v.Status])
		fmt.Fprintf(&sb, "- 目标：%s\n", v.Target)
		if v.Category != "" {
			fmt.Fprintf(&sb, "- 类型：%s\n", v.Category)
		}
		if v.Platform == "android" {
			fmt.Fprintf(&sb, "- 平台：安卓（App）· 包名 `%s`", v.AppPackage)
			if v.AppVersion != "" {
				fmt.Fprintf(&sb, " · 版本 %s", v.AppVersion)
			}
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "- 来源：%s\n- 提交时间：%s\n", v.Source, v.CreatedAt.Format("2006-01-02 15:04:05"))
		if v.Review != nil && v.Review.State == "done" {
			fmt.Fprintf(&sb, "- 评审：%s\n", v.Review.Reason)
		}
		sb.WriteString("\n### 漏洞详情\n\n" + v.Description + "\n\n")
		if strings.TrimSpace(v.Packet) != "" {
			sb.WriteString("### 原始数据包\n\n" + fence(v.Packet, "") + "\n\n")
		}
		if v.Repro != "" {
			sb.WriteString("### 复现步骤\n\n" + v.Repro + "\n\n")
		}
		if len(v.Evidence) > 0 {
			sb.WriteString("### 证据\n\n")
			for j, e := range v.Evidence {
				fmt.Fprintf(&sb, "%d. %s\n", j+1, e.Note)
				if e.Command != "" {
					sb.WriteString("\n命令：\n\n" + fence(e.Command, "sh") + "\n\n")
				}
				if e.Output != "" {
					sb.WriteString("\n输出：\n\n" + fence(e.Output, "") + "\n\n")
				}
				if e.Kind == "file" && e.Path != "" {
					fmt.Fprintf(&sb, "\n- 文件：`%s`\n", e.Path)
				}
				if e.Kind == "screenshot" && e.Path != "" {
					fmt.Fprintf(&sb, "\n![截图](%s)\n\n> %s\n", e.Path, e.Note)
				}
			}
			sb.WriteString("\n")
		}
		if v.Remediation != "" {
			sb.WriteString("### 修复建议\n\n" + v.Remediation + "\n\n")
		}
		if len(v.Notes) > 0 {
			sb.WriteString("### 处理时间线\n\n")
			for _, n := range v.Notes {
				fmt.Fprintf(&sb, "- %s %s：%s\n", n.At.Format("01-02 15:04"), n.Author, n.Text)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("---\n\n")
	}

	format := q.Get("format") // md（默认）/ docx
	filename := fmt.Sprintf("FORANG-vuln-report-%s.md", time.Now().Format("20060102"))
	if taskID != 0 {
		filename = fmt.Sprintf("FORANG-task%d-vuln-report-%s.md", taskID, time.Now().Format("20060102"))
	}
	if format == "docx" {
		dx := buildVulnDocx(title, list, vs)
		b, err := dx.Build()
		if err != nil {
			writeErr(w, 500, "Word 生成失败: "+err.Error())
			return
		}
		filename = strings.TrimSuffix(filename, ".md") + ".docx"
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(sb.String()))
}

// buildVulnDocx 把漏洞清单渲染为 Word 文档（与 MD 版同结构）。
func buildVulnDocx(scope string, list []*db.Vuln, vs *db.VulnStore) *Docx {
	dx := NewDocx()
	dx.Heading(1, "FORANG 渗透测试漏洞报告")
	dx.Paragraph(fmt.Sprintf("**范围**：%s　·　**漏洞数**：%d　·　**生成时间**：%s", scope, len(list), time.Now().Format("2006-01-02 15:04")))
	dx.PageBreak()

	for i, row := range list {
		v, err := vs.GetVuln(row.ID)
		if err != nil || v == nil {
			continue
		}
		dx.Heading(2, fmt.Sprintf("%d. %s %s", i+1, v.Label, v.Title))

		dx.Table(
			[]string{"属性", "值"},
			[][]string{
				{"等级", fmt.Sprintf("%s（CVSS %.1f）", vulnSeverityLabels[v.Severity], v.Cvss)},
				{"状态", vulnStatusLabels[v.Status]},
				{"目标", v.Target},
				{"类型", v.Category},
				{"来源", v.Source},
				{"提交时间", v.CreatedAt.Format("2006-01-02 15:04")},
				{"定级来源", vulnRatingNote(v)},
			},
		)

		if v.Review != nil && v.Review.State == "done" {
			dx.Heading(3, "评审员结论")
			dx.Paragraph(v.Review.Reason)
		}

		dx.Heading(3, "漏洞详情")
		dx.Paragraph(v.Description)

		if strings.TrimSpace(v.Packet) != "" {
			dx.Heading(3, "原始数据包")
			dx.CodeBlock(v.Packet)
		}
		if v.Repro != "" {
			dx.Heading(3, "复现步骤")
			dx.Paragraph(v.Repro)
		}
		if len(v.Evidence) > 0 {
			dx.Heading(3, "证据")
			for _, e := range v.Evidence {
				dx.Paragraph("• " + e.Note)
				if e.Command != "" {
					dx.CodeBlock("$ " + e.Command)
				}
				if e.Output != "" {
					dx.CodeBlock(e.Output)
				}
				if e.Kind == "screenshot" && e.Path != "" {
					dx.Image(e.Path, e.Note) // 嵌入截图到 Word
				}
			}
		}
		if v.Remediation != "" {
			dx.Heading(3, "修复建议")
			dx.Paragraph(v.Remediation)
		}
		if len(v.Notes) > 0 {
			dx.Heading(3, "处理时间线")
			for _, n := range v.Notes {
				dx.Paragraph(fmt.Sprintf("%s %s：%s", n.At.Format("01-02 15:04"), n.Author, n.Text))
			}
		}
		if i < len(list)-1 {
			dx.PageBreak()
		}
	}
	return dx
}
