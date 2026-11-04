package server

// report_visual_test.go — 报告结构冒烟：生成样例 docx 供人工/渲染验收。
// go test ./server/ -run TestReportVisualSample --path=xxx.docx 生成到指定路径。
import (
	"os"
	"testing"
)

func TestReportVisualSample(t *testing.T) {
	out := os.Getenv("REPORT_OUT")
	if out == "" {
		t.Skip("REPORT_OUT 未设置，跳过样例生成")
	}
	d := NewDocx()
	d.SetHeader("密级：商业机密")
	d.CoverPage("视频业务智能分析系统", "渗透测试报告", [][2]string{
		{"文档编号", "FORANG-313-20261104"},
		{"密级", "商业机密"},
		{"版本编号", "V1.0"},
		{"日期", "2026-11-04"},
	}, "© 2026 FORANG 自主渗透测试平台")
	d.TOCPage()
	d.Heading(1, "1. 目标信息")
	d.Heading(2, "1.1 资产列表")
	d.Table([]string{"序号", "资产"}, [][]string{{"1", "http://target.example.com"}})
	d.Heading(1, "3. 漏洞信息")
	d.Heading(2, "3.1 风险概览")
	d.TableRich([]string{"危险等级", "数量"}, [][]CellSpec{
		{{Text: "高", Color: sevColorOf("高"), Bold: true}, {Text: "1"}},
		{{Text: "中", Color: sevColorOf("中"), Bold: true}, {Text: "1"}},
	})
	d.Heading(2, "3.2 漏洞汇总")
	d.TableRich([]string{"编号", "漏洞名称", "危险等级", "相关URL"}, [][]CellSpec{
		strRow{"3.3", "未授权访问", "高", "http://t.example.com/api/admin"}.rowSpec(),
	})
	d.PageBreak()
	d.VulnHeading(3, "高", "未授权访问")
	d.FieldLine("漏洞描述：", "管理接口可被未授权调用，导致敏感数据泄露。")
	d.FieldLine("相关URL：", "")
	d.Paragraph("http://t.example.com/api/admin/users")
	d.FieldLine("POC请求包：", "以下为可直接重放的原始 HTTP 请求")
	d.CodeBlock("GET /api/admin/users HTTP/1.1\nHost: t.example.com\nUser-Agent: Mozilla/5.0\n\n")
	d.FieldLine("加固建议：", "为相关接口启用强认证与访问控制。")
	d.PageBreak()
	d.Heading(1, "5. 建议总结")
	d.Paragraph("针对本次测试发现的安全问题，建议从以下方面加强系统安全防护。")

	b, err := d.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("written:", out, len(b), "bytes")
}

// rowSpec 把 [4]string 字面量转 CellSpec 行（测试便捷用）。
type strRow [4]string

func (r strRow) rowSpec() []CellSpec {
	return []CellSpec{{Text: r[0]}, {Text: r[1]}, {Text: r[2], Color: sevColorOf(r[2]), Bold: true}, {Text: r[3]}}
}
