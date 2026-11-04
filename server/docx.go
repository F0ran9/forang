package server

// docx.go — 极简 OOXML .docx 生成器（专业渗透测试报告版）。
// 无外部依赖：archive/zip + 手写 WordprocessingML。
// 参照行业交付模板（绿盟/长亭类）：表格式封面、目录域、页眉密级、页脚页码、
// 品牌色标题体系、等级配色漏洞小节、等比截图、代码框、汇总表。

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// 品牌色（报告体系）：主色墨绿 + 中性灰阶；等级色沿用行业惯例。
const (
	docxBrandColor  = "006B54" // 主色：墨绿（标题/表头/横线）
	docxInkColor    = "1A1A1A" // 正文近黑
	docxGrayColor   = "595959" // 辅助灰（图注/页脚）
	docxLineGray    = "C9D2D8" // 表格线
	docxCodeBg      = "F6F8FA" // 代码框底
	docxCodeBorder  = "D0D7DE" // 代码框边
	docxMetaLabelBg = "EEF3F1" // 封面信息栏标签底
)

// 等级色（漏洞标题【】、汇总表等级列）。
var sevColor = map[string]string{
	"严重": "B30000", "高": "E02E2E", "中": "E8890C", "低": "2E7CD6", "信息": "808080",
	"critical": "B30000", "high": "E02E2E", "medium": "E8890C", "low": "2E7CD6", "info": "808080",
}

func sevColorOf(label string) string {
	if c, ok := sevColor[label]; ok {
		return c
	}
	return docxInkColor
}

// Docx 是一个正在构建的 Word 文档。
type Docx struct {
	body   strings.Builder
	images []docxImage // 待嵌入的图片
	header string      // 每页页眉右侧文字（密级标识等）；空=默认内部资料
}

// SetHeader 设置每页页眉右侧文字（密级标识）。左侧固定为报告名。
func (d *Docx) SetHeader(text string) *Docx {
	d.header = strings.TrimSpace(text)
	return d
}

type docxImage struct {
	rID   string
	name  string
	bytes []byte
}

// NewDocx 创建空文档（A4 纵向）。
func NewDocx() *Docx { return &Docx{} }

// ---------- 低层 run 工具 ----------

func runText(text, color string, bold bool, szHalf int, fontEast string) string {
	rPr := `<w:rPr>`
	if fontEast != "" {
		rPr += fmt.Sprintf(`<w:rFonts w:eastAsia="%s" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>`, fontEast)
	}
	if bold {
		rPr += `<w:b/>`
	}
	if color != "" && color != docxInkColor {
		rPr += fmt.Sprintf(`<w:color w:val="%s"/>`, color)
	}
	if szHalf > 0 {
		rPr += fmt.Sprintf(`<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, szHalf, szHalf)
	}
	rPr += `</w:rPr>`
	return fmt.Sprintf(`<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>`, rPr, xmlEscape(text))
}

// ---------- 结构元素 ----------

// CoverPage 专业封面：系统名 + 报告类型大标题 + 信息栏 + 底部版权。
func (d *Docx) CoverPage(sysName, docType string, meta [][2]string, copyright string) *Docx {
	for i := 0; i < 5; i++ {
		d.body.WriteString(`<w:p/>`)
	}
	d.body.WriteString(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="240"/></w:pPr>`)
	d.body.WriteString(runText(sysName, "333333", false, 52, "黑体"))
	d.body.WriteString(`</w:p>`)
	d.body.WriteString(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="120"/></w:pPr>`)
	d.body.WriteString(runText(docType, docxBrandColor, true, 88, "黑体"))
	d.body.WriteString(`</w:p>`)
	d.body.WriteString(`<w:p><w:pPr><w:jc w:val="center"/></w:pPr>`)
	d.body.WriteString(runText("Penetration Test Report", docxGrayColor, false, 21, ""))
	d.body.WriteString(`</w:p>`)
	for i := 0; i < 5; i++ {
		d.body.WriteString(`<w:p/>`)
	}
	if len(meta) > 0 {
		d.body.WriteString(`<w:tbl><w:tblPr><w:jc w:val="center"/><w:tblW w:w="5880" w:type="dxa"/><w:tblBorders>`)
		for _, edge := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
			d.body.WriteString(fmt.Sprintf(`<w:%s w:val="single" w:sz="4" w:color="%s"/>`, edge, docxLineGray))
		}
		d.body.WriteString(`</w:tblBorders></w:tblPr><w:tblGrid><w:gridCol w:w="2200"/><w:gridCol w:w="3680"/></w:tblGrid>`)
		for _, kv := range meta {
			d.body.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>`)
			d.body.WriteString(fmt.Sprintf(`<w:tc><w:tcPr><w:tcW w:w="2200" w:type="dxa"/><w:shd w:val="clear" w:fill="%s"/></w:tcPr><w:p><w:pPr><w:spacing w:before="60" w:after="60"/></w:pPr>%s</w:p></w:tc>`,
				docxMetaLabelBg, runText("■ "+kv[0], docxInkColor, true, 21, "宋体")))
			d.body.WriteString(fmt.Sprintf(`<w:tc><w:tcPr><w:tcW w:w="3680" w:type="dxa"/></w:tcPr><w:p><w:pPr><w:spacing w:before="60" w:after="60"/></w:pPr>%s</w:p></w:tc>`,
				runText(kv[1], docxInkColor, false, 21, "宋体")))
			d.body.WriteString(`</w:tr>`)
		}
		d.body.WriteString(`</w:tbl>`)
	}
	for i := 0; i < 6; i++ {
		d.body.WriteString(`<w:p/>`)
	}
	if copyright != "" {
		d.body.WriteString(`<w:p><w:pPr><w:jc w:val="center"/></w:pPr>`)
		d.body.WriteString(runText(copyright, docxGrayColor, false, 18, "宋体"))
		d.body.WriteString(`</w:p>`)
	}
	d.PageBreak()
	return d
}

// TOCPage 目录页：目录域（打开文档后 Word 提示更新域生成页码）。
func (d *Docx) TOCPage() *Docx {
	d.body.WriteString(`<w:p><w:pPr><w:spacing w:before="120" w:after="240"/></w:pPr>`)
	d.body.WriteString(runText("目  录", docxBrandColor, true, 32, "黑体"))
	d.body.WriteString(`</w:p>`)
	d.body.WriteString(`<w:p><w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>`)
	d.body.WriteString(`<w:r><w:instrText xml:space="preserve"> TOC \o "1-2" \h \z \u </w:instrText></w:r>`)
	d.body.WriteString(`<w:r><w:fldChar w:fldCharType="separate"/></w:r>`)
	d.body.WriteString(runText("（目录为域：打开文档后按提示更新域，或全选后按 F9，即可生成带页码的目录）", docxGrayColor, false, 18, "宋体"))
	d.body.WriteString(`<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`)
	d.PageBreak()
	return d
}

// Heading 添加标题（level 1-4，品牌色样式；进目录大纲）。
func (d *Docx) Heading(level int, text string) *Docx {
	style := fmt.Sprintf("Heading%d", level)
	d.body.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:pStyle w:val="%s"/></w:pPr>%s</w:p>`,
		style, runText(text, "", true, 0, "")))
	return d
}

// VulnHeading 漏洞小节标题：编号 + 等级色【】+ 名称（Heading2 样式，进目录）。
func (d *Docx) VulnHeading(numIdx int, sev, title string) *Docx {
	d.body.WriteString(`<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr>`)
	d.body.WriteString(runText(fmt.Sprintf("3.%d ", numIdx), "", true, 0, ""))
	d.body.WriteString(runText(fmt.Sprintf("【%s】", sev), sevColorOf(sev), true, 0, ""))
	d.body.WriteString(runText(title, "", true, 0, ""))
	d.body.WriteString(`</w:p>`)
	return d
}

// Paragraph 添加正文段落（支持 **加粗** 内联标记；两端对齐 1.3 倍行距）。
func (d *Docx) Paragraph(text string) *Docx {
	d.body.WriteString(`<w:p><w:pPr><w:jc w:val="both"/><w:spacing w:line="312" w:lineRule="auto"/></w:pPr>`)
	d.body.WriteString(runsFromMarkdown(text))
	d.body.WriteString(`</w:p>`)
	return d
}

// GoalLine 目标/范围文本行：编号行（1) 2)…、①、-、•）加左缩进；长 token 场景
// 用左对齐（jc both 会把无空格断行的长串撑得字距极大）。
func (d *Docx) GoalLine(text string) *Docx {
	indent := ""
	if r := []rune(text); len(r) > 1 {
		c, c2 := r[0], r[1]
		numbered := (c >= '0' && c <= '9' && (c2 == ')' || c2 == '.' || c2 == '、'))
		bullet := c == '-' || c == '•' || c == '①' || c == '·' // -、•、①、· 类要点符
		if numbered || bullet {
			indent = `<w:ind w:left="360"/>`
		}
	}
	d.body.WriteString(`<w:p><w:pPr><w:spacing w:line="312" w:lineRule="auto"/>` + indent + `</w:pPr>`)
	d.body.WriteString(runsFromMarkdown(text))
	d.body.WriteString(`</w:p>`)
	return d
}

// FieldLine 字段行：加粗深色标签 + 常规内容（「漏洞描述： xxx」）。
func (d *Docx) FieldLine(label, text string) *Docx {
	d.body.WriteString(`<w:p><w:pPr><w:spacing w:before="160" w:after="80" w:line="312" w:lineRule="auto"/><w:keepNext/></w:pPr>`)
	d.body.WriteString(runText(label, "262626", true, 24, "宋体"))
	if text != "" {
		d.body.WriteString(runText(text, docxInkColor, false, 24, "宋体"))
	}
	d.body.WriteString(`</w:p>`)
	return d
}

// CodeBlock 报文/代码框：单元格表格，灰底细边框，Consolas 8.5pt。
func (d *Docx) CodeBlock(text string) *Docx {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) == 0 {
		return d
	}
	if len(lines) > 400 {
		lines = append(lines[:400], "…（内容过长已截断）")
	}
	d.body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>`)
	for _, edge := range []string{"top", "left", "bottom", "right"} {
		d.body.WriteString(fmt.Sprintf(`<w:%s w:val="single" w:sz="4" w:color="%s"/>`, edge, docxCodeBorder))
	}
	d.body.WriteString(`</w:tblBorders><w:tblCellMar><w:top w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid><w:gridCol w:w="9062"/></w:tblGrid>`)
	d.body.WriteString(fmt.Sprintf(`<w:tr><w:tc><w:tcPr><w:shd w:val="clear" w:fill="%s"/></w:tcPr>`, docxCodeBg))
	for _, ln := range lines {
		if ln == "" {
			ln = " "
		}
		d.body.WriteString(fmt.Sprintf(
			`<w:p><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="宋体"/><w:sz w:val="17"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="宋体"/><w:sz w:val="17"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
			xmlEscape(ln)))
	}
	d.body.WriteString(`</w:tc></w:tr></w:tbl><w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>`)
	return d
}

// CellSpec 富单元格（汇总表用：等级配色等）。
type CellSpec struct {
	Text  string
	Color string
	Bold  bool
}

// Table 标准表格：品牌色表头（白字）+ 细灰线。
func (d *Docx) Table(headers []string, rows [][]string) *Docx {
	rich := make([][]CellSpec, 0, len(rows))
	for _, r := range rows {
		cr := make([]CellSpec, len(r))
		for i, c := range r {
			cr[i] = CellSpec{Text: c}
		}
		rich = append(rich, cr)
	}
	return d.TableRich(headers, rich)
}

// TableRich 富单元格表格（支持单元格配色/加粗）。
func (d *Docx) TableRich(headers []string, rows [][]CellSpec) *Docx {
	d.body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>`)
	for _, edge := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		d.body.WriteString(fmt.Sprintf(`<w:%s w:val="single" w:sz="4" w:color="%s"/>`, edge, docxLineGray))
	}
	d.body.WriteString(`</w:tblBorders><w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr>`)
	nCols := len(headers)
	if nCols == 0 {
		nCols = 1
	}
	colW := 9062 / nCols
	d.body.WriteString(`<w:tblGrid>`)
	for i := 0; i < nCols; i++ {
		d.body.WriteString(fmt.Sprintf(`<w:gridCol w:w="%d"/>`, colW))
	}
	d.body.WriteString(`</w:tblGrid>`)
	d.body.WriteString(`<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>`)
	for _, h := range headers {
		d.body.WriteString(fmt.Sprintf(
			`<w:tc><w:tcPr><w:shd w:val="clear" w:fill="%s"/></w:tcPr><w:p><w:pPr><w:spacing w:before="20" w:after="20"/></w:pPr>%s</w:p></w:tc>`,
			docxBrandColor, runText(h, "FFFFFF", true, 21, "黑体")))
	}
	d.body.WriteString(`</w:tr>`)
	for _, row := range rows {
		d.body.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>`)
		for _, cell := range row {
			d.body.WriteString(fmt.Sprintf(
				`<w:tc><w:p><w:pPr><w:spacing w:before="20" w:after="20"/></w:pPr>%s</w:p></w:tc>`,
				runText(cell.Text, cell.Color, cell.Bold, 21, "宋体")))
		}
		d.body.WriteString(`</w:tr>`)
	}
	d.body.WriteString(`</w:tbl><w:p><w:pPr><w:spacing w:after="0"/></w:pPr></w:p>`)
	return d
}

// HRule 品牌色粗分隔线（Heading1 样式已自带底线，此方法供额外分隔用）。
func (d *Docx) HRule() *Docx {
	d.body.WriteString(fmt.Sprintf(`<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="12" w:space="2" w:color="%s"/></w:pBdr><w:spacing w:after="120"/></w:pPr></w:p>`, docxBrandColor))
	return d
}

// pngSize 解析 PNG IHDR 真实宽高（等比缩放用）。
func pngSize(b []byte) (int, int) {
	if len(b) < 24 || string(b[1:4]) != "PNG" {
		return 0, 0
	}
	return int(binary.BigEndian.Uint32(b[16:20])), int(binary.BigEndian.Uint32(b[20:24]))
}

// Image 嵌入 PNG 截图（按 IHDR 等比缩放至页宽内，居中 + 图注）。
func (d *Docx) Image(path string, caption string) *Docx {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 100 {
		return d
	}
	idx := len(d.images) + 1
	img := docxImage{
		rID:   fmt.Sprintf("rIdImg%d", idx),
		name:  fmt.Sprintf("word/media/image%d.png", idx),
		bytes: b,
	}
	d.images = append(d.images, img)

	wEMU, hEMU := int64(5250000), int64(2953125)
	if pw, ph := pngSize(b); pw > 0 && ph > 0 {
		wEMU, hEMU = int64(pw)*9525, int64(ph)*9525 // px → EMU (96dpi)
		if wEMU > 5250000 {
			hEMU = hEMU * 5250000 / wEMU
			wEMU = 5250000
		}
		if hEMU > 7800000 {
			wEMU = wEMU * 7800000 / hEMU
			hEMU = 7800000
		}
	}
	d.body.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="80"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="Image%d"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="%d" name="image%d.png"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="%s" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`,
		wEMU, hEMU, idx, idx, idx, idx, img.rID, wEMU, hEMU))
	if caption != "" {
		d.body.WriteString(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="120"/></w:pPr>`)
		d.body.WriteString(runText("▲ "+caption, docxGrayColor, false, 18, "宋体"))
		d.body.WriteString(`</w:p>`)
	}
	return d
}

// PageBreak 插入分页符。
func (d *Docx) PageBreak() *Docx {
	d.body.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
	return d
}

// ---------- 打包 ----------

// Build 生成 .docx 字节流。
func (d *Docx) Build() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	ct := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
  <Override PartName="/word/headerFirst.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
  <Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
  <Override PartName="/word/footerFirst.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
</Types>`
	if err := writeZipEntry(zw, "[Content_Types].xml", ct); err != nil {
		return nil, err
	}

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	if err := writeZipEntry(zw, "_rels/.rels", rels); err != nil {
		return nil, err
	}

	docRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
	docRels += `<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`
	docRels += `<Relationship Id="rIdHdr1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>`
	docRels += `<Relationship Id="rIdHdrF" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="headerFirst.xml"/>`
	docRels += `<Relationship Id="rIdFtr1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>`
	docRels += `<Relationship Id="rIdFtrF" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footerFirst.xml"/>`
	for _, img := range d.images {
		docRels += fmt.Sprintf(
			`<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image%d.png"/>`,
			img.rID, indexOfImage(d.images, img.rID))
	}
	docRels += `</Relationships>`
	if err := writeZipEntry(zw, "word/_rels/document.xml.rels", docRels); err != nil {
		return nil, err
	}

	for _, img := range d.images {
		if err := writeZipBytes(zw, img.name, img.bytes); err != nil {
			return nil, err
		}
	}

	// styles.xml — 行业交付样式：正文 宋体/TNR 12pt 1.3 倍行距；标题黑体品牌色（H1 带色底线）。
	styles := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="宋体" w:cs="Times New Roman"/><w:color w:val="%s"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:rPrDefault>
    <w:pPrDefault><w:pPr><w:spacing w:line="312" w:lineRule="auto"/></w:pPr></w:pPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:jc w:val="center"/><w:spacing w:before="240" w:after="240"/></w:pPr><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="黑体"/><w:b/><w:sz w:val="52"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:keepNext/><w:outlineLvl w:val="0"/><w:pBdr><w:bottom w:val="single" w:sz="12" w:space="2" w:color="%s"/></w:pBdr><w:spacing w:before="360" w:after="200"/></w:pPr><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:color w:val="%s"/><w:sz w:val="32"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:keepNext/><w:outlineLvl w:val="1"/><w:spacing w:before="300" w:after="140"/></w:pPr><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:color w:val="%s"/><w:sz w:val="28"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:pPr><w:keepNext/><w:outlineLvl w:val="2"/><w:spacing w:before="220" w:after="100"/></w:pPr><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:pPr><w:outlineLvl w:val="3"/></w:pPr><w:rPr><w:rFonts w:eastAsia="宋体"/><w:b/><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/></w:style>
</w:styles>`, docxInkColor, docxBrandColor, docxBrandColor, docxBrandColor)
	if err := writeZipEntry(zw, "word/styles.xml", styles); err != nil {
		return nil, err
	}

	// header1.xml — 左：报告名；右：密级；底部品牌色细线。
	hdrRight := d.header
	if hdrRight == "" {
		hdrRight = "内部资料"
	}
	if strings.Contains(hdrRight, "★") == false && hdrRight != "内部资料" && hdrRight != "公开" {
		hdrRight += " ★"
	}
	hdr := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="2" w:color="%s"/></w:pBdr><w:tabs><w:tab w:val="right" w:pos="9062"/></w:tabs></w:pPr>
    <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="%s"/><w:rFonts w:eastAsia="宋体"/></w:rPr><w:t xml:space="preserve">FORANG 渗透测试报告</w:t></w:r>
    <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="%s"/><w:rFonts w:eastAsia="宋体"/></w:rPr><w:tab/><w:t xml:space="preserve">%s</w:t></w:r>
  </w:p>
</w:hdr>`, docxBrandColor, docxGrayColor, docxGrayColor, xmlEscape(hdrRight))
	if err := writeZipEntry(zw, "word/header1.xml", hdr); err != nil {
		return nil, err
	}

	hdrF := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p/></w:hdr>`
	if err := writeZipEntry(zw, "word/headerFirst.xml", hdrF); err != nil {
		return nil, err
	}

	ftr := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p><w:pPr><w:jc w:val="center"/><w:pBdr><w:top w:val="single" w:sz="4" w:space="2" w:color="C9D2D8"/></w:pBdr></w:pPr>
    <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="595959"/><w:rFonts w:eastAsia="宋体"/></w:rPr><w:t xml:space="preserve">第 </w:t></w:r>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>
    <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="595959"/><w:rFonts w:eastAsia="宋体"/></w:rPr><w:t xml:space="preserve"> 页 / 共 </w:t></w:r>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>
    <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="595959"/><w:rFonts w:eastAsia="宋体"/></w:rPr><w:t xml:space="preserve"> 页</w:t></w:r>
  </w:p>
</w:ftr>`
	if err := writeZipEntry(zw, "word/footer1.xml", ftr); err != nil {
		return nil, err
	}

	ftrF := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p/></w:ftr>`
	if err := writeZipEntry(zw, "word/footerFirst.xml", ftrF); err != nil {
		return nil, err
	}

	doc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>%s<w:sectPr><w:titlePg/><w:headerReference w:type="default" r:id="rIdHdr1"/><w:headerReference w:type="first" r:id="rIdHdrF"/><w:footerReference w:type="default" r:id="rIdFtr1"/><w:footerReference w:type="first" r:id="rIdFtrF"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1418" w:right="1418" w:bottom="1418" w:left="1418" w:header="708" w:footer="708"/></w:sectPr></w:body>
</w:document>`, d.body.String())
	if err := writeZipEntry(zw, "word/document.xml", doc); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeZipEntry(zw *zip.Writer, name, content string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, content)
	return err
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// runsFromMarkdown 把 **bold** 标记转成 OOXML run 序列（继承默认字体）。
func runsFromMarkdown(text string) string {
	parts := strings.Split(text, "**")
	var sb strings.Builder
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i%2 == 1 {
			sb.WriteString(fmt.Sprintf(`<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r>`, xmlEscape(part)))
		} else {
			sb.WriteString(fmt.Sprintf(`<w:r><w:t xml:space="preserve">%s</w:t></w:r>`, xmlEscape(part)))
		}
	}
	return sb.String()
}

func indexOfImage(images []docxImage, rID string) int {
	for i, img := range images {
		if img.rID == rID {
			return i + 1
		}
	}
	return 1
}

func writeZipBytes(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
