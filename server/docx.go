package server

// docx.go — 极简 OOXML .docx 生成器（无外部依赖，archive/zip + 手写 WordprocessingML）。
// 支持：标题（多级）、段落、加粗、代码块、表格、分页符。够生成专业渗透测试报告。

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"io"
	"strings"
)

// Docx 是一个正在构建的 Word 文档。
type Docx struct {
	body   strings.Builder
	images []docxImage // 待嵌入的图片
}

type docxImage struct {
	rID   string // 关系 ID（rIdImg1, rIdImg2…）
	name  string // word/media/image1.png
	bytes []byte
}

// NewDocx 创建空文档（A4 纵向）。
func NewDocx() *Docx { return &Docx{} }

// Image 嵌入一张 PNG 图片（自动缩放到页宽以内，居中）。
// 文件路径须存在；不存在的静默跳过（证据可能被清理）。
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

	// 计算 EMU 尺寸（A4 内容宽 ≈ 15cm ≈ 5400000 EMU；保持 16:9 比例默认）
	wEMU, hEMU := int64(5400000), int64(3037500)
	d.body.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"><wp:extent cx="%d" cy="%d"/><wp:docPr id="%d" name="Image%d"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="%d" name="image%d.png"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="%s" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`,
		wEMU, hEMU, idx, idx, idx, idx, img.rID, wEMU, hEMU))

	if caption != "" {
		d.Paragraph("▲ " + caption) // 图注
	}
	return d
}

// title 添加封面大标题（Title 样式，黑体居中）。
func (d *Docx) title(text string) *Docx {
	d.body.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		xmlEscape(text)))
	return d
}

// Heading 添加标题（level 1-4，Word 内置 Heading 样式）。
func (d *Docx) Heading(level int, text string) *Docx {
	style := fmt.Sprintf("Heading%d", level)
	d.body.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:pStyle w:val="%s"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		style, xmlEscape(text)))
	return d
}

// Paragraph 添加正文段落（支持 **加粗** 内联标记）。
func (d *Docx) Paragraph(text string) *Docx {
	d.body.WriteString(`<w:p><w:r>`)
	d.body.WriteString(runsFromMarkdown(text))
	d.body.WriteString(`</w:r></w:p>`)
	return d
}

// CodeBlock 添加等宽代码/报文块（灰底、Consolas 字体）。
func (d *Docx) CodeBlock(text string) *Docx {
	lines := strings.Split(text, "\n")
	for _, ln := range lines {
		d.body.WriteString(fmt.Sprintf(
			`<w:p><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/><w:spacing w:after="0"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Consolas" w:cs="Consolas" w:sz="18"/></w:rPr></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Consolas" w:cs="Consolas" w:sz="18"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
			xmlEscape(ln)))
	}
	d.body.WriteString(`<w:p/>`) // 空行分隔
	return d
}

// Table 添加表格（headers + rows，自动表头加粗灰底）。
func (d *Docx) Table(headers []string, rows [][]string) *Docx {
	d.body.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>`)
	for _, edge := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		d.body.WriteString(fmt.Sprintf(`<w:%s w:val="single" w:sz="4" w:color="94a3b8"/>`, edge))
	}
	d.body.WriteString(`</w:tblBorders></w:tblPr>`)

	// 表头
	d.body.WriteString(`<w:tr>`)
	for _, h := range headers {
		d.body.WriteString(fmt.Sprintf(
			`<w:tc><w:tcPr><w:shd w:val="clear" w:fill="E2E8F0"/></w:tcPr><w:p><w:r><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`,
			xmlEscape(h)))
	}
	d.body.WriteString(`</w:tr>`)

	// 数据行
	for _, row := range rows {
		d.body.WriteString(`<w:tr>`)
		for _, cell := range row {
			d.body.WriteString(fmt.Sprintf(
				`<w:tc><w:p><w:r><w:rPr><w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`,
				xmlEscape(cell)))
		}
		d.body.WriteString(`</w:tr>`)
	}
	d.body.WriteString(`</w:tbl><w:p/>`)
	return d
}

// PageBreak 插入分页符。
func (d *Docx) PageBreak() *Docx {
	d.body.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
	return d
}

// Build 生成 .docx 字节流。
func (d *Docx) Build() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// [Content_Types].xml（含图片类型）
	ct := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>`
	if err := writeZipEntry(zw, "[Content_Types].xml", ct); err != nil {
		return nil, err
	}

	// _rels/.rels
	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	if err := writeZipEntry(zw, "_rels/.rels", rels); err != nil {
		return nil, err
	}

	// word/_rels/document.xml.rels（图片关系；无图片时也写入空壳保持结构完整）
	docRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`
	for _, img := range d.images {
		docRels += fmt.Sprintf(
			`<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image%d.png"/>`,
			img.rID, indexOfImage(d.images, img.rID))
	}
	docRels += `</Relationships>`
	if err := writeZipEntry(zw, "word/_rels/document.xml.rels", docRels); err != nil {
		return nil, err
	}

	// 图片二进制
	for _, img := range d.images {
		if err := writeZipBytes(zw, img.name, img.bytes); err != nil {
			return nil, err
		}
	}

	// word/styles.xml — 字体对齐行业交付模板：正文 宋体/Times New Roman 12pt；
	// 一级标题 黑体 16pt、二级 黑体 14pt、三级 黑体 12pt（均加粗）；TableGrid。
	styles := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="宋体" w:cs="Times New Roman"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:rPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:pPr><w:jc w:val="center"/><w:spacing w:before="240" w:after="240"/></w:pPr><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="黑体"/><w:b/><w:sz w:val="52"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:outlineLvl w:val="0"/><w:spacing w:before="360" w:after="160"/></w:pPr><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:sz w:val="32"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:outlineLvl w:val="1"/><w:spacing w:before="280" w:after="120"/></w:pPr><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:sz w:val="28"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:pPr><w:outlineLvl w:val="2"/><w:spacing w:before="200" w:after="80"/></w:pPr><w:rPr><w:rFonts w:eastAsia="黑体" w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:b/><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:pPr><w:outlineLvl w:val="3"/></w:pPr><w:rPr><w:rFonts w:eastAsia="宋体"/><w:b/><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/></w:style>
</w:styles>`
	if err := writeZipEntry(zw, "word/styles.xml", styles); err != nil {
		return nil, err
	}

	// word/document.xml — 正文
	doc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>%s<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1418" w:right="1418" w:bottom="1418" w:left="1418"/></w:sectPr></w:body>
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

// runsFromMarkdown 把 **bold** 标记转成 OOXML run 序列。
func runsFromMarkdown(text string) string {
	parts := strings.Split(text, "**")
	var sb strings.Builder
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i%2 == 1 {
			sb.WriteString(fmt.Sprintf(`<w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s</w:t>`, xmlEscape(part)))
		} else {
			sb.WriteString(fmt.Sprintf(`<w:t xml:space="preserve">%s</w:t>`, xmlEscape(part)))
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
