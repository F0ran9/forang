package webshell

// disguise_test.go — 容器链回归。
//
// 三类断言层次不同，缺一不可：
//  1. 往返一致：Wrap 出来的容器能被自己的 Unwrap 还原成原始字节；
//  2. 容器合法：标准库解码器（image/png、image/gif）能打开，PDF 的 xref 偏移
//     真的能指到对象上——这一层才是「伪装」成立的前提，否则一眼假；
//  3. 拒绝异常：签名不对、载荷区被截断时必须报错而不是返回垃圾。

import (
	"bytes"
	"encoding/binary"
	"image/gif"
	"image/png"
	"strconv"
	"testing"
)

func sampleSecret(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

func TestDisguiseRoundTrip(t *testing.T) {
	for _, name := range DisguiseNames() {
		d, err := GetDisguise(name)
		if err != nil || d == nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, n := range []int{1, 17, 1024, 32 << 10, 200 << 10} {
			secret := sampleSecret(n)
			container, err := d.Wrap(secret)
			if err != nil {
				t.Fatalf("%s/%d: wrap: %v", name, n, err)
			}
			if got := DetectDisguise(container); got != name {
				t.Errorf("%s/%d: 签名识别为 %q", name, n, got)
			}
			back, err := d.Unwrap(container)
			if err != nil {
				t.Fatalf("%s/%d: unwrap: %v", name, n, err)
			}
			if !bytes.Equal(back, secret) {
				t.Fatalf("%s/%d: 往返不一致（得到 %d 字节）", name, n, len(back))
			}
		}
	}
}

func TestPNGDecodable(t *testing.T) {
	d, _ := GetDisguise("png")
	container, err := d.Wrap(sampleSecret(8192))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(container))
	if err != nil {
		t.Fatalf("标准解码器打不开：%v", err)
	}
	// IHDR 声明的尺寸必须和解码结果一致，否则说明 chunk 写坏了
	w := int(binary.BigEndian.Uint32(container[16:20]))
	h := int(binary.BigEndian.Uint32(container[20:24]))
	b := img.Bounds()
	if b.Dx() != w || b.Dy() != h {
		t.Fatalf("尺寸不符：IHDR %dx%d，解码 %dx%d", w, h, b.Dx(), b.Dy())
	}
	if w < 120 || h < 90 {
		t.Errorf("画布过小，容易被看出异常：%dx%d", w, h)
	}
}

func TestGIFDecodable(t *testing.T) {
	d, _ := GetDisguise("gif")
	container, err := d.Wrap(sampleSecret(4096))
	if err != nil {
		t.Fatal(err)
	}
	img, err := gif.Decode(bytes.NewReader(container))
	if err != nil {
		t.Fatalf("标准解码器打不开：%v", err)
	}
	w := int(binary.LittleEndian.Uint16(container[6:8]))
	h := int(binary.LittleEndian.Uint16(container[8:10]))
	b := img.Bounds()
	if b.Dx() != w || b.Dy() != h {
		t.Fatalf("尺寸不符：头 %dx%d，解码 %dx%d", w, h, b.Dx(), b.Dy())
	}
}

func TestPDFStructure(t *testing.T) {
	d, _ := GetDisguise("pdf")
	container, err := d.Wrap(sampleSecret(4096))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(container, []byte("%PDF-1.5")) {
		t.Fatal("缺 PDF 头")
	}
	if !bytes.HasSuffix(container, []byte("%%EOF\n")) {
		t.Fatalf("缺文件结束标记")
	}
	// startxref 必须指向真正的 xref 关键字
	i := bytes.LastIndex(container, []byte("startxref"))
	if i < 0 {
		t.Fatal("缺 startxref")
	}
	rest := bytes.TrimSpace(container[i+len("startxref"):])
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	off, err := strconv.Atoi(string(rest[:end]))
	if err != nil || off <= 0 || off >= len(container) {
		t.Fatalf("startxref 偏移非法: %q", rest[:end])
	}
	if !bytes.HasPrefix(container[off:], []byte("xref")) {
		end := off + 8
		if end > len(container) {
			end = len(container)
		}
		t.Fatalf("startxref 未指向 xref 表（偏移 %d 处是 %q）", off, container[off:end])
	}
	// xref 表里每个偏移都应落在 "<n> 0 obj" 上
	for n := 1; n <= 5; n++ {
		entry := off + len("xref\n0 6\n0000000000 65535 f \n") + (n-1)*20
		want := []byte(strconv.Itoa(n) + " 0 obj")
		if !bytes.HasPrefix(container[entry+0:], []byte("000000")) {
			continue // 偏移表格式异常时交由下一层断言
		}
		objOff, err := strconv.Atoi(string(container[entry : entry+10]))
		if err != nil || objOff <= 0 || objOff >= len(container) {
			t.Fatalf("对象 %d 偏移非法", n)
		}
		if !bytes.HasPrefix(container[objOff:], want) {
			t.Fatalf("对象 %d 偏移错位：%q", n, container[objOff:objOff+12])
		}
	}
}

func TestDisguiseRejects(t *testing.T) {
	for _, name := range DisguiseNames() {
		d, _ := GetDisguise(name)
		if _, err := d.Wrap(nil); err == nil {
			t.Errorf("%s: 空载荷应报错", name)
		}
		if _, err := d.Unwrap([]byte("not a container at all")); err == nil {
			t.Errorf("%s: 非容器输入应报错", name)
		}
		// 截断容器：破坏尾部，必须报错而不是返回半截数据
		container, err := d.Wrap(sampleSecret(2048))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Unwrap(container[:len(container)/2]); err == nil {
			t.Errorf("%s: 截断容器应报错", name)
		}
	}
}

func TestGetDisguiseNames(t *testing.T) {
	if _, err := GetDisguise(""); err != nil {
		t.Errorf("空串应表示不伪装：%v", err)
	}
	d, err := GetDisguise("NONE")
	if err != nil || d != nil {
		t.Errorf("none 应返回 nil,nil：%v %v", d, err)
	}
	if _, err := GetDisguise("rsa"); err == nil {
		t.Error("未知链名应报错")
	}
	names := DisguiseNames()
	if len(names) != 3 || names[0] != "gif" || names[1] != "pdf" || names[2] != "png" {
		t.Errorf("链名列表异常: %v", names)
	}
}

func TestPackSecret(t *testing.T) {
	secret := sampleSecret(100)
	packed := packSecret(secret)
	if got, err := unpackSecret(packed); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("pack/unpack: %v", err)
	}
	// 尾部冗余（GIF 的像素填充、中间设备追加）不应影响还原
	padded := append(append([]byte{}, packed...), 0x11, 0x22, 0x33)
	if got, err := unpackSecret(padded); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("带冗余尾部: %v", err)
	}
	// 长度前缀声称的长度超出实际数据，必须拒绝
	if _, err := unpackSecret(packed[:len(packed)-10]); err == nil {
		t.Fatal("长度越界应报错")
	}
	if _, err := unpackSecret([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("零长度应报错")
	}
}
