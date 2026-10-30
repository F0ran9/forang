"use client";

// c2-console.tsx — Cobalt Strike 风格 C2 指挥台：
//   深色指挥窗（标题栏 + Listener/Beacon 计数 + 配置）
//   会话表（CS 列：外部IP | 内部IP | 主机名 | 系统 | 架构 | 用户 | 心跳 | 最后回连 | 备注）
//   选中行 → Beacon Console（黑底 beacon> 控制台：命令历史/输出滚动/shell 前缀解析）
//   操作：Interact / Note（goc2 notes）/ 刷新 / 全部测活
import React from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { RefreshCw, SettingsIcon, PencilIcon, XIcon, ZapIcon } from "lucide-react";

interface BeaconRow {
  id: string;
  externalIp?: string;
  internalIp?: string;
  hostname?: string;
  osType?: string;
  arch?: string;
  username?: string;
  process?: string;
  interval?: number;
  jitter?: number;
  lastBeacon?: string;
  notes?: string;
  integrityLevel?: string;
  listenerId?: string;
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
  const [cfgOpen, setCfgOpen] = React.useState(false);
  const [cfgUrl, setCfgUrl] = React.useState("");
  const [cfgToken, setCfgToken] = React.useState("");
  const [reload, setReload] = React.useState(0);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

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

  React.useEffect(() => {
    load();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
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
    try {
      await fetch(`/api/tools/c2/clients/${encodeURIComponent(b.id)}/notes`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ notes: n }),
      });
      setReload((x) => x + 1);
    } catch {
      /* ignore */
    }
  };

  const selBeacon = beacons.find((b) => b.id === sel);

  return (
    <div className="flex h-[calc(100vh-190px)] min-h-[560px] flex-col overflow-hidden rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 shadow-2xl">
      {/* 标题栏（CS 顶栏） */}
      <div className="flex flex-wrap items-center gap-2 border-b border-zinc-700 bg-zinc-800 px-3 py-2 text-sm">
        <span className="flex items-center gap-1.5 font-semibold text-red-400">
          <ZapIcon className="size-4" /> FORANG Strike
        </span>
        <span className={`rounded px-1.5 text-[10px] ${status?.reachable ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
          {status?.reachable ? "teamserver 在线" : "不可达"}
        </span>
        <span className="font-mono text-[11px] text-zinc-400">{status?.url} · token {status?.token_masked}</span>
        <span className="rounded bg-zinc-700 px-1.5 text-[10px]">Beacons {beacons.length}</span>
        <span className="rounded bg-zinc-700 px-1.5 text-[10px]">Listeners {listeners.length}</span>
        {!status?.reachable && status?.error && <span className="text-[10px] text-red-400">{status.error.slice(0, 60)}</span>}
        <div className="ml-auto flex gap-1">
          <button className="flex items-center gap-1 rounded border border-zinc-600 px-2 py-1 text-[11px] hover:bg-zinc-700" onClick={() => setCfgOpen(!cfgOpen)}>
            <SettingsIcon className="size-3.5" /> Preferences
          </button>
          <button className="flex items-center gap-1 rounded border border-zinc-600 px-2 py-1 text-[11px] hover:bg-zinc-700" onClick={() => setReload((n) => n + 1)}>
            <RefreshCw className="size-3.5" /> Refresh
          </button>
        </div>
      </div>
      {cfgOpen && (
        <div className="flex flex-wrap items-center gap-2 border-b border-zinc-700 bg-zinc-800/70 px-3 py-2 text-xs">
          <Input className="h-7 w-64 border-zinc-600 bg-zinc-800 font-mono text-[11px] text-zinc-200" placeholder="goc2 admin URL" value={cfgUrl} onChange={(e) => setCfgUrl(e.target.value)} />
          <Input className="h-7 w-56 border-zinc-600 bg-zinc-800 font-mono text-[11px] text-zinc-200" placeholder="admin token（留空不改）" value={cfgToken} onChange={(e) => setCfgToken(e.target.value)} />
          <Button size="sm" variant="secondary" onClick={saveCfg}>Connect</Button>
          <span className="text-zinc-500">token 只存服务端</span>
        </div>
      )}

      {/* 会话表（CS Sessions） */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-[11px]">
          <thead className="sticky top-0 bg-zinc-800 text-zinc-400">
            <tr className="text-left">
              <th className="px-2 py-1.5">*</th>
              <th>外部 IP</th>
              <th>内部 IP</th>
              <th>主机名</th>
              <th>操作系统</th>
              <th>架构</th>
              <th>用户</th>
              <th className="w-16">心跳</th>
              <th className="w-20">最后回连</th>
              <th>备注</th>
              <th className="w-16">操作</th>
            </tr>
          </thead>
          <tbody>
            {beacons.length === 0 && (
              <tr><td colSpan={11} className="py-10 text-center text-zinc-500">{status?.reachable ? "无活跃会话——等待 beacon 回连" : "teamserver 不可达（配置 goc2 连接）"}</td></tr>
            )}
            {beacons.map((b) => (
              <tr
                key={b.id}
                className={`cursor-pointer border-b border-zinc-800 hover:bg-zinc-800/60 ${sel === b.id ? "bg-blue-900/30 text-zinc-100" : ""}`}
                onClick={() => setSel(b.id)}
              >
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
                  <button title="备注" onClick={(e) => { e.stopPropagation(); editNote(b); }}><PencilIcon className="size-3 text-zinc-500 hover:text-zinc-200" /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Beacon Console */}
      {selBeacon && <BeaconConsole beacon={selBeacon} onClose={() => setSel("")} pollRef={pollRef} onRefresh={() => setReload((n) => n + 1)} />}
    </div>
  );
}

// ---------- Beacon Console（CS 交互控制台） ----------

function BeaconConsole({ beacon, onClose, pollRef, onRefresh }: {
  beacon: BeaconRow;
  onClose: () => void;
  pollRef: React.MutableRefObject<ReturnType<typeof setInterval> | null>;
  onRefresh: () => void;
}) {
  const [out, setOut] = React.useState("");
  const [cmd, setCmd] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const hist = React.useRef<string[]>([]);
  const hidx = React.useRef(-1);
  const outRef = React.useRef<HTMLPreElement>(null);

  React.useEffect(() => {
    setOut(`[*] 会话 ${beacon.hostname}（${beacon.internalIp}）· ${beacon.osType}/${beacon.arch}${beacon.username ? " · " + beacon.username : ""}\n[*] 输入命令回车下发；shell/sh 前缀自动剥离；help 查看内置。\n`);
  }, [beacon.id]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(() => {
    if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight;
  }, [out]);

  const append = (s: string) => setOut((o) => o + s + "\n");

  const send = async (raw?: string) => {
    let line = (raw ?? cmd).trim();
    if (!line) return;
    setCmd("");
    if (line === "clear") { setOut(""); return; }
    if (line === "help") {
      append("[*] 内置：clear 清屏 | help 本帮助。其余任意命令作为 shell 任务下发到目标（shell/sh 前缀剥离），如：whoami、shell id、netstat -antp。");
      return;
    }
    for (const p of ["shell ", "sh "]) {
      if (line.toLowerCase().startsWith(p)) { line = line.slice(p.length); break; }
    }
    hist.current.push(raw ?? cmd);
    hidx.current = -1;
    append(`beacon> ${line}`);
    setBusy(true);
    try {
      const r = await api.c2Exec(beacon.id, line);
      const tid = r.data?.task_id;
      if (!tid) throw new Error("无 taskId");
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const t = await api.c2Tasks(beacon.id, tid);
          const arr = t.data || [];
          for (const it of arr) {
            const m = it as Record<string, unknown>;
            if ((m.taskId as string) !== tid && (m.taskId as string) !== "") continue;
            const st = String(m.status || "");
            const o = String(m.output || m.result || "");
            if (o || st === "completed" || st === "done") {
              if (pollRef.current) clearInterval(pollRef.current);
              append(o || `[*] 任务 ${tid} ${st}（无输出）`);
              setBusy(false);
              onRefresh();
              return;
            }
          }
        } catch {
          if (pollRef.current) clearInterval(pollRef.current);
          setBusy(false);
        }
      }, 2000);
      setTimeout(() => {
        if (pollRef.current) {
          clearInterval(pollRef.current);
          setBusy(false);
          append(`[*] 任务 ${tid} 40s 内未回显（心跳间隔 ${beacon.interval || "?"}s），稍后 Refresh 看任务。`);
        }
      }, 40000);
    } catch (e) {
      append(`[!] 下发失败: ${e instanceof Error ? e.message : String(e)}`);
      setBusy(false);
    }
  };

  return (
    <div className="flex h-64 flex-col border-t border-zinc-700 bg-black">
      <div className="flex items-center gap-2 bg-zinc-800/80 px-3 py-1 text-[11px]">
        <span className="font-semibold text-red-400">Beacon Console</span>
        <span className="font-mono text-blue-400">{beacon.hostname}</span>
        <span className="text-zinc-500">{beacon.id.slice(0, 18)}…</span>
        {busy && <span className="animate-pulse text-amber-400">等待回连…</span>}
        <button className="ml-auto text-zinc-500 hover:text-red-400" onClick={onClose}><XIcon className="size-3.5" /></button>
      </div>
      <pre ref={outRef} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-3 py-1.5 font-mono text-[11px] leading-relaxed text-zinc-300">{out}</pre>
      <div className="flex items-center gap-1 border-t border-zinc-800 px-3 py-1.5">
        <span className="shrink-0 font-mono text-[11px] text-red-400">beacon&gt;</span>
        <input
          className="flex-1 bg-transparent font-mono text-[11px] text-zinc-200 outline-none placeholder:text-zinc-600"
          placeholder={busy ? "…" : "shell whoami（Enter 下发，↑↓ 历史）"}
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
      </div>
    </div>
  );
}
