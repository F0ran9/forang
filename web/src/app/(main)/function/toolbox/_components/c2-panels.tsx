"use client";

// c2-panels.tsx — C2 升级面板：SysInfo（系统信息快照+敏感文件）/ Schedule（定时任务）/ Audit（审计日志+报告+KillSwitch）
import React from "react";
import { api } from "@/lib/api";
import { InfoIcon, ClockIcon, ScrollTextIcon, ZapIcon, TrashIcon, RefreshCw } from "lucide-react";

// ---------- SysInfo ----------
export function SysInfoPanel({ beaconId }: { beaconId: string }) {
  const [report, setReport] = React.useState("");
  const [sensitive, setSensitive] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [tab, setTab] = React.useState<"sys" | "sens">("sys");

  const collect = async () => {
    setBusy(true);
    try {
      const r = await api.c2Sysinfo(beaconId);
      setReport(r.data?.report || "");
    } finally { setBusy(false); }
  };
  const scanSensitive = async () => {
    setBusy(true);
    setTab("sens");
    try {
      const r = await api.c2Sensitive(beaconId);
      setSensitive(r.data?.report || "");
    } finally { setBusy(false); }
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <button className={`flex items-center gap-1 rounded px-2 py-0.5 ${tab === "sys" ? "bg-blue-600 text-white" : "text-zinc-300 hover:bg-zinc-700"}`} onClick={() => setTab("sys")}>
          <InfoIcon className="size-3" /> 系统信息
        </button>
        <button className={`flex items-center gap-1 rounded px-2 py-0.5 ${tab === "sens" ? "bg-blue-600 text-white" : "text-zinc-300 hover:bg-zinc-700"}`} onClick={scanSensitive} disabled={busy}>
          <ZapIcon className="size-3" /> 敏感文件
        </button>
        <button className="ml-auto flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" onClick={collect} disabled={busy}>
          <RefreshCw className={`size-3 ${busy ? "animate-spin" : ""}`} /> 采集
        </button>
      </div>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-2 py-1 font-mono text-zinc-300">
        {(tab === "sys" ? report : sensitive) || "（点「采集」或「敏感文件」获取）"}
      </pre>
    </div>
  );
}

// ---------- Schedule ----------
export function SchedulePanel({ beaconId }: { beaconId: string }) {
  const [interval, setInterval] = React.useState(60);
  const [cmd, setCmd] = React.useState("id");
  const [output, setOutput] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const run = async (action: string, opts?: Record<string, unknown>) => {
    setBusy(true);
    try {
      const r = await api.c2Schedule(beaconId, action, opts as never);
      setOutput(r.data?.output || "");
    } catch (e) {
      setOutput("错误: " + (e instanceof Error ? e.message : String(e)));
    } finally { setBusy(false); }
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex flex-wrap items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <input type="number" className="w-20 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-zinc-200" value={interval} onChange={(e) => setInterval(Number(e.target.value) || 60)} />
        <span className="text-zinc-500">秒</span>
        <input className="flex-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-200" value={cmd} onChange={(e) => setCmd(e.target.value)} placeholder="命令" />
        <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700 disabled:opacity-40" onClick={() => run("add", { interval_sec: interval, cmd })} disabled={busy}>
          <ClockIcon className="mr-0.5 inline size-3" /> 添加
        </button>
        <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={() => run("ls")} disabled={busy}>列出</button>
        <button className="rounded border border-red-800 bg-red-950/50 px-1.5 py-0.5 text-red-300 hover:bg-red-900/50" onClick={() => run("clear")} disabled={busy}>清空</button>
      </div>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-2 py-1 font-mono text-zinc-300">{output || "（添加定时任务或列出已有任务）"}</pre>
    </div>
  );
}

// ---------- Audit + Kill Switch + Report ----------
export function AuditPanel() {
  const [entries, setEntries] = React.useState<{ id: number; session_id: string; hostname: string; action: string; detail: string; created_at: string }[]>([]);
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const r = await api.c2AuditList(50);
      setEntries(r.data || []);
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const killAll = async () => {
    if (!window.confirm("⚠️ 紧急停机：向所有会话下发 kill，确认？")) return;
    setBusy(true);
    try {
      const r = await api.c2KillSwitch();
      const results = r.data || [];
      window.alert(`已向 ${results.length} 个会话下发 kill\n` + results.map((x: { session_id: string; status: string }) => `${x.session_id.slice(0, 10)}…: ${x.status}`).join("\n"));
      load();
    } finally { setBusy(false); }
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-2 py-1">
        <ScrollTextIcon className="size-3.5 text-zinc-400" />
        <span className="font-semibold text-zinc-300">审计日志</span>
        <button className="ml-auto flex items-center gap-1 rounded border border-red-800 bg-red-950/50 px-2 py-0.5 text-red-300 hover:bg-red-900/50 disabled:opacity-40" onClick={killAll} disabled={busy}>
          <ZapIcon className="size-3" /> Kill Switch（全部会话）
        </button>
        <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={load}>
          <RefreshCw className="size-3" /> 刷新
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-zinc-900 text-zinc-500">
            <tr className="text-left"><th className="px-2 py-1">时间</th><th>动作</th><th>详情</th><th>会话</th></tr>
          </thead>
          <tbody>
            {entries.length === 0 && <tr><td colSpan={4} className="py-4 text-center text-zinc-500">（暂无记录）</td></tr>}
            {entries.map((e) => (
              <tr key={e.id} className="border-b border-zinc-800/60 hover:bg-zinc-800/40">
                <td className="px-2 py-0.5 text-zinc-400">{e.created_at}</td>
                <td className="font-mono text-blue-400">{e.action}</td>
                <td className="truncate text-zinc-300" title={e.detail}>{e.detail}</td>
                <td className="font-mono text-zinc-500">{e.session_id.slice(0, 12)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
