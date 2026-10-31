"use client";

// c2-autopilot-panel.tsx — C2 AI 自动驾驶面板 + 漏洞链推断 + 载荷匹配 + AI 报告
import React from "react";
import { BotIcon, PlayIcon, SquareIcon, RefreshCw, LinkIcon, TargetIcon, FileTextIcon } from "lucide-react";

interface Action { round: number; cmd: string; label: string; output: string; ok: boolean; reason: string }

export default function C2AutopilotPanel({ beaconId }: { beaconId: string }) {
  const [running, setRunning] = React.useState(false);
  const [status, setStatus] = React.useState<{ running: boolean; round: number; max_rounds: number; actions: Action[]; goal?: string } | null>(null);
  const [goal, setGoal] = React.useState("尽可能深入地渗透内网，收集凭据和敏感信息");
  const [chainResult, setChainResult] = React.useState<{ chains?: { name: string; steps: string[]; impact: string; severity: string }[]; next_move?: string; raw?: string } | null>(null);
  const [matchResult, setMatchResult] = React.useState<{ env?: string; recommendations?: { script_type: string; encoder: string; reason: string }[] } | null>(null);
  const [reportResult, setReportResult] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const loadStatus = React.useCallback(async () => {
    try {
      const r = await fetch("/api/tools/c2/autopilot/status", {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
      const j = await r.json() as { data?: typeof status };
      setStatus(j.data || null);
      setRunning(j.data?.running || false);
    } catch { /* ignore */ }
  }, []);

  React.useEffect(() => {
    loadStatus();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [loadStatus]);

  // 自动驾驶运行时 3s 轮询状态
  React.useEffect(() => {
    if (running) {
      pollRef.current = setInterval(loadStatus, 3000);
    } else if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [running, loadStatus]);

  const start = async () => {
    setBusy(true);
    try {
      const r = await fetch("/api/tools/c2/autopilot/start", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId, goal, max_rounds: 10, cooldown_sec: 5 }),
      });
      const j = await r.json();
      if (j.error) { alert(j.error); return; }
      setRunning(true);
      loadStatus();
    } finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true);
    try {
      await fetch("/api/tools/c2/autopilot/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: "{}",
      });
      setRunning(false);
      loadStatus();
    } finally { setBusy(false); }
  };

  const analyzeChain = async () => {
    setBusy(true);
    setChainResult(null);
    try {
      const r = await fetch("/api/tools/c2/autopilot/chain", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId }),
      });
      const j = await r.json() as { data?: typeof chainResult };
      setChainResult(j.data || null);
    } finally { setBusy(false); }
  };

  const matchPayload = async () => {
    setBusy(true);
    setMatchResult(null);
    try {
      const r = await fetch("/api/tools/c2/autopilot/match", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId }),
      });
      const j = await r.json() as { data?: typeof matchResult };
      setMatchResult(j.data || null);
    } finally { setBusy(false); }
  };

  const generateReport = async () => {
    setBusy(true);
    setReportResult("");
    try {
      const r = await fetch("/api/tools/c2/autopilot/report", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId }),
      });
      const j = await r.json() as { data?: { report?: string } };
      setReportResult(j.data?.report || "");
    } finally { setBusy(false); }
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      {/* 工具栏 */}
      <div className="flex flex-wrap items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <BotIcon className="size-3.5 text-purple-400" />
        <span className="font-semibold text-zinc-300">AI 自动驾驶</span>
        <span className={`rounded px-1.5 text-[9px] ${running ? "bg-purple-500/20 text-purple-300" : "bg-muted text-zinc-500"}`}>
          {running ? `第 ${status?.round || 0}/${status?.max_rounds || 10} 轮运行中` : "未启动"}
        </span>
        {!running ? (
          <button className="flex items-center gap-1 rounded border border-purple-500 bg-purple-500/10 px-2 py-0.5 font-semibold text-purple-300 hover:bg-purple-500/20 disabled:opacity-40" onClick={start} disabled={busy}>
            <PlayIcon className="size-3" /> 启动自动驾驶
          </button>
        ) : (
          <button className="flex items-center gap-1 rounded border border-red-800 bg-red-950/50 px-2 py-0.5 text-red-300 hover:bg-red-900/50" onClick={stop} disabled={busy}>
            <SquareIcon className="size-3" /> 停止
          </button>
        )}
        <div className="ml-auto flex gap-1">
          <button className="flex items-center gap-1 rounded border border-blue-500 bg-blue-500/10 px-1.5 py-0.5 text-blue-300 hover:bg-blue-500/20 disabled:opacity-40" onClick={analyzeChain} disabled={busy}>
            <LinkIcon className="size-3" /> 漏洞链
          </button>
          <button className="flex items-center gap-1 rounded border border-green-500 bg-green-500/10 px-1.5 py-0.5 text-green-300 hover:bg-green-500/20 disabled:opacity-40" onClick={matchPayload} disabled={busy}>
            <TargetIcon className="size-3" /> 载荷匹配
          </button>
          <button className="flex items-center gap-1 rounded border border-amber-500 bg-amber-500/10 px-1.5 py-0.5 text-amber-300 hover:bg-amber-500/20 disabled:opacity-40" onClick={generateReport} disabled={busy}>
            <FileTextIcon className="size-3" /> AI 报告
          </button>
          <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={loadStatus}>
            <RefreshCw className={`size-3 ${busy ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* 目标输入 */}
      <div className="border-b border-zinc-800 px-2 py-1.5">
        <input
          className="w-full rounded border border-zinc-700 bg-zinc-800 px-2 py-1 text-zinc-200 placeholder:text-zinc-600"
          placeholder="攻击目标（如：提权到 root / 收集全部凭据 / 横向移动到 192.168.1.0/24）"
          value={goal}
          onChange={(e) => setGoal(e.target.value)}
          disabled={running}
        />
      </div>

      {/* 主体 */}
      <div className="min-h-0 flex-1 overflow-auto p-2">
        {/* 自动驾驶动作流 */}
        {status?.actions?.length ? (
          <div className="mb-3">
            <div className="mb-1 font-semibold text-purple-300">已执行 {status.actions.length} 个动作</div>
            {status.actions.slice(-20).map((a, i) => (
              <div key={i} className={`mb-1 rounded border p-1.5 ${a.ok ? "border-zinc-800" : "border-red-800"}`}>
                <div className="flex items-center gap-1.5">
                  <span className={`rounded px-1 text-[9px] ${a.ok ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>
                    R{a.round}
                  </span>
                  <span className="font-semibold text-blue-300">{a.label}</span>
                  <span className="ml-auto text-[9px] text-zinc-600">{a.reason}</span>
                </div>
                <div className="text-[10px] text-zinc-500">$ {a.cmd.slice(0, 60)}</div>
                {a.output && <div className="font-mono text-[10px] text-zinc-400">{a.output.slice(0, 100)}</div>}
              </div>
            ))}
          </div>
        ) : !running && (
          <div className="py-4 text-center text-zinc-500">
            <BotIcon className="mx-auto mb-2 size-10 opacity-20" />
            <div className="text-sm">AI 自动驾驶未启动</div>
            <div className="mt-1 text-[10px] opacity-50">
              设定攻击目标 → 启动后 AI 持续分析链路图 → 自主决策 → 自动执行<br/>
              每轮冷却 5 秒，最多 10 轮，可随时停止
            </div>
          </div>
        )}

        {/* 漏洞链分析 */}
        {chainResult && (
          <div className="mb-3 rounded border border-blue-700/50 bg-blue-950/20 p-2">
            <div className="mb-1 font-semibold text-blue-300">🔗 漏洞链分析</div>
            {chainResult.chains?.map((c, i) => (
              <div key={i} className="mb-1.5 rounded border border-blue-800/50 p-1.5">
                <div className="flex items-center gap-1">
                  <span className={`rounded px-1 text-[9px] ${c.severity === "critical" ? "bg-red-500/20 text-red-300" : c.severity === "high" ? "bg-orange-500/20 text-orange-300" : "bg-yellow-500/20 text-yellow-300"}`}>
                    {c.severity}
                  </span>
                  <span className="font-semibold text-blue-200">{c.name}</span>
                </div>
                <div className="mt-0.5 text-[10px] text-zinc-400">{c.impact}</div>
                <div className="mt-0.5 flex flex-wrap gap-0.5">
                  {c.steps.map((s, j) => (
                    <span key={j} className="rounded bg-blue-900/50 px-1 py-0.5 text-[9px] text-blue-300">{j + 1}. {s}</span>
                  ))}
                </div>
              </div>
            ))}
            {chainResult.next_move && (
              <div className="rounded bg-green-950/30 p-1.5 text-[10px] text-green-300">
                ⚡ 建议：{chainResult.next_move}
              </div>
            )}
            {chainResult.raw && <pre className="text-[10px] text-zinc-500">{chainResult.raw}</pre>}
          </div>
        )}

        {/* 载荷匹配 */}
        {matchResult && (
          <div className="mb-3 rounded border border-green-700/50 bg-green-950/20 p-2">
            <div className="mb-1 font-semibold text-green-300">🎯 载荷匹配</div>
            <div className="mb-1 font-mono text-[10px] text-zinc-500">环境：{matchResult.env?.slice(0, 100)}</div>
            {matchResult.recommendations?.map((r, i) => (
              <div key={i} className="rounded border border-green-800/50 p-1.5">
                <span className="font-mono font-bold text-green-300">{r.script_type}/{r.encoder}</span>
                <span className="ml-2 text-zinc-400">{r.reason}</span>
              </div>
            ))}
          </div>
        )}

        {/* AI 报告 */}
        {reportResult && (
          <div className="rounded border border-amber-700/50 bg-amber-950/20 p-2">
            <div className="mb-1 font-semibold text-amber-300">📄 AI 报告</div>
            <pre className="max-h-60 overflow-auto whitespace-pre-wrap font-mono text-[10px] text-zinc-300">{reportResult}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
