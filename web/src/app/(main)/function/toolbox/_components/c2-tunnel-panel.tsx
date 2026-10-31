"use client";

// c2-tunnel-panel.tsx — C2 内网穿透面板（SOCKS5 + 多层链路可视化）：
//   单层：beacon → socat → 平台 SOCKS5 → 浏览器进内网
//   多层：beacon A(DMZ) → beacon B(内网1) → beacon C(内网2) → 链式隧道
import React from "react";
import { api } from "@/lib/api";
import { GlobeIcon, LayersIcon, PlayIcon, SquareIcon, RefreshCw, ArrowRightIcon } from "lucide-react";

interface TunnelEntry {
  session_id: string;
  hostname: string;
  internal_ip: string;
  remote_port: number;
  status: string;
  chain: string[];
  created_at: string;
}

interface TunnelState {
  socks_port: number;
  socks_running: boolean;
  tunnels: TunnelEntry[];
}

export default function C2TunnelPanel({ beaconId, hostname, internalIP }: { beaconId: string; hostname: string; internalIP: string }) {
  const [state, setState] = React.useState<TunnelState | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [socksPort, setSocksPort] = React.useState(11080);

  const load = React.useCallback(async () => {
    try {
      const r = await fetch("/api/tools/c2/tunnel/status", {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
      const j = await r.json() as { data?: TunnelState };
      setState(j.data || null);
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const start = async () => {
    setBusy(true);
    setMsg("建立中…（SOCKS5 + 目标端 socat）");
    try {
      const r = await fetch("/api/tools/c2/tunnel/start", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId, hostname, internal_ip: internalIP, socks_port: socksPort }),
      });
      const j = await r.json() as { data?: { message?: string }; error?: string };
      setMsg(j.data?.message || j.error || "完成");
      load();
    } catch (e) {
      setMsg("失败: " + (e instanceof Error ? e.message : String(e)));
    } finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true);
    try {
      await fetch("/api/tools/c2/tunnel/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: "{}",
      });
      setMsg("隧道已全部停止");
      load();
    } finally { setBusy(false); }
  };

  // 最大链路深度
  const maxDepth = Math.max(...(state?.tunnels || []).map((t) => t.chain.length), 0);

  return (
    <div className="flex h-full flex-col text-[11px]">
      {/* 工具栏 */}
      <div className="flex flex-wrap items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <GlobeIcon className="size-3.5 text-blue-400" />
        <span className="font-semibold text-zinc-300">内网穿透</span>
        <span className={`rounded px-1.5 text-[9px] ${state?.socks_running ? "bg-green-500/20 text-green-400" : "bg-muted text-zinc-500"}`}>
          SOCKS5 {state?.socks_running ? `:${state.socks_port}` : "未启动"}
        </span>
        <span className="text-zinc-500">{state?.tunnels?.length || 0} 条隧道</span>
        <input
          type="number"
          className="ml-2 w-16 rounded border border-zinc-700 bg-zinc-800 px-1 py-0.5 text-zinc-200"
          value={socksPort}
          onChange={(e) => setSocksPort(Number(e.target.value) || 11080)}
          placeholder="端口"
        />
        <button
          className="flex items-center gap-1 rounded border border-blue-500 bg-blue-500/10 px-2 py-0.5 text-blue-300 hover:bg-blue-500/20 disabled:opacity-40"
          onClick={start}
          disabled={busy}
        >
          <PlayIcon className="size-3" /> 建立隧道
        </button>
        <button
          className="flex items-center gap-1 rounded border border-red-800 bg-red-950/50 px-2 py-0.5 text-red-300 hover:bg-red-900/50 disabled:opacity-40"
          onClick={stop}
          disabled={busy || !state?.socks_running}
        >
          <SquareIcon className="size-3" /> 全部停止
        </button>
        <button className="ml-auto rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={load}>
          <RefreshCw className="size-3" />
        </button>
      </div>

      {/* 消息 */}
      {msg && (
        <div className="border-b border-zinc-800 bg-blue-950/30 px-2 py-1 text-[10px] text-blue-300">{msg}</div>
      )}

      {/* 链路可视化 */}
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {state?.tunnels?.length ? (
          <div className="space-y-3">
            {/* 链路拓扑图 */}
            <div className="rounded border border-zinc-700 bg-black/30 p-3">
              <div className="mb-2 flex items-center gap-1 text-[10px] font-semibold text-zinc-400">
                <LayersIcon className="size-3" /> 链路拓扑
              </div>
              {state.tunnels.map((t, i) => (
                <div key={i} className="mb-2 flex items-center gap-1">
                  <span className="rounded bg-zinc-700 px-1.5 py-0.5 text-[10px]">浏览器/代理</span>
                  <ArrowRightIcon className="size-3 text-zinc-500" />
                  <span className="rounded bg-blue-900/50 px-1.5 py-0.5 text-[10px] text-blue-300">
                    SOCKS5 :{state.socks_port}
                  </span>
                  {t.chain.map((hop, j) => (
                    <React.Fragment key={j}>
                      <ArrowRightIcon className="size-3 text-zinc-500" />
                      <span className={`rounded px-1.5 py-0.5 text-[10px] ${j === t.chain.length - 1 ? "bg-green-900/50 text-green-300" : "bg-purple-900/50 text-purple-300"}`}>
                        {hop}
                        {j > 0 && <span className="ml-0.5 text-[8px] opacity-60">L{j + 1}</span>}
                      </span>
                    </React.Fragment>
                  ))}
                  <ArrowRightIcon className="size-3 text-zinc-500" />
                  <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">内网</span>
                </div>
              ))}
              {maxDepth > 1 && (
                <div className="mt-1 text-[9px] text-amber-400">
                  ⚡ 多层穿透（{maxDepth} 层）——可访问最深层 beacon 所在网段
                </div>
              )}
            </div>

            {/* 隧道详情表 */}
            <table className="w-full">
              <thead className="text-zinc-500">
                <tr className="text-left border-b border-zinc-800">
                  <th className="py-1 pl-2">主机</th>
                  <th>内网 IP</th>
                  <th>远程端口</th>
                  <th>链路</th>
                  <th>状态</th>
                  <th>时间</th>
                </tr>
              </thead>
              <tbody>
                {state.tunnels.map((t, i) => (
                  <tr key={i} className="border-b border-zinc-800/60">
                    <td className="py-0.5 pl-2 font-semibold text-blue-400">{t.hostname}</td>
                    <td className="font-mono text-zinc-300">{t.internal_ip}</td>
                    <td className="font-mono text-zinc-400">:{t.remote_port}</td>
                    <td className="text-zinc-400">{t.chain.join(" → ")}</td>
                    <td>
                      <span className={`rounded px-1 ${t.status === "active" ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"}`}>
                        {t.status}
                      </span>
                    </td>
                    <td className="text-zinc-500">{t.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* 使用说明 */}
            <div className="rounded border border-zinc-700 bg-zinc-800/50 p-2 text-[10px] text-zinc-400">
              <div className="mb-1 font-semibold">使用方法</div>
              <div>1. 浏览器/代理工具（Burp/curl/浏览器）连接 <code className="rounded bg-zinc-900 px-1">socks5://127.0.0.1:{state.socks_port}</code></div>
              <div>2. 所有流量将经过目标机进入其内网</div>
              <div>3. 多层场景：先对 DMZ 层 beacon 建隧道，再对内网 beacon 建隧道（链式）</div>
            </div>
          </div>
        ) : (
          <div className="flex h-full items-center justify-center">
            <div className="text-center text-zinc-500">
              <GlobeIcon className="mx-auto mb-2 size-10 opacity-20" />
              <div className="text-sm">暂无隧道</div>
              <div className="mt-1 text-[10px] opacity-50">
                点「建立隧道」——SOCKS5 在平台启动 + 目标机 socat 反弹<br/>
                完成后浏览器连 socks5://127.0.0.1:{socksPort} 即可穿透内网
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
