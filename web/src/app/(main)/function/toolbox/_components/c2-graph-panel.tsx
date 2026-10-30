"use client";

// c2-graph-panel.tsx — C2 攻击链路图 + AI 驱动（参考 oktos GoalManagement + FORANG 探索图）：
//   左：链路图（SVG 树形可视化，节点按类型着色，点击展开详情）
//   右：AI 指挥官（自然语言指令 → AI 规划 → 执行 → 自动建节点）
import React from "react";
import { api } from "@/lib/api";
import { NetworkIcon, BotIcon, PlayIcon, RefreshCw, TrashIcon, ZapIcon } from "lucide-react";

interface GNode {
  id: number;
  session_id: string;
  parent_id: number | null;
  node_type: string;
  label: string;
  detail: string;
  status: string;
  created_at: string;
  children?: GNode[];
}

interface ExecResult {
  node_id: number;
  cmd: string;
  label: string;
  output: string;
  reason: string;
  ok: boolean;
}

const typeColor: Record<string, string> = {
  beacon: "#f87171",
  cmd: "#60a5fa",
  asset: "#4ade80",
  cred: "#fbbf24",
  lateral: "#c084fc",
  ai_insight: "#38bdf8",
};
const typeLabel: Record<string, string> = {
  beacon: "Beacon",
  cmd: "命令",
  asset: "资产",
  cred: "凭据",
  lateral: "横向",
  ai_insight: "AI",
};

export default function C2GraphPanel({ beaconId }: { beaconId: string }) {
  const [nodes, setNodes] = React.useState<GNode[]>([]);
  const [selNode, setSelNode] = React.useState<GNode | null>(null);
  const [instruction, setInstruction] = React.useState("");
  const [aiReply, setAiReply] = React.useState("");
  const [aiResults, setAiResults] = React.useState<ExecResult[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [showAI, setShowAI] = React.useState(true);

  const load = React.useCallback(async () => {
    try {
      const r = await fetch(`/api/tools/c2/graph?session_id=${beaconId}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
      const j = await r.json() as { data?: GNode[] };
      setNodes(j.data || []);
    } catch { /* ignore */ }
  }, [beaconId]);
  React.useEffect(() => { load(); }, [load]);

  const aiDrive = async () => {
    if (!instruction.trim()) return;
    setBusy(true);
    setAiReply("");
    setAiResults([]);
    try {
      const r = await fetch("/api/tools/c2/ai", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId, instruction }),
      });
      const j = await r.json() as { data?: { ai_reply?: string; executed?: number; results?: ExecResult[] } };
      if (j.data?.ai_reply) setAiReply(j.data.ai_reply);
      if (j.data?.results) setAiResults(j.data.results);
      load();
    } catch (e) {
      setAiReply("错误: " + (e instanceof Error ? e.message : String(e)));
    } finally { setBusy(false); }
  };

  const suggest = async () => {
    setBusy(true);
    setInstruction("请建议下一步最有价值的行动");
    try {
      const r = await fetch(`/api/tools/c2/ai/suggestions?session_id=${beaconId}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
      const j = await r.json() as { data?: { suggestions?: string } };
      if (j.data?.suggestions) setAiReply(j.data.suggestions);
    } finally { setBusy(false); }
  };

  const clearGraph = async () => {
    if (!window.confirm("清空此会话的攻击链路图？")) return;
    await fetch(`/api/tools/c2/graph/${beaconId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
    });
    load();
  };

  return (
    <div className="flex h-full text-[11px]">
      {/* 左：链路图 */}
      <div className={`flex min-w-0 flex-1 flex-col ${showAI ? "" : "w-full"}`}>
        <div className="flex items-center gap-1 border-b border-zinc-800 px-2 py-1">
          <NetworkIcon className="size-3.5 text-red-400" />
          <span className="font-semibold text-zinc-300">攻击链路图</span>
          <span className="text-zinc-500">{countNodes(nodes)} 节点</span>
          <div className="ml-auto flex gap-1">
            <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={load}><RefreshCw className="size-3" /></button>
            <button className="rounded border border-red-800 bg-red-950/50 px-1.5 py-0.5 text-red-300 hover:bg-red-900/50" onClick={clearGraph}><TrashIcon className="size-3" /></button>
            <button className={`rounded border px-1.5 py-0.5 ${showAI ? "border-blue-500 bg-blue-500/10" : "border-zinc-700"}`} onClick={() => setShowAI(!showAI)}><BotIcon className="size-3" /></button>
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto bg-black/40 p-3">
          {nodes.length === 0 ? (
            <div className="flex h-full items-center justify-center text-zinc-500">
              <div className="text-center">
                <NetworkIcon className="mx-auto mb-2 size-8 opacity-30" />
                <div>暂无节点——用右侧 AI 指挥官下达指令</div>
                <div className="mt-1 text-[10px] opacity-50">如：「获取系统信息和凭据」「提权探测」「内网横向扫描」</div>
              </div>
            </div>
          ) : (
            <div className="space-y-1">{nodes.map((n) => renderNode(n, 0, setSelNode))}</div>
          )}
        </div>
      </div>

      {/* 右：AI 指挥官 */}
      {showAI && (
        <div className="flex w-72 shrink-0 flex-col border-l border-zinc-700">
          <div className="flex items-center gap-1 border-b border-zinc-800 bg-zinc-800/50 px-2 py-1">
            <BotIcon className="size-3.5 text-blue-400" />
            <span className="font-semibold text-blue-300">AI 指挥官</span>
            <button className="ml-auto rounded border border-zinc-700 bg-zinc-800 px-1 py-0.5 text-[10px] hover:bg-zinc-700" onClick={suggest} disabled={busy}>
              <ZapIcon className="mr-0.5 inline size-2.5" /> 建议
            </button>
          </div>
          <div className="border-b border-zinc-800 p-2">
            <textarea
              className="h-16 w-full rounded border border-zinc-700 bg-zinc-800 p-1.5 text-zinc-200 placeholder:text-zinc-600"
              placeholder="自然语言指令，如：获取所有凭据 / 提权探测 / 扫描内网 / 分析当前权限"
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); aiDrive(); } }}
              disabled={busy}
            />
            <button
              className="mt-1 flex w-full items-center justify-center gap-1 rounded bg-blue-600 py-1 text-white hover:bg-blue-500 disabled:opacity-40"
              onClick={aiDrive}
              disabled={busy || !instruction.trim()}
            >
              <PlayIcon className="size-3" /> {busy ? "执行中…" : "执行"}
            </button>
          </div>
          <div className="min-h-0 flex-1 overflow-auto p-2">
            {aiResults.map((r) => (
              <div key={r.node_id} className={`mb-1.5 rounded border p-1.5 ${r.ok ? "border-zinc-700" : "border-red-800"}`}>
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-blue-300">{r.label}</span>
                  <span className={`text-[10px] ${r.ok ? "text-green-400" : "text-red-400"}`}>{r.ok ? "✓" : "✗"}</span>
                </div>
                <div className="text-[10px] text-zinc-500">$ {r.cmd.slice(0, 50)}</div>
                <div className="mt-0.5 font-mono text-[10px] text-zinc-400">{r.output.slice(0, 120)}</div>
                {r.reason && <div className="mt-0.5 text-[9px] italic text-zinc-600">{r.reason}</div>}
              </div>
            ))}
            {aiReply && <pre className="whitespace-pre-wrap text-[10px] text-zinc-500">{aiReply}</pre>}
            {!aiResults.length && !aiReply && (
              <div className="pt-4 text-center text-[10px] text-zinc-600">
                AI 基于攻击链路图上下文规划并执行命令，结果自动入图。
              </div>
            )}
          </div>
        </div>
      )}

      {/* 节点详情弹窗 */}
      {selNode && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setSelNode(null)}>
          <div className="max-h-[60vh] w-[480px] overflow-auto rounded-lg border border-zinc-600 bg-zinc-900 p-3" onClick={(e) => e.stopPropagation()}>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-semibold" style={{ color: typeColor[selNode.node_type] || "#fff" }}>
                {typeLabel[selNode.node_type] || selNode.node_type} — {selNode.label}
              </span>
              <button onClick={() => setSelNode(null)} className="text-zinc-500 hover:text-white">✕</button>
            </div>
            <pre className="whitespace-pre-wrap rounded bg-black/50 p-2 font-mono text-[11px] text-zinc-300">{selNode.detail || "（无详情）"}</pre>
            <div className="mt-2 text-[10px] text-zinc-500">状态: {selNode.status} · 时间: {selNode.created_at}</div>
          </div>
        </div>
      )}
    </div>
  );
}

// 递归渲染节点
function renderNode(n: GNode, depth: number, onSel: (n: GNode) => void): React.ReactNode {
  const color = typeColor[n.node_type] || "#71717a";
  return (
    <div key={n.id}>
      <div
        className="group flex cursor-pointer items-center gap-1.5 rounded px-1 py-0.5 hover:bg-zinc-800/60"
        style={{ paddingLeft: `${depth * 20 + 4}px` }}
        onClick={() => onSel(n)}
      >
        <span className="size-2 shrink-0 rounded-full" style={{ background: color }} />
        <span className="truncate font-mono" style={{ color: n.status === "failed" ? "#f87171" : "#d4d4d8" }}>
          {n.label}
        </span>
        <span className="shrink-0 text-[9px] text-zinc-600">{n.created_at}</span>
        {n.status === "running" && <span className="animate-pulse text-[9px] text-amber-400">…</span>}
      </div>
      {n.children?.map((c) => renderNode(c, depth + 1, onSel))}
    </div>
  );
}

function countNodes(nodes: GNode[]): number {
  let c = 0;
  const walk = (ns: GNode[]) => { for (const n of ns) { c++; if (n.children) walk(n.children); } };
  walk(nodes);
  return c;
}
