"use client";

// c2-graph-panel.tsx — C2 攻击链路图（FORANG 探索图同构 SVG 可视化）+ AI 指挥官：
//   左：SVG 树形图（节点圆形/连线/颜色分类/缩放拖拽/点击详情）
//   右：AI 指挥官（自然语言 → AI 规划 → 执行 → 自动建节点）
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
  beacon: "#ef4444",
  cmd: "#3b82f6",
  asset: "#22c55e",
  cred: "#eab308",
  lateral: "#a855f7",
  ai_insight: "#06b6d4",
};
const typeLabel: Record<string, string> = {
  beacon: "Beacon",
  cmd: "命令",
  asset: "资产",
  cred: "凭据",
  lateral: "横向",
  ai_insight: "AI",
};
const NODE_W = 160;
const NODE_H = 36;
const GAP_X = 200;
const GAP_Y = 56;

// 布局：递归计算每个节点的 x/y
interface LayoutNode {
  node: GNode;
  x: number; y: number;
  children: LayoutNode[];
}

function layout(nodes: GNode[], depth = 0, xOffset = { v: 0 }): LayoutNode[] {
  return nodes.map((n) => {
    const ln: LayoutNode = { node: n, x: 0, y: depth * GAP_Y, children: [] };
    if (n.children && n.children.length > 0) {
      ln.children = layout(n.children, depth + 1, xOffset);
      // x = 子节点平均
      ln.x = (ln.children[0].x + ln.children[ln.children.length - 1].x) / 2;
    } else {
      ln.x = xOffset.v * GAP_X;
      xOffset.v += 1;
    }
    return ln;
  });
}

function countLeaves(nodes: GNode[]): number {
  let c = 0;
  const walk = (ns: GNode[]) => {
    for (const n of ns) {
      if (!n.children || n.children.length === 0) c++;
      else walk(n.children);
    }
  };
  walk(nodes);
  return Math.max(c, 1);
}

export default function C2GraphPanel({ beaconId }: { beaconId: string }) {
  const [nodes, setNodes] = React.useState<GNode[]>([]);
  const [selNode, setSelNode] = React.useState<GNode | null>(null);
  const [instruction, setInstruction] = React.useState("");
  const [aiReply, setAiReply] = React.useState("");
  const [aiResults, setAiResults] = React.useState<ExecResult[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [showAI, setShowAI] = React.useState(true);
  const [zoom, setZoom] = React.useState(1);
  const [pan, setPan] = React.useState({ x: 0, y: 0 });
  const dragRef = React.useRef<{ x: number; y: number } | null>(null);
  const svgRef = React.useRef<SVGSVGElement>(null);

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
    setBusy(true); setAiReply(""); setAiResults([]);
    try {
      const r = await fetch("/api/tools/c2/ai", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ session_id: beaconId, instruction }),
      });
      const j = await r.json() as { data?: { ai_reply?: string; results?: ExecResult[] } };
      if (j.data?.ai_reply) setAiReply(j.data.ai_reply);
      if (j.data?.results) setAiResults(j.data.results);
      load();
    } catch (e) { setAiReply("错误: " + (e instanceof Error ? e.message : String(e))); }
    finally { setBusy(false); }
  };

  const suggest = async () => {
    setBusy(true);
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

  // SVG 鼠标拖拽
  const onMouseDown = (e: React.MouseEvent) => {
    dragRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };
  const onMouseMove = (e: React.MouseEvent) => {
    if (dragRef.current) {
      setPan({ x: e.clientX - dragRef.current.x, y: e.clientY - dragRef.current.y });
    }
  };
  const onMouseUp = () => { dragRef.current = null; };

  // 布局
  const laidOut = React.useMemo(() => {
    const offset = { v: 0 };
    return layout(nodes, 0, offset);
  }, [nodes]);
  const leaves = countLeaves(nodes);
  const svgW = Math.max(leaves * GAP_X + 100, 600);
  const svgH = Math.max(nodes.length > 0 ? getMaxDepth(nodes) * GAP_Y + 100 : 300, 300);

  // 渲染连线 + 节点
  const renderEdges = (lns: LayoutNode[]): React.ReactNode[] => {
    const edges: React.ReactNode[] = [];
    const walk = (items: LayoutNode[]) => {
      for (const ln of items) {
        for (const c of ln.children) {
          edges.push(
            <path
              key={`e-${ln.node.id}-${c.node.id}`}
              d={`M ${ln.x + NODE_W / 2} ${ln.y + NODE_H / 2} C ${ln.x + NODE_W / 2} ${ln.y + GAP_Y / 2}, ${c.x + NODE_W / 2} ${c.y - GAP_Y / 2}, ${c.x + NODE_W / 2} ${c.y}`}
              stroke={typeColor[c.node.node_type] || "#3f3f46"}
              strokeWidth={1.5}
              fill="none"
              opacity={0.6}
            />,
          );
          walk([c]);
        }
      }
    };
    walk(lns);
    return edges;
  };

  const renderNodes = (lns: LayoutNode[]): React.ReactNode[] => {
    const result: React.ReactNode[] = [];
    const walk = (items: LayoutNode[]) => {
      for (const ln of items) {
        const n = ln.node;
        const color = typeColor[n.node_type] || "#71717a";
        result.push(
          <g key={n.id} transform={`translate(${ln.x}, ${ln.y})`} className="cursor-pointer"
             onClick={() => setSelNode(n)}>
            {/* 节点背景 */}
            <rect
              width={NODE_W} height={NODE_H} rx={6} ry={6}
              fill={n.status === "failed" ? "#450a0a" : "#18181b"}
              stroke={color}
              strokeWidth={n.status === "running" ? 2 : 1.5}
              strokeDasharray={n.status === "running" ? "4,2" : undefined}
            />
            {/* 状态灯 */}
            <circle cx={10} cy={NODE_H / 2} r={4} fill={color}
              className={n.status === "running" ? "animate-pulse" : ""} />
            {/* 类型标签 */}
            <text x={22} y={14} fontSize={8} fill={color} fontWeight="bold">
              {typeLabel[n.node_type] || n.node_type}
            </text>
            {/* 节点名 */}
            <text x={22} y={27} fontSize={10} fill="#d4d4d8" fontWeight="500">
              {n.label.length > 14 ? n.label.slice(0, 13) + "…" : n.label}
            </text>
          </g>,
        );
        walk(ln.children);
      }
    };
    walk(lns);
    return result;
  };

  return (
    <div className="flex h-full text-[11px]">
      {/* 左：链路图 SVG */}
      <div className={`flex min-w-0 flex-1 flex-col ${showAI ? "" : "w-full"}`}>
        <div className="flex items-center gap-1 border-b border-zinc-800 px-2 py-1">
          <NetworkIcon className="size-3.5 text-red-400" />
          <span className="font-semibold text-zinc-300">攻击链路图</span>
          <span className="text-zinc-500">{countAll(nodes)} 节点</span>
          {/* 图例 */}
          <div className="ml-2 flex gap-1.5">
            {Object.entries(typeColor).map(([t, c]) => (
              <span key={t} className="flex items-center gap-0.5 text-[9px] text-zinc-500">
                <span className="size-1.5 rounded-full" style={{ background: c }} />
                {typeLabel[t]}
              </span>
            ))}
          </div>
          <div className="ml-auto flex items-center gap-1">
            <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={() => setZoom(z => Math.max(0.5, z - 0.15))}>−</button>
            <span className="w-8 text-center text-zinc-400">{Math.round(zoom * 100)}%</span>
            <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={() => setZoom(z => Math.min(2, z + 0.15))}>+</button>
            <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>重置</button>
            <button className="rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={load}><RefreshCw className="size-3" /></button>
            <button className="rounded border border-red-800 bg-red-950/50 px-1.5 py-0.5 text-red-300 hover:bg-red-900/50" onClick={clearGraph}><TrashIcon className="size-3" /></button>
            <button className={`rounded border px-1.5 py-0.5 ${showAI ? "border-blue-500 bg-blue-500/10" : "border-zinc-700"}`} onClick={() => setShowAI(!showAI)}><BotIcon className="size-3" /></button>
          </div>
        </div>
        <div
          className="relative min-h-0 flex-1 overflow-hidden bg-black/50"
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
        >
          {nodes.length === 0 ? (
            <div className="flex h-full items-center justify-center text-zinc-500">
              <div className="text-center">
                <NetworkIcon className="mx-auto mb-2 size-10 opacity-20" />
                <div className="text-sm">暂无攻击链路数据</div>
                <div className="mt-1 text-[10px] opacity-50">用右侧 AI 指挥官下达指令，或手动添加节点</div>
              </div>
            </div>
          ) : (
            <svg
              ref={svgRef}
              width="100%" height="100%"
              viewBox={`0 0 ${svgW} ${svgH}`}
              style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, transformOrigin: "0 0", cursor: dragRef.current ? "grabbing" : "grab" }}
            >
              {renderEdges(laidOut)}
              {renderNodes(laidOut)}
            </svg>
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
              <ZapIcon className="mr-0.5 inline size-2.5" /> 建议下一步
            </button>
          </div>
          <div className="border-b border-zinc-800 p-2">
            <textarea
              className="h-16 w-full rounded border border-zinc-700 bg-zinc-800 p-1.5 text-zinc-200 placeholder:text-zinc-600"
              placeholder="自然语言指令，如：获取所有凭据 / 提权探测 / 扫描内网"
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
              <PlayIcon className="size-3" /> {busy ? "执行中…" : "AI 规划并执行"}
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
                {typeLabel[selNode.node_type]} — {selNode.label}
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

function getMaxDepth(nodes: GNode[], depth = 1): number {
  let max = depth;
  for (const n of nodes) {
    if (n.children) {
      max = Math.max(max, getMaxDepth(n.children, depth + 1));
    }
  }
  return max;
}

function countAll(nodes: GNode[]): number {
  let c = 0;
  const walk = (ns: GNode[]) => { for (const n of ns) { c++; if (n.children) walk(n.children); } };
  walk(nodes);
  return c;
}
