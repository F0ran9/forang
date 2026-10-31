"use client";

// realtime-panel.tsx — 实时仪表盘面板（SSE 驱动）：C2/Webshell/知识库/AI 全平台态势
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  BotIcon, BugIcon, DatabaseIcon, FileTextIcon, GlobeIcon, PackageIcon,
  ShieldIcon, TargetIcon, TerminalIcon, ZapIcon, ActivityIcon, ChevronRightIcon,
} from "lucide-react";
import Link from "next/link";

interface DashData {
  active_tasks: number;
  total_findings: number;
  critical_finds: number;
  high_finds: number;
  c2_online: boolean;
  c2_sessions: number;
  c2_autopilot: boolean;
  c2_tunnels: number;
  webshell_targets: number;
  webshell_alive: number;
  kb_total: number;
  kb_chunks: number;
  dict_total: number;
  llm_profiles: number;
  token_input: number;
  token_output: number;
  c2_ai_calls: number;
  c2_auto_findings: number;
  total_assets: number;
  repeater_history: number;
  scan_jobs: number;
  timestamp: string;
}

function Metric({ icon, label, value, color, sub }: {
  icon: React.ReactNode; label: string; value: string | number; color: string; sub?: string;
}) {
  return (
    <div className="flex items-center gap-2 rounded-lg border p-3">
      <div className="flex size-9 shrink-0 items-center justify-center rounded-lg" style={{ background: color + "20" }}>
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-xl font-bold tabular-nums" style={{ color }}>{value}</div>
        <div className="text-xs text-muted-foreground">{label}{sub ? ` · ${sub}` : ""}</div>
      </div>
    </div>
  );
}

export default function RealtimePanel() {
  const [data, setData] = React.useState<DashData | null>(null);
  const [connected, setConnected] = React.useState(false);

  React.useEffect(() => {
    // 初始加载
    fetch("/api/dashboard/enhanced", {
      headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
    }).then(r => r.json()).then(j => setData(j.data || null)).catch(() => {});

    // SSE 实时
    const es = new EventSource("/api/dashboard/stream");
    es.addEventListener("dashboard", (e) => {
      try {
        setData(JSON.parse((e as MessageEvent).data));
        setConnected(true);
      } catch { /* ignore */ }
    });
    es.onerror = () => setConnected(false);

    // 兜底轮询（SSE 断开时）
    const fallback = setInterval(() => {
      if (!connected) {
        fetch("/api/dashboard/enhanced", {
          headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        }).then(r => r.json()).then(j => setData(j.data || null)).catch(() => {});
      }
    }, 10000);

    return () => { es.close(); clearInterval(fallback); };
  }, []);

  if (!data) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">
          <ActivityIcon className="mx-auto mb-2 size-6 opacity-30" />
          加载实时数据…
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {/* 实时状态指示 */}
      <div className="flex items-center gap-2 text-xs">
        <span className={`flex items-center gap-1 rounded px-2 py-0.5 ${connected ? "bg-green-500/15 text-green-600" : "bg-muted text-muted-foreground"}`}>
          <span className={`size-1.5 rounded-full ${connected ? "animate-pulse bg-green-500" : "bg-zinc-400"}`} />
          {connected ? "SSE 实时" : "轮询模式"} · {data.timestamp}
        </span>
        {data.c2_autopilot && (
          <span className="flex items-center gap-1 rounded bg-purple-500/15 px-2 py-0.5 text-purple-600">
            <BotIcon className="size-3 animate-pulse" /> AI 自动驾驶运行中
          </span>
        )}
      </div>

      {/* 第一行：核心作战指标 */}
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-6">
        <Link href="/function/tasks">
          <Metric icon={<TargetIcon className="size-4 text-blue-500" />} label="进行中任务" value={data.active_tasks} color="#3b82f6" />
        </Link>
        <Link href="/function/findings">
          <Metric icon={<BugIcon className="size-4 text-red-500" />} label="漏洞发现" value={data.total_findings} color="#ef4444" sub={`${data.critical_finds} critical`} />
        </Link>
        <Link href="/function/toolbox">
          <Metric icon={<TerminalIcon className="size-4 text-purple-500" />} label="C2 会话" value={data.c2_sessions} color={data.c2_online ? "#a855f7" : "#71717a"} sub={data.c2_online ? "在线" : "离线"} />
        </Link>
        <Metric icon={<ShieldIcon className="size-4 text-green-500" />} label="Webshell" value={data.webshell_alive} color="#22c55e" sub={`${data.webshell_targets} 目标`} />
        <Metric icon={<GlobeIcon className="size-4 text-cyan-500" />} label="活跃隧道" value={data.c2_tunnels} color="#06b6d4" />
        <Metric icon={<PackageIcon className="size-4 text-amber-500" />} label="资产" value={data.total_assets} color="#eab308" />
      </div>

      {/* 第二行：AI/知识/工具箱 */}
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-6">
        <Metric icon={<ZapIcon className="size-4 text-violet-500" />} label="AI 调用(C2)" value={data.c2_ai_calls} color="#8b5cf6" sub={`${data.c2_auto_findings} 发现`} />
        <Metric icon={<FileTextIcon className="size-4 text-blue-400" />} label="知识总结" value={data.kb_total} color="#60a5fa" sub={`${data.kb_chunks} chunks`} />
        <Metric icon={<DatabaseIcon className="size-4 text-orange-500" />} label="字典条目" value={data.dict_total} color="#f97316" />
        <Metric icon={<ActivityIcon className="size-4 text-pink-500" />} label="Token 输入" value={fmt(data.token_input)} color="#ec4899" />
        <Metric icon={<ActivityIcon className="size-4 text-indigo-500" />} label="Token 输出" value={fmt(data.token_output)} color="#6366f1" />
        <Metric icon={<TargetIcon className="size-4 text-teal-500" />} label="扫描任务" value={data.scan_jobs} color="#14b8a6" />
      </div>

      {/* 快捷入口 */}
      <div className="flex flex-wrap gap-2">
        {[
          { href: "/function/toolbox", label: "工具箱", icon: <TerminalIcon className="size-3.5" /> },
          { href: "/function/findings", label: "漏洞中台", icon: <BugIcon className="size-3.5" /> },
          { href: "/function/knowledge", label: "知识库", icon: <FileTextIcon className="size-3.5" /> },
          { href: "/function/tasks", label: "任务管理", icon: <TargetIcon className="size-3.5" /> },
        ].map((l) => (
          <Link key={l.href} href={l.href}
            className="flex items-center gap-1 rounded border px-3 py-1 text-xs hover:bg-muted/50">
            {l.icon} {l.label} <ChevronRightIcon className="size-3 opacity-40" />
          </Link>
        ))}
      </div>
    </div>
  );
}

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return String(n);
}
