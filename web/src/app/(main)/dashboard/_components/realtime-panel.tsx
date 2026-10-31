"use client";

// realtime-panel.tsx — 作战态势条（仅显示现有仪表盘没有的指标：C2/Webshell/隧道/知识库/字典）
// 不重复已有的：任务/发现/资产/Token（下方原有面板已覆盖）
import React from "react";
import {
  BotIcon, DatabaseIcon, FileTextIcon, GlobeIcon, ShieldIcon, TerminalIcon,
  ActivityIcon,
} from "lucide-react";
import Link from "next/link";

interface OpsData {
  c2_online: boolean;
  c2_sessions: number;
  c2_autopilot: boolean;
  c2_tunnels: number;
  webshell_alive: number;
  webshell_targets: number;
  kb_total: number;
  dict_total: number;
  c2_ai_calls: number;
  c2_auto_findings: number;
  timestamp: string;
}

function Pill({ icon, label, value, color, href, pulse }: {
  icon: React.ReactNode; label: string; value: string | number; color: string; href?: string; pulse?: boolean;
}) {
  const content = (
    <div className="flex items-center gap-1.5 rounded-full border px-2.5 py-1 transition-colors hover:bg-muted/40">
      <span className={`shrink-0 ${pulse ? "animate-pulse" : ""}`} style={{ color }}>{icon}</span>
      <span className="text-xs font-semibold tabular-nums" style={{ color }}>{value}</span>
      <span className="text-[10px] text-muted-foreground">{label}</span>
    </div>
  );
  return href ? <Link href={href}>{content}</Link> : content;
}

export default function RealtimePanel() {
  const [data, setData] = React.useState<OpsData | null>(null);
  const [connected, setConnected] = React.useState(false);

  React.useEffect(() => {
    const load = () => {
      fetch("/api/dashboard/enhanced", {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      }).then(r => r.json()).then(j => setData(j.data || null)).catch(() => {});
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  if (!data) return null;

  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-lg border bg-muted/20 px-2 py-1.5">
      {/* 实时指示 */}
      <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
        <span className={`size-1.5 rounded-full ${connected ? "animate-pulse bg-green-500" : "bg-zinc-400"}`} />
        作战态势
      </span>

      {/* 仅新增指标（不与下方面板重复） */}
      <Pill icon={<TerminalIcon className="size-3" />} label="C2 会话" value={data.c2_sessions}
            color={data.c2_online ? "#a855f7" : "#71717a"} href="/function/toolbox" />
      <Pill icon={<ShieldIcon className="size-3" />} label="Webshell" value={`${data.webshell_alive}/${data.webshell_targets}`}
            color="#22c55e" href="/function/toolbox" />
      {data.c2_tunnels > 0 && (
        <Pill icon={<GlobeIcon className="size-3" />} label="隧道" value={data.c2_tunnels}
              color="#06b6d4" href="/function/toolbox" />
      )}
      {data.c2_autopilot && (
        <Pill icon={<BotIcon className="size-3" />} label="AI 驾驶" value="ON"
              color="#8b5cf6" pulse href="/function/toolbox" />
      )}
      <Pill icon={<FileTextIcon className="size-3" />} label="知识库" value={data.kb_total}
            color="#60a5fa" href="/function/knowledge" />
      <Pill icon={<DatabaseIcon className="size-3" />} label="字典" value={data.dict_total}
            color="#f97316" href="/function/knowledge" />
      {data.c2_ai_calls > 0 && (
        <Pill icon={<ActivityIcon className="size-3" />} label="AI 发现" value={data.c2_auto_findings}
              color="#ec4899" />
      )}
    </div>
  );
}
