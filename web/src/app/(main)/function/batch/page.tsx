"use client";

// batch/page.tsx — 批量资产渗透任务：多目标输入 → 自动指纹 → 每目标 AI 任务 → 进度汇总
import React from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  LayersIcon, PlayIcon, RefreshCw, TargetIcon, BugIcon, ChevronRightIcon,
  CheckCircleIcon, ClockIcon, AlertTriangleIcon,
} from "lucide-react";

interface BatchTarget {
  url: string;
  fingerprint?: string;
  task_id?: number;
  status: string;
}

interface Campaign {
  id: number;
  name: string;
  status: string;
  targets: BatchTarget[];
  created_at: string;
}

interface CampaignDetail {
  id: number;
  name: string;
  status: string;
  targets: BatchTarget[];
  task_details: Record<string, { task_id: number; task_status: string; findings: number; critical: number }>;
  summary: { total_targets: number; done: number; total_findings: number; critical: number };
}

export default function BatchPage() {
  const [campaigns, setCampaigns] = React.useState<Campaign[]>([]);
  const [sel, setSel] = React.useState<CampaignDetail | null>(null);
  const [name, setName] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [goalTemplate, setGoalTemplate] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const r = await fetch("/api/batch", {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
      const j = await r.json() as { data?: Campaign[] };
      setCampaigns(j.data || []);
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const create = async () => {
    const list = targets.split("\n").map(t => t.trim()).filter(t => t.startsWith("http"));
    if (list.length === 0) return void alert("请输入至少一个以 http 开头的 URL");
    setBusy(true); setMsg("");
    try {
      const r = await fetch("/api/batch/create", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ name, targets: list, goal_template: goalTemplate || undefined }),
      });
      const j = await r.json() as { data?: { campaign_id: number; message: string }; error?: string };
      setMsg(j.data?.message || j.error || "");
      load();
    } finally { setBusy(false); }
  };

  const openDetail = async (id: number) => {
    try {
      const r = await fetch(`/api/batch/${id}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
      const j = await r.json() as { data?: CampaignDetail };
      setSel(j.data || null);
    } catch { /* ignore */ }
  };

  return (
    <div className="space-y-4 p-4">
      <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
        <LayersIcon className="size-5" /> 批量资产渗透
      </h1>

      {/* 创建区 */}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm">创建批量战役</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Input placeholder="战役名称（可选，默认自动生成）" value={name} onChange={(e) => setName(e.target.value)} />
          <textarea
            className="h-32 w-full rounded border bg-transparent p-2 font-mono text-xs"
            placeholder={"每行一个目标 URL：\nhttp://target1.example.com\nhttp://target2.example.com:8080\nhttps://target3.example.com/admin"}
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
          />
          <textarea
            className="h-20 w-full rounded border bg-transparent p-2 text-xs"
            placeholder={"目标模板（可选，{URL} 和 {FINGERPRINT} 会被替换）：\n对目标 {URL} 进行渗透测试。指纹：{FINGERPRINT}\n优先检查未授权访问/默认凭据。"}
            value={goalTemplate}
            onChange={(e) => setGoalTemplate(e.target.value)}
          />
          <Button onClick={create} disabled={busy || !targets.trim()}>
            <PlayIcon className="mr-1 size-4" /> {busy ? "创建中…（指纹识别 + 任务生成）" : "创建批量战役"}
          </Button>
          {msg && <div className="rounded border bg-muted/30 p-2 text-xs">{msg}</div>}
        </CardContent>
      </Card>

      {/* 战役列表 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between py-2">
          <CardTitle className="text-sm">战役列表（{campaigns.length}）</CardTitle>
          <Button variant="outline" size="sm" onClick={load}><RefreshCw className="size-3.5" /></Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {campaigns.length === 0 && (
            <div className="py-6 text-center text-sm text-muted-foreground">暂无战役</div>
          )}
          {campaigns.map(c => (
            <div key={c.id}
                 className="flex cursor-pointer items-center gap-2 rounded border p-2 hover:bg-muted/40"
                 onClick={() => openDetail(c.id)}>
              <span className="font-medium">{c.name}</span>
              <span className="rounded bg-muted px-1.5 text-xs">{(c.targets || []).length} 目标</span>
              <span className={`rounded px-1.5 text-xs ${
                c.status === "done" ? "bg-green-500/15 text-green-600" :
                c.status === "created" ? "bg-blue-500/15 text-blue-500" :
                "bg-muted text-muted-foreground"
              }`}>{c.status}</span>
              <span className="ml-auto text-xs text-muted-foreground">{c.created_at}</span>
              <ChevronRightIcon className="size-4 opacity-40" />
            </div>
          ))}
        </CardContent>
      </Card>

      {/* 战役详情 */}
      {sel && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between py-2">
            <CardTitle className="text-sm">{sel.name} — 详情</CardTitle>
            <Button variant="outline" size="sm" onClick={() => setSel(null)}>收起</Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {/* 汇总 */}
            <div className="flex flex-wrap gap-2 text-sm">
              <span className="rounded border px-2 py-1">
                <TargetIcon className="mr-1 inline size-3.5" />
                {sel.summary.total_targets} 目标
              </span>
              <span className="rounded border px-2 py-1">
                <CheckCircleIcon className="mr-1 inline size-3.5 text-green-500" />
                {sel.summary.done} 完成
              </span>
              <span className="rounded border px-2 py-1">
                <BugIcon className="mr-1 inline size-3.5 text-red-500" />
                {sel.summary.total_findings} 发现
              </span>
              {sel.summary.critical > 0 && (
                <span className="rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-red-600">
                  <AlertTriangleIcon className="mr-1 inline size-3.5" />
                  {sel.summary.critical} critical
                </span>
              )}
            </div>

            {/* 目标进度表 */}
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="py-1.5">目标</th>
                  <th>指纹</th>
                  <th>任务</th>
                  <th>状态</th>
                  <th>发现</th>
                  <th className="w-20">操作</th>
                </tr>
              </thead>
              <tbody>
                {sel.targets.map((t, i) => {
                  const td = t.task_id ? sel.task_details[String(t.task_id)] : null;
                  return (
                    <tr key={i} className="border-b border-border/40">
                      <td className="py-1 font-mono text-blue-500">{t.url}</td>
                      <td className="text-muted-foreground">{t.fingerprint || "—"}</td>
                      <td>{t.task_id ? `#${t.task_id}` : "—"}</td>
                      <td>
                        <span className={`rounded px-1.5 ${
                          td?.task_status === "done" ? "bg-green-500/15 text-green-600" :
                          td?.task_status === "running" ? "bg-blue-500/15 text-blue-500 animate-pulse" :
                          "bg-muted text-muted-foreground"
                        }`}>
                          {td?.task_status || t.status}
                        </span>
                      </td>
                      <td>
                        {td && td.findings > 0 && (
                          <span className="text-red-500">{td.findings}</span>
                        )}
                        {td && td.critical > 0 && (
                          <span className="ml-1 text-red-600 font-bold">⚠{td.critical}</span>
                        )}
                      </td>
                      <td>
                        {t.task_id && (
                          <Link href={`/function/tasks/detail?id=${t.task_id}`}
                                className="text-blue-400 hover:underline">
                            详情 <ChevronRightIcon className="inline size-3" />
                          </Link>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
