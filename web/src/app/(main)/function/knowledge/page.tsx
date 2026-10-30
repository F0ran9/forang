// 知识库 —— 任务终态自动蒸馏沉淀 + 跨任务检索复用（移植自 AI-PENTEST knowledge 模块）。
// 左：总结列表（搜索/状态/统计）；右：选中总结 markdown 详情 + 重新生成。
// agent 侧同源能力为 kb_search 工具（开新任务前查过往沉淀）。
"use client";

import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type KBSummary, type KBSummaryDetail } from "@/lib/api";
import { BookOpen, PlayIcon, RefreshCw } from "lucide-react";

export default function KnowledgePage() {
  const [q, setQ] = React.useState("");
  const [list, setList] = React.useState<KBSummary[]>([]);
  const [ov, setOv] = React.useState<{ total: number; done: number; failed: number; vulns: number; chunks: number } | null>(null);
  const [cur, setCur] = React.useState<KBSummaryDetail | null>(null);
  const [busy, setBusy] = React.useState(false);
  const searchDeb = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = React.useCallback(async (query?: string) => {
    try {
      const [o, l] = await Promise.all([api.kbOverview(), api.kbSummaries(query)]);
      setOv(o);
      setList(l.data || []);
    } catch {
      /* ignore */
    }
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const onSearch = (v: string) => {
    setQ(v);
    if (searchDeb.current) clearTimeout(searchDeb.current);
    searchDeb.current = setTimeout(() => load(v.trim() || undefined), 300);
  };

  const openDetail = async (taskId: number) => {
    try {
      const r = await api.kbSummaryDetail(taskId);
      setCur(r.data || null);
    } catch (e) {
      window.alert(e instanceof Error ? e.message : "加载失败");
    }
  };

  const regen = async (taskId: number) => {
    if (!window.confirm(`重新生成任务 #${taskId} 的知识总结？（LLM 真跑，约 30-120 秒）`)) return;
    setBusy(true);
    try {
      await api.kbRegenerate(taskId);
      window.alert("已提交重新生成，稍后刷新查看");
      setTimeout(() => load(q.trim() || undefined), 5000);
    } catch (e) {
      window.alert("失败: " + (e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };

  const statusColor = (st: string) =>
    st === "done" ? "bg-green-500/15 text-green-600" : st === "failed" ? "bg-red-500/15 text-red-500" : "bg-amber-500/15 text-amber-500";

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          <BookOpen className="size-5" /> 知识库
        </h1>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {ov && (
            <>
              <span className="rounded bg-muted px-2 py-1">总结 {ov.total}（成功 {ov.done} / 降级 {ov.failed}）</span>
              <span className="rounded bg-muted px-2 py-1">沉淀漏洞 {ov.vulns}</span>
              <span className="rounded bg-muted px-2 py-1">索引块 {ov.chunks}</span>
            </>
          )}
          <Button variant="outline" size="sm" onClick={() => load(q.trim() || undefined)}>
            <RefreshCw className="mr-1 size-4" /> 刷新
          </Button>
        </div>
      </div>

      <div className="rounded border bg-muted/30 p-3 text-xs text-muted-foreground">
        机制：任务终态（done/failed/timeout）自动蒸馏成四章知识总结 —— 执行概况 / 漏洞与可复用手法（含目标与
        PoC）/ 经验教训 / 下次建议；LLM 失败自动降级模板。agent 在新任务中可用 <code className="rounded bg-muted px-1">kb_search</code> 工具检索这些沉淀复用。
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <Card className="md:col-span-1">
          <CardHeader className="py-2">
            <CardTitle className="text-sm">
              <Input className="h-7 text-xs" placeholder="搜索标题/正文…" value={q} onChange={(e) => onSearch(e.target.value)} />
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-[620px] space-y-1 overflow-auto p-2">
            {list.length === 0 && (
              <div className="py-8 text-center text-xs text-muted-foreground">
                暂无总结。任务完结后 30 秒内自动蒸馏；也可在详情页点重新生成。
              </div>
            )}
            {list.map((it) => (
              <div
                key={it.task_id}
                className={`cursor-pointer rounded border p-2 text-xs hover:bg-muted/60 ${cur?.task_id === it.task_id ? "border-primary bg-muted" : ""}`}
                onClick={() => openDetail(it.task_id)}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="truncate font-medium">{it.title || `任务 #${it.task_id}`}</span>
                  <span className={`shrink-0 rounded px-1 ${statusColor(it.status)}`}>{it.status}</span>
                </div>
                <div className="mt-0.5 flex items-center gap-2 text-[10px] text-muted-foreground">
                  <span>#{it.task_id}</span>
                  <span>漏洞 {it.vuln_count}</span>
                  <span>记忆 {it.fact_count}</span>
                  <span>{it.updated_at}</span>
                  {it.source === "manual" && <span className="rounded bg-blue-500/15 px-1 text-blue-500">手动</span>}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between py-2">
            <CardTitle className="text-sm">{cur ? cur.title || `任务 #${cur.task_id}` : "总结详情"}</CardTitle>
            {cur && (
              <Button variant="outline" size="sm" onClick={() => regen(cur.task_id)} disabled={busy}>
                <PlayIcon className="mr-1 size-4" /> 重新生成
              </Button>
            )}
          </CardHeader>
          <CardContent className="p-2">
            {!cur && <div className="py-16 text-center text-sm text-muted-foreground">（左侧选择一条总结查看）</div>}
            {cur && (
              <>
                {cur.status === "failed" && cur.error && (
                  <div className="mb-2 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-600">
                    LLM 蒸馏失败已降级模板：{cur.error}
                  </div>
                )}
                <pre className="max-h-[580px] overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-3 font-mono text-xs leading-relaxed">
                  {cur.summary_md || "（空总结）"}
                </pre>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
