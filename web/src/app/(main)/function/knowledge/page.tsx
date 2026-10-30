// 知识库 —— 任务终态自动蒸馏沉淀 + 跨任务检索复用（移植自 AI-PENTEST knowledge 模块）。
// 左：总结列表（搜索/状态/统计）；右：选中总结 markdown 详情 + 重新生成。
// agent 侧同源能力为 kb_search 工具（开新任务前查过往沉淀）。
"use client";

import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type DictEntry, type KBSummary, type KBSummaryDetail } from "@/lib/api";
import { BookOpen, PlayIcon, RefreshCw, DownloadIcon, PlusIcon, TrashIcon } from "lucide-react";

export default function KnowledgePage() {
  const [mod, setMod] = React.useState<"summaries" | "dicts">("summaries");
  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          <BookOpen className="size-5" /> 知识库
        </h1>
        <div className="flex gap-1 rounded border p-0.5 text-sm">
          {([["summaries", "经验总结"], ["dicts", "字典中心"]] as const).map(([k, label]) => (
            <button
              key={k}
              className={`rounded px-3 py-1 ${mod === k ? "bg-muted font-semibold" : "text-muted-foreground hover:bg-muted/50"}`}
              onClick={() => setMod(k)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {mod === "summaries" ? <SummariesModule /> : <DictsModule />}
    </div>
  );
}

function SummariesModule() {
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
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-end gap-2">
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
        PoC）/ 经验教训 / 下次建议；LLM 失败自动降级模板。蒸馏同时把 findings/facts 里的路径、凭据、参数名沉淀进字典中心；agent 可用 kb_search / dict_query 检索复用。
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

// ==================== 字典中心 ====================

const DICT_KINDS: { key: string; label: string }[] = [
  { key: "path", label: "路径/目录/API" },
  { key: "user", label: "用户名" },
  { key: "pass", label: "密码" },
  { key: "param", label: "敏感参数" },
  { key: "subdomain", label: "子域名" },
];

function DictsModule() {
  const [kind, setKind] = React.useState("path");
  const [q, setQ] = React.useState("");
  const [entries, setEntries] = React.useState<DictEntry[]>([]);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [addOpen, setAddOpen] = React.useState(false);
  const [addValues, setAddValues] = React.useState("");
  const [addNote, setAddNote] = React.useState("");
  const searchDeb = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = React.useCallback(async (k: string, query?: string) => {
    try {
      const r = await api.kbDicts(k, query);
      setEntries(r.data || []);
      setCounts(r.counts || {});
    } catch {
      /* ignore */
    }
  }, []);

  React.useEffect(() => {
    load(kind);
  }, [kind, load]);

  const onSearch = (v: string) => {
    setQ(v);
    if (searchDeb.current) clearTimeout(searchDeb.current);
    searchDeb.current = setTimeout(() => load(kind, v.trim() || undefined), 300);
  };

  const add = async () => {
    if (!addValues.trim()) return;
    try {
      const r = await api.kbDictCreate({ kind, values: addValues, note: addNote });
      setAddOpen(false);
      setAddValues("");
      setAddNote("");
      load(kind, q.trim() || undefined);
      window.alert(`已添加 ${r.added} 条`);
    } catch (e) {
      window.alert("失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  const remove = async (id: number) => {
    if (!window.confirm("删除该条目？（内置种子不可删）")) return;
    try {
      await api.kbDictDelete(id);
      load(kind, q.trim() || undefined);
    } catch (e) {
      window.alert("失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  const exportDict = async () => {
    try {
      const token = localStorage.getItem("forang_token") || "";
      const resp = await fetch(api.kbDictExportUrl(kind), { headers: { Authorization: `Bearer ${token}` } });
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `dict-${kind}.txt`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      window.alert("导出失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  return (
    <div className="space-y-3">
      <div className="rounded border bg-muted/30 p-3 text-xs text-muted-foreground">
        五类字典沉淀复用：<b>路径/目录/API</b>（目录与 API 同构，统一为一类）、用户名、密码、敏感参数、子域名。
        三路沉淀：任务蒸馏自动提取 findings/facts 里的路径与凭据；目录扫描命中自动回灌（命中次数越刷越高）；
        agent 用 dict_add 主动记录。目录扫描默认联用本字典（命中多的路径优先测）。导出 txt 可直接喂 hydra / dirsearch / Intruder。
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {DICT_KINDS.map((k) => (
          <button
            key={k.key}
            className={`rounded px-2.5 py-1 text-sm ${kind === k.key ? "bg-muted font-semibold" : "text-muted-foreground hover:bg-muted/50"}`}
            onClick={() => setKind(k.key)}
          >
            {k.label}（{counts[k.key] || 0}）
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <Input
            className="h-8 w-44 text-xs"
            placeholder="搜索值/说明/上下文…"
            value={q}
            onChange={(e) => onSearch(e.target.value)}
          />
          <Button variant="outline" size="sm" onClick={() => setAddOpen(!addOpen)}>
            <PlusIcon className="mr-1 size-4" /> 添加
          </Button>
          <Button variant="outline" size="sm" onClick={exportDict}>
            <DownloadIcon className="mr-1 size-4" /> 导出
          </Button>
        </div>
      </div>

      {addOpen && (
        <Card>
          <CardContent className="space-y-2 p-3 text-sm">
            <div className="text-xs text-muted-foreground">
              批量添加到「{DICT_KINDS.find((k) => k.key === kind)?.label}」：每行一条
            </div>
            <textarea
              className="h-28 w-full rounded border bg-transparent p-2 font-mono text-xs"
              value={addValues}
              onChange={(e) => setAddValues(e.target.value)}
              placeholder={kind === "path" ? "/actuator/env\n/admin/login" : "admin\ntest"}
            />
            <Input className="text-xs" placeholder="说明（可选，如：nacos 默认口令）" value={addNote} onChange={(e) => setAddNote(e.target.value)} />
            <Button size="sm" onClick={add}>提交</Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-2">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="py-1.5">值</th>
                <th className="w-14">命中</th>
                {kind === "path" && <th className="w-14">状态</th>}
                <th className="w-20">来源</th>
                <th className="w-32">上下文</th>
                <th className="w-28">说明</th>
                <th className="w-24">更新</th>
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-6 text-center text-muted-foreground">
                    暂无条目
                  </td>
                </tr>
              )}
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-border/40">
                  <td className="py-1 font-mono">
                    {kind === "path" ? "/" + e.value.replace(/^\/+/, "") : e.value}
                  </td>
                  <td className={e.hit_count > 1 ? "font-semibold text-green-600" : "text-muted-foreground"}>{e.hit_count}</td>
                  {kind === "path" && (
                    <td>
                      {e.last_status > 0 && (
                        <span
                          className={`rounded px-1 ${
                            e.last_status < 300
                              ? "bg-green-500/15 text-green-600"
                              : e.last_status < 400
                                ? "bg-amber-500/15 text-amber-500"
                                : "bg-orange-500/15 text-orange-500"
                          }`}
                        >
                          {e.last_status}
                        </span>
                      )}
                    </td>
                  )}
                  <td>
                    <span className="rounded bg-muted px-1 text-[10px] text-muted-foreground">{e.source}</span>
                  </td>
                  <td className="truncate text-muted-foreground" title={e.context}>{e.context || "-"}</td>
                  <td className="truncate text-muted-foreground" title={e.note}>{e.note || "-"}</td>
                  <td className="text-muted-foreground">{e.updated_at}</td>
                  <td>
                    {e.source !== "builtin" && (
                      <button title="删除" onClick={() => remove(e.id)}>
                        <TrashIcon className="size-3.5 text-red-400" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
