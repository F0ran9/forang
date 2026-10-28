"use client";

// 漏洞中枢（移植自全链哨兵 vuln hub）：结构化漏洞记录（CVSS+原始数据包）→
// LLM 评审员重定级 → 操作员复核（待确认/已确认/误报/已修复）+ 时间线 → Markdown 导出。
// agent 侧通过 vuln_submit / vuln_list / vuln_get 写入同一张表。
import * as React from "react";

import { BugIcon, DownloadIcon, FileTextIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, sseUrl } from "@/lib/api";
import type { VulnDetail, VulnRow } from "@/lib/types";

const SEV_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-red-500 text-white", medium: "bg-amber-500 text-white",
  low: "bg-blue-500 text-white", info: "bg-zinc-500 text-white",
};
const STATUS_LABEL: Record<string, string> = { pending: "待确认", confirmed: "已确认", false_positive: "误报", fixed: "已修复" };
const STATUS_CLASS: Record<string, string> = {
  pending: "border-amber-500 text-amber-600", confirmed: "border-green-600 text-green-700",
  false_positive: "border-zinc-400 text-zinc-500", fixed: "border-blue-500 text-blue-600",
};

function sevBadge(s: string) {
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${SEV_CLASS[s] || ""}`}>{SEV_LABEL[s] || s}</span>;
}
function statusBadge(s: string) {
  return <Badge variant="outline" className={STATUS_CLASS[s] || ""}>{STATUS_LABEL[s] || s}</Badge>;
}
function ratingNote(v: VulnRow): string {
  if (!v.review) return "代理自评（未评审）";
  if (v.review.state === "failed") return "代理自评（未评审）";
  if (v.review.state === "queued" || v.review.state === "running") return "评审中";
  return v.review.dubious ? "评审存疑" : "已重定级";
}

export default function VulnsPage() {
  const [rows, setRows] = React.useState<VulnRow[]>([]);
  const [status, setStatus] = React.useState("");
  const [q, setQ] = React.useState("");
  const [detail, setDetail] = React.useState<VulnDetail | null>(null);
  const [note, setNote] = React.useState("");

  const load = React.useCallback(() => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (q) params.set("q", q);
    api
      .vulnList(params.toString() ? `?${params.toString()}` : "")
      .then((r) => setRows((r.items ?? []) as VulnRow[]))
      .catch((e) => toast.error(`加载失败：${e.message}`));
  }, [status, q]);

  React.useEffect(() => {
    load();
  }, [load]);

  const open = (id: number) => {
    api.vulnGet(id).then((d) => setDetail(d)).catch((e) => toast.error(`详情失败：${e.message}`));
  };

  const patch = (id: number, s: string) => {
    api.vulnPatch(id, s, note).then((d) => { setDetail(d); load(); toast.success(`已${STATUS_LABEL[s]}`); }).catch((e) => toast.error(e.message));
  };

  const reReview = (id: number) => {
    api.vulnReview(id).then(() => { toast.success("已重新排队评审（约 20 秒内完成）"); setTimeout(open.bind(null, id), 25000); }).catch((e) => toast.error(e.message));
  };

  const exportFile = (format: "md" | "docx") => {
    const params = new URLSearchParams({ format });
    if (status) params.set("status", status);
    window.open(sseUrl(`/vulns/export?${params.toString()}`), "_blank");
  };

  return (
    <div className="flex min-w-0 flex-1 flex-col p-4 sm:p-6">
      <div className="mb-4 flex items-center justify-between gap-2">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-xl"><BugIcon className="size-5" />漏洞中枢</h1>
          <p className="text-muted-foreground text-sm">
            agent 用 vuln_submit 提交（CVSS 必填 + 原始数据包逐字保存）→ LLM 评审员按 CVSS v3.1 重定级（存疑封顶中危）→ 操作员复核。
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load}><RefreshCwIcon className="mr-1 size-4" />刷新</Button>
          <Button variant="outline" size="sm" onClick={() => exportFile("md")}><DownloadIcon className="mr-1 size-4" />Markdown</Button>
          <Button variant="outline" size="sm" onClick={() => exportFile("docx")}><FileTextIcon className="mr-1 size-4" />Word</Button>
        </div>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        {[["", "全部"], ["pending", "待确认"], ["confirmed", "已确认"], ["false_positive", "误报"], ["fixed", "已修复"]].map(([v, l]) => (
          <Button key={v} size="sm" variant={status === v ? "default" : "outline"} onClick={() => setStatus(v)}>{l}</Button>
        ))}
        <Input placeholder="搜索 label/标题/类别/描述…" value={q} onChange={(e) => setQ(e.target.value)}
          className="ml-auto w-64" onKeyDown={(e) => e.key === "Enter" && load()} />
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>编号</TableHead><TableHead>等级</TableHead><TableHead>状态</TableHead>
                <TableHead>标题</TableHead><TableHead>目标</TableHead><TableHead>定级来源</TableHead><TableHead>更新</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow><TableCell colSpan={7} className="text-muted-foreground py-8 text-center">暂无记录（agent 验证漏洞后用 vuln_submit 提交）</TableCell></TableRow>
              )}
              {rows.map((v) => (
                <TableRow key={v.id} className="cursor-pointer" onClick={() => open(v.id)}>
                  <TableCell className="font-mono text-xs">{v.label}</TableCell>
                  <TableCell>{sevBadge(v.severity)}<span className="ml-1 text-xs text-muted-foreground">{v.cvss.toFixed(1)}</span></TableCell>
                  <TableCell>{statusBadge(v.status)}</TableCell>
                  <TableCell className="max-w-72 truncate">{v.title}</TableCell>
                  <TableCell className="max-w-52 truncate text-xs">{v.target}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{ratingNote(v)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{new Date(v.updated_at).toLocaleString("zh-CN", { hour12: false })}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {detail && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={() => setDetail(null)}>
          <div className="h-full w-full max-w-2xl overflow-y-auto bg-background p-6" onClick={(e) => e.stopPropagation()}>
            <div className="mb-4 flex items-start justify-between gap-2">
              <div>
                <div className="font-mono text-xs text-muted-foreground">{detail.label}</div>
                <h2 className="font-semibold text-lg">{detail.title}</h2>
                <div className="mt-1 flex items-center gap-2">
                  {sevBadge(detail.severity)}
                  <span className="text-sm">CVSS {detail.cvss.toFixed(1)}</span>
                  {detail.cvss_vector && <span className="font-mono text-xs text-muted-foreground">{detail.cvss_vector}</span>}
                  {statusBadge(detail.status)}
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setDetail(null)}>关闭</Button>
            </div>

            {detail.review && (
              <Card className="mb-3">
                <CardHeader className="py-3"><CardTitle className="text-sm">评审员结论（{detail.review.state === "done" ? "已重定级" : detail.review.state}）</CardTitle></CardHeader>
                <CardContent className="text-sm">
                  {detail.review.state === "done" && (
                    <p className="mb-2">CVSS {detail.review.cvss?.toFixed(1)} · {detail.review.vector}{detail.review.dubious ? " · <span className='text-amber-600'>存疑（封顶中危）</span>" : ""}</p>
                  )}
                  <p className="text-muted-foreground">{detail.review.reason || "—"}</p>
                  <Button variant="outline" size="sm" className="mt-2" onClick={() => reReview(detail.id)}>重新评审</Button>
                </CardContent>
              </Card>
            )}

            <Card className="mb-3">
              <CardHeader className="py-3"><CardTitle className="text-sm">详情</CardTitle></CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div><span className="text-muted-foreground">目标：</span>{detail.target}{detail.category && ` · ${detail.category}`}</div>
                {detail.platform === "android" && <div><span className="text-muted-foreground">App：</span>{detail.app_package} {detail.app_version && `(${detail.app_version})`}</div>}
                <div><span className="text-muted-foreground">来源：</span>{detail.source} · {new Date(detail.created_at).toLocaleString("zh-CN", { hour12: false })}</div>
                <div className="whitespace-pre-wrap">{detail.description}</div>
                <div>
                  <div className="mb-1 font-medium">原始数据包</div>
                  <pre className="max-h-64 overflow-auto rounded bg-muted p-2 font-mono text-xs">{detail.packet}</pre>
                </div>
                {detail.repro && <div><div className="mb-1 font-medium">复现步骤</div><pre className="whitespace-pre-wrap text-xs">{detail.repro}</pre></div>}
                {detail.evidence && detail.evidence.length > 0 && (
                  <div>
                    <div className="mb-1 font-medium">证据</div>
                    {detail.evidence.map((e, i) => (
                      <div key={i} className="mb-1 text-xs">
                        [{e.kind}] {e.note}
                        {e.command && <pre className="mt-1 rounded bg-muted p-1 font-mono">{e.command}</pre>}
                        {e.path && <div className="text-muted-foreground">文件：{e.path}</div>}
                      </div>
                    ))}
                  </div>
                )}
                {detail.remediation && <div><div className="mb-1 font-medium">修复建议</div><div className="whitespace-pre-wrap">{detail.remediation}</div></div>}
              </CardContent>
            </Card>

            <Card className="mb-3">
              <CardHeader className="py-3"><CardTitle className="text-sm">处理时间线</CardTitle></CardHeader>
              <CardContent className="text-sm">
                {(detail.notes ?? []).length === 0 && <p className="text-muted-foreground">暂无记录</p>}
                {(detail.notes ?? []).map((n, i) => (
                  <div key={i} className="mb-1 text-xs">
                    <span className="text-muted-foreground">{new Date(n.at).toLocaleString("zh-CN", { hour12: false })} {n.author}：</span>{n.text}
                  </div>
                ))}
              </CardContent>
            </Card>

            <div className="space-y-2">
              <Label>复核备注（随状态变更写入时间线）</Label>
              <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="如：已按 PoC 复现 / 与开发确认误报" />
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" className="border-green-600 text-green-700" onClick={() => patch(detail.id, "confirmed")}>确认漏洞</Button>
                <Button size="sm" variant="outline" onClick={() => patch(detail.id, "false_positive")}>标记误报</Button>
                <Button size="sm" variant="outline" className="border-blue-500 text-blue-600" onClick={() => patch(detail.id, "fixed")}>标记已修复</Button>
                <Button size="sm" variant="outline" onClick={() => patch(detail.id, "pending")}>重置待确认</Button>
                <Button size="sm" variant="ghost" onClick={() => { if (note.trim()) { api.vulnNote(detail.id, note).then(() => { setNote(""); open(detail.id); }); } }}>仅追加备注</Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
