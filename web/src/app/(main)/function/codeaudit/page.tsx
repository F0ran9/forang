"use client";

// codeaudit/page.tsx — 源码审计：上传源码 zip（XHR 进度条，支持大包）→ 一键创建审计任务。
// 审计任务里 agent 只读源码（Read/Grep/Glob），工具面按任务收口：不出网、不执行命令。
import * as React from "react";
import Link from "next/link";

import { FileCode2Icon, FolderArchiveIcon, Loader2Icon, Trash2Icon, UploadIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { CodeUpload } from "@/lib/types";

function fmtSize(n: number): string {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + " GB";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MB";
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KB";
  return n + " B";
}

export default function CodeAuditPage() {
  const [uploads, setUploads] = React.useState<CodeUpload[]>([]);
  const [file, setFile] = React.useState<File | null>(null);
  const [progress, setProgress] = React.useState(-1); // -1=空闲，0-100=上传中
  const [focus, setFocus] = React.useState("");
  const [creating, setCreating] = React.useState("");

  const load = React.useCallback(() => {
    api.codeUploadsList().then(setUploads).catch(() => undefined);
  }, []);
  React.useEffect(() => {
    load();
  }, [load]);

  const upload = () => {
    if (!file) return;
    setProgress(0);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/codeaudit/upload");
    xhr.setRequestHeader("Authorization", `Bearer ${localStorage.getItem("forang_token") || ""}`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) setProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      setProgress(-1);
      try {
        const j = JSON.parse(xhr.responseText);
        if (xhr.status >= 400) {
          toast.error(j.error || `上传失败（HTTP ${xhr.status}）`);
          return;
        }
        toast.success(`已解压 ${j.file_count} 个文件（${fmtSize(j.total_bytes)}）`);
        setFile(null);
        load();
      } catch {
        toast.error("上传响应解析失败");
      }
    };
    xhr.onerror = () => {
      setProgress(-1);
      toast.error("上传失败：网络中断（大包上传请确认网络稳定，上限 2GB）");
    };
    const fd = new FormData();
    fd.append("file", file);
    xhr.send(fd);
  };

  const createTask = (u: CodeUpload) => {
    setCreating(u.id);
    api
      .codeAuditCreateTask(u.id, focus)
      .then((r) => {
        toast.success(`审计任务 #${r.task_id} 已创建并开始执行`);
        load();
      })
      .catch((e) => toast.error(e.message))
      .finally(() => setCreating(""));
  };

  const open = uploads.filter((u) => !u.task_id);
  const used = uploads.filter((u) => u.task_id);

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <div>
        <h1 className="flex items-center gap-2 text-lg font-semibold">
          <FileCode2Icon className="size-5" /> 源码审计
        </h1>
        <p className="text-sm text-muted-foreground">
          上传源码 zip → AI 静态审计：接口清点与权限判定、SQL 注入 / 命令执行 / 未授权 / 路径穿越 / 硬编码凭据，
          每条漏洞带 文件:行号 + 代码片段。审计任务不出网、不执行命令，结论全部由源码证据支撑。
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><FolderArchiveIcon className="size-4" /> 上传源码包</CardTitle>
          <CardDescription>仅支持 .zip，上限 2GB / 解压后 6GB / 30 万文件。上传后立即解压，创建任务时搬入任务目录。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-64 flex-1">
              <Label className="text-xs">源码 zip</Label>
              <Input
                type="file"
                accept=".zip"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className="mt-1"
              />
              {file ? (
                <p className="mt-1 text-xs text-muted-foreground">
                  {file.name} · {fmtSize(file.size)}
                </p>
              ) : null}
            </div>
            <Button onClick={upload} disabled={!file || progress >= 0}>
              {progress >= 0 ? <Loader2Icon className="mr-1 size-4 animate-spin" /> : <UploadIcon className="mr-1 size-4" />}
              {progress >= 0 ? `上传中 ${progress}%` : "上传并解压"}
            </Button>
          </div>
          {progress >= 0 ? (
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div className="h-full bg-primary transition-all" style={{ width: `${progress}%` }} />
            </div>
          ) : null}
          <div>
            <Label className="text-xs">审计重点（可选，留空全面审计）</Label>
            <Input
              className="mt-1"
              placeholder="如：重点查订单接口的越权与支付金额篡改"
              value={focus}
              onChange={(e) => setFocus(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">待审计源码（{open.length}）</CardTitle>
          <CardDescription>上传后可随时创建审计任务；刷新页面不丢失。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {open.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">暂无待审计源码——上传 zip 开始。</p>
          ) : (
            open.map((u) => (
              <div key={u.id} className="flex flex-wrap items-center gap-3 rounded-md border p-3">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{u.filename}</p>
                  <p className="text-xs text-muted-foreground">
                    {u.file_count} 文件 · {fmtSize(u.total_bytes)} · {u.created_at}
                    {u.entries?.length ? ` · 顶层: ${u.entries.slice(0, 5).join("、")}${u.entries.length > 5 ? "…" : ""}` : ""}
                  </p>
                </div>
                <Button size="sm" disabled={creating === u.id} onClick={() => createTask(u)}>
                  {creating === u.id ? <Loader2Icon className="mr-1 size-3.5 animate-spin" /> : <FileCode2Icon className="mr-1 size-3.5" />}
                  {creating === u.id ? "创建中…" : "开始审计"}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => api.codeUploadDelete(u.id).then(load).catch((e) => toast.error(e.message))}>
                  <Trash2Icon className="size-3.5" />
                </Button>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {used.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">已审计（{used.length}）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {used.map((u) => (
              <div key={u.id} className="flex items-center gap-3 rounded-md border p-3">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm">{u.filename}</p>
                  <p className="text-xs text-muted-foreground">{u.file_count} 文件 · {fmtSize(u.total_bytes)}</p>
                </div>
                {u.task_id ? (
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={cn(
                      "text-[10px]",
                      u.task_status === "done" ? "border-green-500/40 text-green-600" : "border-blue-500/40 text-blue-600",
                    )}>
                      {u.task_status === "done" ? "审计完成" : u.task_status === "running" ? "审计中" : u.task_status === "failed" ? "失败" : u.task_status || "—"}
                    </Badge>
                    <Link
                      href={`/function/tasks/detail?id=${u.task_id}`}
                      className="text-sm text-primary hover:underline"
                    >
                      #{u.task_id} →
                    </Link>
                  </div>
                ) : null}
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
