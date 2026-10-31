"use client";

// batch-create-sheet.tsx — 批量创建任务（纯 HTML 覆盖层，零 Radix 依赖）
import React from "react";
import { LayersIcon, Loader2Icon, XIcon } from "lucide-react";

export function BatchCreateSheet({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [batchName, setBatchName] = React.useState("");
  const [urls, setUrls] = React.useState("");
  const [goalTemplate, setGoalTemplate] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [result, setResult] = React.useState("");

  const urlCount = urls.split("\n").filter((u) => u.trim().startsWith("http")).length;

  const submit = async () => {
    const list = urls.split("\n").map((u) => u.trim()).filter((u) => u.startsWith("http"));
    if (list.length === 0) return;
    setBusy(true);
    setResult("");
    try {
      const r = await fetch("/api/batch/create", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ name: batchName || undefined, targets: list, goal_template: goalTemplate || undefined }),
      });
      const j = await r.json();
      setResult((j.data && j.data.message) || j.error || "");
      if (j.data && j.data.created) {
        onCreated();
        setTimeout(() => { setOpen(false); setUrls(""); setResult(""); }, 1500);
      }
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex h-8 items-center gap-1.5 rounded-md border px-3 text-sm font-medium transition-colors hover:bg-muted/50"
      >
        <LayersIcon className="h-4 w-4" />
        批量创建
      </button>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => !busy && setOpen(false)}>
      <div className="w-full max-w-2xl rounded-lg border bg-background p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold">批量创建任务</h2>
            <p className="text-sm text-muted-foreground">输入多个目标 URL，系统自动识别指纹并为每个目标创建独立任务。</p>
          </div>
          <button type="button" onClick={() => setOpen(false)} className="rounded p-1 hover:bg-muted">
            <XIcon className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium">批量名称</label>
            <input
              type="text"
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
              placeholder={"批量渗透（" + (urlCount || "N") + " 目标）"}
              value={batchName}
              onChange={(e) => setBatchName(e.target.value)}
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium">目标 URL（每行一个，最多 100 个）</label>
            <textarea
              className="min-h-32 w-full rounded-md border border-input bg-transparent p-2 font-mono text-xs"
              placeholder="http://target1.example.com&#10;http://target2.example.com:8080"
              value={urls}
              onChange={(e) => setUrls(e.target.value)}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              {urlCount > 0 ? urlCount + " 个有效 URL" : "输入以 http 开头的 URL"}
            </p>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium">目标模板（可选）</label>
            <textarea
              className="min-h-24 w-full rounded-md border border-input bg-transparent p-2 font-mono text-xs"
              placeholder="对目标 {URL} 进行渗透测试。指纹：{FINGERPRINT}"
              value={goalTemplate}
              onChange={(e) => setGoalTemplate(e.target.value)}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              <code className="rounded bg-muted px-1">{"{URL}"}</code> 替换为目标地址，
              <code className="rounded bg-muted px-1">{"{FINGERPRINT}"}</code> 替换为指纹结果
            </p>
          </div>

          {result && (
            <div
              className={"rounded-md border p-2.5 text-sm " + (result.includes("\u2705")
                ? "border-green-500/40 bg-green-500/10 text-green-600"
                : "border-red-500/40 bg-red-500/10 text-red-500")}
            >
              {result}
            </div>
          )}

          <button
            type="button"
            onClick={submit}
            disabled={busy || urlCount === 0}
            className="flex h-10 w-full items-center justify-center gap-2 rounded-md bg-primary text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-40"
          >
            {busy ? (
              <>
                <Loader2Icon className="h-4 w-4 animate-spin" />
                创建中…（指纹识别 + 任务生成）
              </>
            ) : (
              <>
                <LayersIcon className="h-4 w-4" />
                批量创建 {urlCount} 个任务
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
