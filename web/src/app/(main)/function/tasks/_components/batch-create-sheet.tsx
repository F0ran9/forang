"use client";

// batch-create-sheet.tsx — 批量创建任务抽屉（与新建任务同风格，集成到任务模块）
// 多 URL → 自动指纹 → 每目标创建标准任务 → 任务出现在任务列表
import React from "react";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription, SheetTrigger,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { LayersIcon, Loader2Icon } from "lucide-react";

export function BatchCreateSheet({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [batchName, setBatchName] = React.useState("");
  const [urls, setUrls] = React.useState("");
  const [goalTemplate, setGoalTemplate] = React.useState("");
  const [autoFP, setAutoFP] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [result, setResult] = React.useState<string>("");

  const urlCount = urls.split("\n").filter((u) => u.trim().startsWith("http")).length;

  const submit = async () => {
    const list = urls.split("\n").map((u) => u.trim()).filter((u) => u.startsWith("http"));
    if (list.length === 0) return;
    setBusy(true); setResult("");
    try {
      const r = await fetch("/api/batch/create", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({
          name: batchName || undefined,
          targets: list,
          goal_template: goalTemplate || undefined,
        }),
      });
      const j = await r.json() as { data?: { created: number; message: string }; error?: string };
      setResult(j.data?.message || j.error || "");
      if (j.data?.created) {
        onCreated();
        setTimeout(() => { setOpen(false); setUrls(""); setResult(""); }, 1500);
      }
    } finally { setBusy(false); }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button size="sm" variant="outline">
          <LayersIcon className="size-4" /> 批量创建
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-full! max-w-none! gap-0 p-0 sm:w-[45vw]! sm:max-w-[45vw]!">
        <SheetHeader className="border-b p-6">
          <SheetTitle>批量创建任务</SheetTitle>
          <SheetDescription>输入多个目标 URL，系统自动识别指纹并为每个目标创建独立的 AI 渗透任务。</SheetDescription>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto p-6">
          <div className="grid gap-5">
            <div className="grid gap-2">
              <Label>批量名称（可选）</Label>
              <input
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm"
                placeholder={`批量渗透（${urlCount || "N"} 目标）`}
                value={batchName}
                onChange={(e) => setBatchName(e.target.value)}
              />
            </div>

            <div className="grid gap-2">
              <Label>目标 URL（每行一个，最多 100 个）</Label>
              <Textarea
                className="min-h-40 font-mono text-xs"
                placeholder={"http://target1.example.com\nhttp://target2.example.com:8080\nhttps://target3.example.com"}
                value={urls}
                onChange={(e) => setUrls(e.target.value)}
              />
              <div className="text-xs text-muted-foreground">
                {urlCount > 0 ? `${urlCount} 个有效 URL` : "输入以 http 开头的 URL"}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Switch checked={autoFP} onCheckedChange={setAutoFP} />
              <span className="text-sm">自动指纹识别</span>
              <span className="text-xs text-muted-foreground">
                {autoFP ? "并发识别每个目标的技术栈，结果写入任务目标" : "跳过指纹，直接创建任务"}
              </span>
            </div>

            <div className="grid gap-2">
              <Label>目标模板（可选）</Label>
              <Textarea
                className="min-h-28 font-mono text-xs"
                placeholder={
"对目标 {URL} 进行渗透测试，尽可能多地发现高危漏洞。\n指纹：{FINGERPRINT}\n优先检查未授权访问/默认凭据/已知漏洞。"
                }
                value={goalTemplate}
                onChange={(e) => setGoalTemplate(e.target.value)}
              />
              <div className="text-xs text-muted-foreground">
                <code>{"{URL}"}</code> 替换为目标地址，<code>{"{FINGERPRINT}"}</code> 替换为指纹结果
              </div>
            </div>

            {result && (
              <div className={`rounded-md border p-3 text-sm ${result.startsWith("✅") ? "border-green-500/40 bg-green-500/10 text-green-600" : "border-red-500/40 bg-red-500/10 text-red-500"}`}>
                {result}
              </div>
            )}
          </div>
        </div>

        <div className="border-t p-6">
          <Button className="w-full" onClick={submit} disabled={busy || urlCount === 0}>
            {busy ? (
              <>
                <Loader2Icon className="mr-2 size-4 animate-spin" />
                创建中…（指纹识别 + 任务生成）
              </>
            ) : (
              <>
                <LayersIcon className="mr-2 size-4" />
                批量创建 {urlCount} 个任务
              </>
            )}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}
