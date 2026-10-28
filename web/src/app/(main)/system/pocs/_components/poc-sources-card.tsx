"use client";

// POC 订阅源管理（哨兵 poc-subscriptions 移植）：官方 nuclei-templates zip 一键订阅、
// 定时同步、按模板 id 去重 upsert（只增不删）、同步历史（含失败）。
import * as React from "react";
import { CloudDownloadIcon, PlayIcon, PlusIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { PocSourceRow } from "@/lib/types";

type SourceInput = { id: string; name: string; url: string; auth_header?: string; interval_hours: number };

export function PocSourcesCard({ onChanged }: { onChanged?: () => void }) {
  const [sources, setSources] = React.useState<PocSourceRow[]>([]);
  const [history, setHistory] = React.useState<Record<string, { at: string; ok: boolean; message: string }[]>>({});
  const [syncing, setSyncing] = React.useState("");
  const [draft, setDraft] = React.useState({ name: "", url: "" });

  const load = React.useCallback(() => {
    api.pocSources().then((r) => { setSources(r.sources ?? []); setHistory(r.history ?? {}); }).catch(() => undefined);
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const toInput = (s: PocSourceRow): SourceInput =>
    ({ id: s.id, name: s.name, url: s.url, auth_header: s.auth_header, interval_hours: s.interval_hours });

  const save = (list: SourceInput[], ensureOfficial = false) =>
    api.pocSourcesSet(list, ensureOfficial).then(() => { load(); }).catch((e) => toast.error(e.message));

  const ensureOfficial = () => {
    save(sources.map(toInput), true);
    toast.success("官方源已添加（默认每周同步）");
  };
  const sync = (id: string) => {
    setSyncing(id);
    api.pocSync(id).then((r) => { toast.success(`${r.message}（大包首次同步需数分钟）`); onChanged?.(); load(); })
      .catch((e) => toast.error(`同步失败：${e.message}`)).finally(() => setSyncing(""));
  };
  const remove = (id: string) => save(sources.filter((s) => s.id !== id).map(toInput));
  const add = () => {
    if (!draft.url.trim()) { toast.warning("请填 URL"); return; }
    const next = sources.map(toInput);
    next.push({ id: `src-${Date.now() % 1000000}`, name: draft.name || "自定义源", url: draft.url.trim(), interval_hours: 0 });
    save(next);
    setDraft({ name: "", url: "" });
  };

  const hasOfficial = sources.some((s) => s.id === "official");
  return (
    <Card className="mb-4">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><CloudDownloadIcon className="size-4" />POC 订阅</CardTitle>
        <CardDescription>
          订阅 nuclei 模板压缩包（官方 main.zip ≈ 1.4 万模板）。按模板 id 去重 upsert、只增不删；interval_hours&gt;0 时定时同步。GitHub 直连不通可改镜像 URL（如 ghfast.top 前缀）。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {!hasOfficial && <Button size="sm" variant="outline" onClick={ensureOfficial}><PlusIcon className="mr-1 size-4" />一键添加官方源</Button>}
        {sources.map((s) => (
          <div key={s.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm">
            <span className="font-medium">{s.name}</span>
            <span className="max-w-72 truncate text-xs text-muted-foreground">{s.url}</span>
            {s.interval_hours > 0 && <span className="text-xs text-muted-foreground">每 {s.interval_hours}h</span>}
            {history[s.id]?.[0] && (
              <span className={`text-xs ${history[s.id][0].ok ? "text-muted-foreground" : "text-red-500"}`}>
                上次：{history[s.id][0].message}
              </span>
            )}
            <div className="ml-auto flex gap-1">
              <Button size="sm" variant="outline" disabled={syncing === s.id} onClick={() => sync(s.id)}>
                <PlayIcon className="mr-1 size-3" />{syncing === s.id ? "同步中…" : "立即同步"}
              </Button>
              {s.id !== "official" && <Button size="sm" variant="ghost" className="text-destructive" onClick={() => remove(s.id)}>删除</Button>}
            </div>
          </div>
        ))}
        <div className="grid gap-2 sm:grid-cols-[1fr_2fr_auto]">
          <Input placeholder="名称" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          <Input placeholder="https://…/templates.zip" value={draft.url} onChange={(e) => setDraft({ ...draft, url: e.target.value })} />
          <Button size="sm" onClick={add}>添加</Button>
        </div>
      </CardContent>
    </Card>
  );
}
