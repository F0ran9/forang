"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, GlobeIcon, LinkIcon, RefreshCwIcon, SendIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type TunnelInfo = {
  entry: string;
  host: string;
  token: string;
  share_base: string;
  notify_base: string;
  auto_sync: boolean;
  in_sync: boolean;
  unit_active: boolean;
  entry_file: string;
};

function authHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? window.localStorage.getItem("mixcx_token") : "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// TunnelCard 显示当前公网入口（Cloudflare 临时隧道），支持一键重建与回连地址同步。
// 关键点：推送回链必须是公网可达地址，否则飞书里点审批/详情无效。
export function TunnelCard() {
  const [info, setInfo] = React.useState<TunnelInfo | null>(null);
  const [busy, setBusy] = React.useState<"refresh" | "sync" | "notify" | null>(null);
  const [copied, setCopied] = React.useState(false);

  const load = React.useCallback(() => {
    fetch("/api/tunnel", { headers: authHeaders() })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setInfo)
      .catch(() => undefined);
  }, []);

  React.useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, [load]);

  const copy = () => {
    if (!info?.entry) return;
    navigator.clipboard
      .writeText(info.entry)
      .then(() => {
        setCopied(true);
        toast.success("入口链接已复制（等同密码，注意别外传）");
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => toast.error("复制失败，请手动选中复制"));
  };

  const refresh = () => {
    if (!window.confirm("重建隧道会分配新域名，旧链接立即失效（回连地址会自动同步）。继续？")) return;
    setBusy("refresh");
    fetch("/api/tunnel/refresh", { method: "POST", headers: authHeaders() })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok) throw new Error(d?.error || "重建失败");
        setInfo(d);
        toast.success(d.synced ? "新隧道已就绪，回连地址已同步" : "新隧道已就绪，请点「同步回连地址」");
        if (d.entry) navigator.clipboard?.writeText(d.entry).catch(() => undefined);
      })
      .catch((e) => toast.error("重建失败：" + (e as Error).message))
      .finally(() => setBusy(null));
  };

  const sync = () => {
    setBusy("sync");
    fetch("/api/tunnel/sync", { method: "POST", headers: authHeaders() })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok) throw new Error(d?.error || "同步失败");
        setInfo(d);
        toast.success("回连地址已更新为公网入口");
      })
      .catch((e) => toast.error("同步失败：" + (e as Error).message))
      .finally(() => setBusy(null));
  };

  const notifyFeishu = () => {
    setBusy("notify");
    fetch("/api/tunnel/notify", { method: "POST", headers: authHeaders() })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok) throw new Error(d?.error || "推送失败");
        toast.success("已推送到飞书，请查看手机");
      })
      .catch((e) => toast.error("推送失败：" + (e as Error).message))
      .finally(() => setBusy(null));
  };

  const toggleAuto = (v: boolean) => {
    if (!info) return;
    setInfo({ ...info, auto_sync: v });
    fetch("/api/settings", {
      method: "PUT",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ tunnel_auto_sync: v }),
    })
      .then(() => toast.success(v ? "已开启：换域名时自动同步回连地址" : "已关闭自动同步"))
      .catch(() => toast.error("保存失败"));
  };

  const bad = !info?.entry || !info?.unit_active;

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <GlobeIcon className="size-4" />
          公网入口
        </CardTitle>
        <CardDescription>
          手机/外网访问用的隧道地址。推送回链（飞书审批、任务详情）必须走这个地址，否则点开无效。
          入口变化时会自动推送到飞书。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={info?.unit_active ? "secondary" : "destructive"}>
            {info?.unit_active ? "隧道运行中" : "隧道未运行"}
          </Badge>
          {info?.entry && info.token && <Badge variant="outline">隐身入口已启用</Badge>}
          {info && !info.in_sync && <Badge variant="outline" className="text-amber-600">回连地址未同步</Badge>}
        </div>

        <div className="space-y-1.5">
          <Label className="text-xs">当前公网链接</Label>
          <div className="flex gap-2">
            <Input readOnly value={info?.entry || "（尚未生成，点下方「重建隧道」）"} className="font-mono text-xs" />
            <Button size="sm" variant="outline" onClick={copy} disabled={!info?.entry}>
              {copied ? <CheckIcon /> : <CopyIcon />}
            </Button>
          </div>
        </div>

        <div className="space-y-1.5">
          <Label className="text-xs">推送回连地址（飞书卡片按钮用的基址）</Label>
          <Input readOnly value={info?.notify_base || "（未设置）"} className="font-mono text-xs" />
          {info && !info.in_sync && (
            <p className="flex items-start gap-1.5 text-xs text-amber-600">
              <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
              与当前公网入口不一致，飞书里点审批/详情会打不开，点「同步回连地址」修正。
            </p>
          )}
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-xs">
          <input
            type="checkbox"
            className="size-3.5 accent-primary"
            checked={info?.auto_sync ?? true}
            onChange={(e) => toggleAuto(e.target.checked)}
          />
          隧道换域名时自动同步回连地址（推荐开启）
        </label>

        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onClick={sync} disabled={busy !== null || !info?.entry}>
            <LinkIcon className={busy === "sync" ? "animate-pulse" : ""} />
            {busy === "sync" ? "同步中…" : "同步回连地址"}
          </Button>
          <Button size="sm" variant="outline" onClick={refresh} disabled={busy !== null}>
            <RefreshCwIcon className={busy === "refresh" ? "animate-spin" : ""} />
            {busy === "refresh" ? "重建中（约 20 秒）…" : "重建隧道"}
          </Button>
          <Button size="sm" variant="ghost" onClick={notifyFeishu} disabled={busy !== null || !info?.entry}>
            <SendIcon className={busy === "notify" ? "animate-pulse" : ""} />
            发到飞书
          </Button>
        </div>

        {bad && (
          <p className="text-xs text-muted-foreground">
            隧道没起来时：SSH 上服务器执行 <code className="font-mono">systemctl status mixcx-tunnel</code> 看日志。
          </p>
        )}
      </CardContent>
    </Card>
  );
}
