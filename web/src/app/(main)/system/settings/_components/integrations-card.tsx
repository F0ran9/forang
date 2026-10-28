"use client";

// 平台集成设置卡（哨兵移植批次）：资产测绘（FOFA/Quake/Hunter）、Webhook 通知、
// Tavily 号池、监督员策略、拦截前缀白名单。全部独立加载，互不阻塞。
import * as React from "react";

import { FlaskConicalIcon, GlobeIcon, BellRingIcon, KeySquareIcon, EyeIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { NotifyConfig, SurveyPlatform, TavilyKeyRow } from "@/lib/types";

const PLATFORMS: [string, string][] = [["fofa", "FOFA"], ["quake", "360 Quake"], ["hunter", "奇安信 Hunter"]];
const STRATEGIES: [string, string][] = [
  ["steady", "稳健交付"], ["validation", "漏洞验证"], ["offensive", "红队推进"], ["stealth", "低噪声"], ["guarded", "避危险接口"],
];

function SurveyCard() {
  const [cfg, setCfg] = React.useState<Record<string, SurveyPlatform>>({});
  const [keys, setKeys] = React.useState<Record<string, string>>({});
  const [bases, setBases] = React.useState<Record<string, string>>({});
  const [testing, setTesting] = React.useState("");

  const load = React.useCallback(() => {
    api.surveyConfig().then((r) => {
      setCfg(r);
      const k: Record<string, string> = {};
      const b: Record<string, string> = {};
      for (const [p] of PLATFORMS) {
        k[p] = "";
        b[p] = r[p]?.base_url ?? "";
      }
      setKeys(k);
      setBases(b);
    }).catch(() => undefined);
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const save = (p: string, enabled: boolean) => {
    api.surveySet(p, { enabled, key: keys[p] || undefined, base_url: bases[p] ?? "" })
      .then((v) => { setCfg((c) => ({ ...c, [p]: v })); setKeys((k) => ({ ...k, [p]: "" })); toast.success(`已保存 ${p}（保存后自动验证）`); })
      .catch((e) => toast.error(e.message));
  };
  const test = (p: string) => {
    setTesting(p);
    api.surveyTest(p, keys[p] ?? "", bases[p] ?? "").then((r) => {
      if (r.ok) toast.success(`${p} 验证通过：${r.quota}`);
      else toast.error(`${p} 验证失败：${r.error}`);
      load();
    }).catch((e) => toast.error(e.message)).finally(() => setTesting(""));
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><GlobeIcon className="size-4" />资产测绘</CardTitle>
        <CardDescription>
          FOFA / 360 Quake / 奇安信 Hunter 公网测绘。只有「已启用 + 已配 Key + 验证通过」的平台才会对 agent 挂载 fofa_search / quake_search / hunter_search 工具；查询原始响应落 evidence/survey/，流水含失败（失败也耗额度）。BaseURL 可填反代前缀。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {PLATFORMS.map(([p, label]) => {
          const c = cfg[p];
          return (
            <div key={p} className="rounded-md border p-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-medium">
                  {label}
                  {c && <span className={`text-xs ${c.usable ? "text-green-600" : "text-muted-foreground"}`}>
                    {c.usable ? `可用 · ${c.status_quota || "已验证"}` : c.has_key ? (c.status_ok ? "已验证（未启用）" : `未验证${c.status_error ? `：${c.status_error.slice(0, 40)}` : ""}`) : "未配置"}
                  </span>}
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" disabled={testing === p} onClick={() => test(p)}>
                    {testing === p ? "验证中…" : "验证"}
                  </Button>
                  <Switch checked={!!c?.enabled} onCheckedChange={(v) => save(p, v)} />
                </div>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <div>
                  <Label className="text-xs">API Key{c?.has_key ? `（已存 …${c.key_tail}，留空保持）` : ""}</Label>
                  <Input type="password" value={keys[p] ?? ""} onChange={(e) => setKeys((k) => ({ ...k, [p]: e.target.value }))} placeholder={c?.has_key ? "留空保持不变" : "粘贴平台 API Key"} />
                </div>
                <div>
                  <Label className="text-xs">BaseURL（可选反代前缀，留空官方）</Label>
                  <Input value={bases[p] ?? ""} onChange={(e) => setBases((b) => ({ ...b, [p]: e.target.value }))} placeholder="https://your-proxy/fofa" />
                </div>
              </div>
              {c?.syntax && <p className="mt-1 text-xs text-muted-foreground">语法：{c.syntax}</p>}
              <Button size="sm" variant="outline" className="mt-2" onClick={() => save(p, !!c?.enabled)}>保存</Button>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function NotifyCard() {
  const [cfg, setCfg] = React.useState<NotifyConfig>({ dingtalk: { enabled: false, webhook: "", secret: "" }, feishu: { enabled: false, webhook: "", secret: "" } });
  React.useEffect(() => { api.notifyConfig().then(setCfg).catch(() => undefined); }, []);
  const save = () => api.notifySet(cfg).then(() => toast.success("已保存通知配置")).catch((e) => toast.error(e.message));
  const test = () => api.notifyTest().then(() => toast.success("测试消息已发出")).catch((e) => toast.error(`发送失败：${e.message}`));

  const row = (k: "dingtalk" | "feishu", label: string) => (
    <div className="rounded-md border p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-sm font-medium">{label}</span>
        <Switch checked={cfg[k].enabled} onCheckedChange={(v) => setCfg({ ...cfg, [k]: { ...cfg[k], enabled: v } })} />
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <div>
          <Label className="text-xs">Webhook（https）</Label>
          <Input value={cfg[k].webhook} onChange={(e) => setCfg({ ...cfg, [k]: { ...cfg[k], webhook: e.target.value } })} placeholder="https://oapi.dingtalk.com/robot/send?access_token=…" />
        </div>
        <div>
          <Label className="text-xs">加签密钥（可选）</Label>
          <Input type="password" value={cfg[k].secret} onChange={(e) => setCfg({ ...cfg, [k]: { ...cfg[k], secret: e.target.value } })} placeholder="SEC…" />
        </div>
      </div>
    </div>
  );
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><BellRingIcon className="size-4" />通知推送</CardTitle>
        <CardDescription>评审确认的高危/严重漏洞自动推送（dubious 存疑不推）。钉钉加签 timestamp+sign、飞书签名均为 HMAC-SHA256。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {row("dingtalk", "钉钉机器人")}
        {row("feishu", "飞书机器人")}
        <div className="flex gap-2">
          <Button size="sm" onClick={save}>保存</Button>
          <Button size="sm" variant="outline" onClick={test}>发送测试</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function TavilyPoolCard() {
  const [keys, setKeys] = React.useState<TavilyKeyRow[]>([]);
  const [draft, setDraft] = React.useState({ label: "", key: "" });
  const load = React.useCallback(() => { api.tavilyPool().then((r) => setKeys(r.keys ?? [])).catch(() => undefined); }, []);
  React.useEffect(() => { load(); }, [load]);

  const save = (list: { id: string; label: string; key?: string; enabled: boolean }[]) =>
    api.tavilyPoolSet(list).then(() => { load(); toast.success("号池已保存"); }).catch((e) => toast.error(e.message));
  const add = () => {
    if (!draft.key.trim()) return toast.warning("请填入 Key");
    const next: { id: string; label: string; key?: string; enabled: boolean }[] = keys.map((k) => ({ id: k.id, label: k.label, enabled: k.enabled }));
    next.push({ id: "", label: draft.label || `Key ${keys.length + 1}`, key: draft.key.trim(), enabled: true });
    setDraft({ label: "", key: "" });
    save(next);
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><KeySquareIcon className="size-4" />Tavily 号池</CardTitle>
        <CardDescription>
          多 Key 按剩余额度择优（60s /usage 缓存，401/403 自动跳出）。需同时在「网络搜索」选择 tavily 后端；另提供 web_extract 正文抓取工具。SDK 单次调用内不中途换 Key。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {keys.map((k, i) => (
          <div key={k.id || i} className="flex items-center gap-2 rounded-md border p-2 text-sm">
            <Switch checked={k.enabled} onCheckedChange={(v) => save(keys.map((x, j) => (j === i ? { id: x.id, label: x.label, enabled: v } : { id: x.id, label: x.label, enabled: x.enabled })))} />
            <span className="font-medium">{k.label}</span>
            <span className="text-xs text-muted-foreground">…{k.key_tail}</span>
            {k.usage && (
              <span className={`text-xs ${k.usage.dead ? "text-red-500" : "text-muted-foreground"}`}>
                {k.usage.dead ? "Key 无效" : k.usage.remaining > 1e12 ? "额度不限" : `剩余 ${Math.round(k.usage.remaining)}`}
              </span>
            )}
            <Button variant="ghost" size="sm" className="ml-auto text-destructive"
              onClick={() => save(keys.filter((_, j) => j !== i).map((x) => ({ id: x.id, label: x.label, enabled: x.enabled })))}>删除</Button>
          </div>
        ))}
        <div className="grid gap-2 sm:grid-cols-[1fr_2fr_auto]">
          <Input placeholder="标签（如 主号）" value={draft.label} onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
          <Input type="password" placeholder="tvly-…" value={draft.key} onChange={(e) => setDraft({ ...draft, key: e.target.value })} />
          <Button size="sm" onClick={add}>添加</Button>
        </div>
      </CardContent>
    </Card>
  );
}

function SupervisorStrategyCard() {
  const [strategy, setStrategy] = React.useState("steady");
  const [cfg, setCfg] = React.useState<{ enabled: boolean; strategy: string; interval_sec: number; min_actions: number } | null>(null);
  React.useEffect(() => {
    fetch("/api/supervisor/config", { headers: authHeaders() }).then((r) => r.json()).then((d) => {
      setStrategy(d.strategy ?? "steady");
      setCfg(d);
    }).catch(() => undefined);
  }, []);
  const save = (s: string) => {
    setStrategy(s);
    if (!cfg) return;
    fetch("/api/supervisor/config", { method: "PUT", headers: { ...authHeaders(), "Content-Type": "application/json" }, body: JSON.stringify({ ...cfg, strategy: s }) })
      .then(() => toast.success(`监督策略已切换：${s}`)).catch(() => toast.error("保存失败"));
  };
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><EyeIcon className="size-4" />监督员策略</CardTitle>
        <CardDescription>监督模式（第二个 LLM 旁观工具流）的作战策略：滚动维护「已测/已排除」，digest 脱敏后判定空转并注入建议。</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-2">
        {STRATEGIES.map(([v, l]) => (
          <Button key={v} size="sm" variant={strategy === v ? "default" : "outline"} onClick={() => save(v)} disabled={!cfg}>{l}</Button>
        ))}
      </CardContent>
    </Card>
  );
}

function PrefixCard() {
  const [v, setV] = React.useState("");
  React.useEffect(() => { api.interceptPrefixes().then((r) => setV(r.prefixes ?? "")).catch(() => undefined); }, []);
  const save = () => api.interceptPrefixesSet(v).then(() => toast.success("前缀白名单已保存")).catch((e) => toast.error(e.message));
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><ShieldCheckIcon className="size-4" />命令前缀白名单</CardTitle>
        <CardDescription>逗号分隔的命令首词（如 nmap,nuclei,httpx）：规则未命中且非复合命令（&&/||/;/管道/替换）时直接放行，不进 AI 审批。</CardDescription>
      </CardHeader>
      <CardContent className="flex gap-2">
        <Input value={v} onChange={(e) => setV(e.target.value)} placeholder="nmap,nuclei,httpx,subfinder" />
        <Button size="sm" onClick={save}>保存</Button>
      </CardContent>
    </Card>
  );
}

function authHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? window.localStorage.getItem("forang_token") : "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function IntegrationsCards() {
  return (
    <>
      <SurveyCard />
      <SupervisorStrategyCard />
      <NotifyCard />
      <TavilyPoolCard />
      <PrefixCard />
    </>
  );
}

export { FlaskConicalIcon };

