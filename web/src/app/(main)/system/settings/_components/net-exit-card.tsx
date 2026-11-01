"use client";

// net-exit-card.tsx — 测试网络出口（内网/互联网分线）：
//   网线直连内网测试入口 → 出口类型 direct（系统路由自动走对网卡），点「自检」验证连通；
//   平台不在内网 → 出口改 socks5/http 代理（如 frp 反向 SOCKS5 / 跳板代理）；
//   网段规则决定目标走哪条线（192.168/10/172.16 → 内网测试，其余 → 互联网默认出口）。
//   平台原生工具（端口/目录扫描、指纹、Webshell）按规则选出口；agent Bash 走全局代理设置。
import * as React from "react";

import { CableIcon, PlusIcon, Trash2Icon, ZapIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { NetExit, NetExitConfig, NetRoute } from "@/lib/types";

const TYPES: [NetExit["type"], string][] = [
  ["direct", "直连（网卡/系统路由）"],
  ["socks5", "SOCKS5 代理"],
  ["http", "HTTP 代理"],
];

export function NetExitCard() {
  const [cfg, setCfg] = React.useState<NetExitConfig>({ exits: [], routes: [], default_exit: "" });
  const [checking, setChecking] = React.useState("");
  const [result, setResult] = React.useState<Record<string, string>>({});

  const load = React.useCallback(() => {
    api.netExitsGet().then(setCfg).catch(() => undefined);
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const patchExit = (i: number, p: Partial<NetExit>) =>
    setCfg((c) => ({ ...c, exits: c.exits.map((e, j) => (j === i ? { ...e, ...p } : e)) }));
  const patchRoute = (i: number, p: Partial<NetRoute>) =>
    setCfg((c) => ({ ...c, routes: c.routes.map((r, j) => (j === i ? { ...r, ...p } : r)) }));

  const save = () => {
    api.netExitsSet(cfg)
      .then(() => toast.success("测试网络出口已保存（5 秒内生效）"))
      .catch((e) => toast.error(e.message));
  };

  const check = (name: string) => {
    setChecking(name);
    api.netExitCheck(name)
      .then((r) => {
        setResult((s) => ({ ...s, [name]: r.ok ? `✅ ${r.detail ?? "连通"}` : `❌ ${r.error ?? "失败"}` }));
        if (r.ok) toast.success(`${name} 连通（${r.ms}ms）`);
        else toast.error(`${name} 不通：${r.error}`);
      })
      .catch((e) => toast.error(e.message))
      .finally(() => setChecking(""));
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><CableIcon className="size-4" /> 测试网络出口（内网 / 互联网分线）</CardTitle>
        <CardDescription>
          按目标网段选出口：端口/目录扫描、指纹识别、Webshell 连接自动走路由命中的出口。
          网线直连内网测试入口时用「直连」即可（系统路由自动走对网卡）；平台不在内网时改 SOCKS5/HTTP 代理出口。
          Agent 的 Bash 工具走「全局代理」设置，两者互补。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Label className="mb-1 block text-sm">出口列表</Label>
          <div className="space-y-2">
            {cfg.exits.map((e, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 rounded-md border p-2">
                <Input className="h-8 w-32 shrink-0" placeholder="名称" value={e.name} onChange={(ev) => patchExit(i, { name: ev.target.value })} />
                <select
                  className="h-8 w-48 shrink-0 rounded-md border bg-transparent px-2 text-sm"
                  value={e.type}
                  onChange={(ev) => patchExit(i, { type: ev.target.value as NetExit["type"] })}
                >
                  {TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
                <Input
                  className="h-8 min-w-48 flex-1"
                  placeholder={e.type === "direct" ? "（直连无需地址）" : "socks5://10.0.0.1:1080 或 http://ip:port"}
                  value={e.addr}
                  disabled={e.type === "direct"}
                  onChange={(ev) => patchExit(i, { addr: ev.target.value })}
                />
                <Input className="h-8 w-36 shrink-0" placeholder="备注" value={e.note} onChange={(ev) => patchExit(i, { note: ev.target.value })} />
                <label className="flex items-center gap-1 text-xs">
                  <input type="radio" name="default-exit" checked={cfg.default_exit === e.name} onChange={() => setCfg((c) => ({ ...c, default_exit: e.name }))} />
                  默认
                </label>
                <Input
                  className="h-8 w-36 shrink-0"
                  placeholder="自检目标 IP"
                  value={e.probe_host ?? ""}
                  onChange={(ev) => patchExit(i, { probe_host: ev.target.value })}
                />
                <Input
                  className="h-8 w-20 shrink-0"
                  placeholder="端口"
                  value={e.probe_port ?? ""}
                  onChange={(ev) => patchExit(i, { probe_port: Number(ev.target.value) || undefined })}
                />
                <Button size="sm" variant="outline" className="h-8" disabled={checking === e.name} onClick={() => check(e.name)}>
                  <ZapIcon className="mr-1 size-3" />{checking === e.name ? "检测中…" : "自检"}
                </Button>
                <Button size="sm" variant="ghost" className="h-8 px-2" onClick={() => setCfg((c) => ({ ...c, exits: c.exits.filter((_, j) => j !== i) }))}>
                  <Trash2Icon className="size-3.5" />
                </Button>
                {result[e.name] ? <span className="w-full text-xs text-muted-foreground">{result[e.name]}</span> : null}
              </div>
            ))}
            <Button size="sm" variant="outline" onClick={() => setCfg((c) => ({ ...c, exits: [...c.exits, { name: "", type: "direct", addr: "", note: "" }] }))}>
              <PlusIcon className="mr-1 size-3.5" />添加出口
            </Button>
          </div>
        </div>

        <div>
          <Label className="mb-1 block text-sm">网段路由（按序匹配，未命中走默认出口）</Label>
          <div className="space-y-2">
            {cfg.routes.map((r, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <Input className="h-8 w-48" placeholder="192.168.0.0/16" value={r.cidr} onChange={(ev) => patchRoute(i, { cidr: ev.target.value })} />
                <span className="text-xs text-muted-foreground">→</span>
                <select
                  className="h-8 w-40 rounded-md border bg-transparent px-2 text-sm"
                  value={r.exit_name}
                  onChange={(ev) => patchRoute(i, { exit_name: ev.target.value })}
                >
                  {cfg.exits.map((e) => <option key={e.name} value={e.name}>{e.name || "(未命名)"}</option>)}
                </select>
                <Button size="sm" variant="ghost" className="h-8 px-2" onClick={() => setCfg((c) => ({ ...c, routes: c.routes.filter((_, j) => j !== i) }))}>
                  <Trash2Icon className="size-3.5" />
                </Button>
              </div>
            ))}
            <Button size="sm" variant="outline" onClick={() => setCfg((c) => ({ ...c, routes: [...c.routes, { cidr: "", exit_name: c.default_exit ?? "" }] }))}>
              <PlusIcon className="mr-1 size-3.5" />添加网段
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap items-end gap-2">
          <p className="text-xs text-muted-foreground">
            各出口的「自检目标 IP/端口」随配置保存：互联网出口留空探公网 DNS；内网出口填网关地址（如 192.168.1.1:80）验证内网线。
          </p>
          <Button onClick={save}>保存出口配置</Button>
        </div>
      </CardContent>
    </Card>
  );
}
