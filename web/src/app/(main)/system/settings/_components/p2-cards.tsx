"use client";

// P2 批次设置卡（哨兵移植收尾）：隐身入口 / 指挥条令 / 任务容器化 / 插件中心。
import * as React from "react";

import { BoxIcon, EyeOffIcon, PuzzleIcon, ScrollTextIcon, UploadIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";

function authHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? window.localStorage.getItem("forang_token") : "";
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

function GateCard() {
  const [cfg, setCfg] = React.useState<{ enabled: boolean; token: string }>({ enabled: false, token: "" });
  const load = React.useCallback(() => {
    fetch("/api/gate", { headers: authHeaders() }).then((r) => r.json()).then(setCfg).catch(() => undefined);
  }, []);
  React.useEffect(() => { load(); }, [load]);
  const set = (body: object) =>
    fetch("/api/gate", { method: "PUT", headers: authHeaders(), body: JSON.stringify(body) })
      .then((r) => r.json()).then((d) => { setCfg(d); toast.success("已保存"); })
      .catch(() => toast.error("保存失败"));
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><EyeOffIcon className="size-4" />隐身入口</CardTitle>
        <CardDescription>
          启用后，除 /api/health 外，未访问过入口 URL 的一切请求（含登录页）一律裸 404——测绘引擎抓不到任何指纹。入口 URL 启用时生成，轮换即全量失效。内网部署可不开。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center gap-2">
          <Switch checked={cfg.enabled} onCheckedChange={(v) => set({ enabled: v })} />
          <span className="text-sm">{cfg.enabled ? "已启用" : "已关闭"}</span>
          <Button size="sm" variant="outline" className="ml-auto"
            onClick={() => { if (window.confirm("轮换 token 将使所有已入口的浏览器失效，继续？")) set({ rotate: true }); }}>轮换 token</Button>
        </div>
        {cfg.token ? (
          <div className="rounded-md border p-2 text-xs">
            <div className="mb-1 text-muted-foreground">入口 URL（收藏/分发）：</div>
            <code className="break-all font-mono">{origin}/{cfg.token}</code>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

interface Doctrine { id: string; name: string; text: string; builtin: boolean }

function DoctrinesCard() {
  const [items, setItems] = React.useState<Doctrine[]>([]);
  const [editing, setEditing] = React.useState<string | null>(null);
  const [draft, setDraft] = React.useState({ name: "", text: "" });
  const load = React.useCallback(() => {
    fetch("/api/doctrines", { headers: authHeaders() }).then((r) => r.json()).then((d) => setItems(d.items ?? [])).catch(() => undefined);
  }, []);
  React.useEffect(() => { load(); }, [load]);
  const save = () => {
    if (!draft.name.trim() || !draft.text.trim()) { toast.warning("名称与正文都必填"); return; }
    const url = editing ? `/api/doctrines/${editing}` : "/api/doctrines";
    fetch(url, { method: editing ? "PUT" : "POST", headers: authHeaders(), body: JSON.stringify(draft) })
      .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d.error || "保存失败"); return d; })
      .then(() => { toast.success(editing ? "条令已更新（对之后启动的运行生效）" : "条令已创建，对话页模式选择器可选用"); setEditing(null); setDraft({ name: "", text: "" }); load(); })
      .catch((e) => toast.error(e.message));
  };
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><ScrollTextIcon className="size-4" />指挥条令</CardTitle>
        <CardDescription>
          UI 可编辑的作战方针模板：在对话页模式选择器里以「⚡条令名」出现（与预设同管道注入，条令只叠方针不换身份）。内置「攻防Web渗透打点」来自全链哨兵。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {items.map((d) => (
          <div key={d.id} className="rounded-md border p-2 text-sm">
            <div className="flex items-center gap-2">
              <span className="font-medium">⚡{d.name}</span>
              {d.builtin ? <Badge variant="outline">内置</Badge> : null}
              <div className="ml-auto flex gap-1">
                <Button size="sm" variant="ghost" onClick={() => { setEditing(d.id); setDraft({ name: d.name, text: d.text }); }}>编辑</Button>
                {!d.builtin ? (
                  <Button size="sm" variant="ghost" className="text-destructive"
                    onClick={() => { if (window.confirm(`删除条令「${d.name}」？`)) fetch(`/api/doctrines/${d.id}`, { method: "DELETE", headers: authHeaders() }).then(load); }}>删除</Button>
                ) : null}
              </div>
            </div>
            {editing !== d.id ? <pre className="mt-1 max-h-24 overflow-y-auto whitespace-pre-wrap text-xs text-muted-foreground">{d.text}</pre> : null}
          </div>
        ))}
        <div className="space-y-2 rounded-md border border-dashed p-2">
          <div className="text-xs text-muted-foreground">{editing ? "编辑条令" : "新建条令"}</div>
          <Input placeholder="条令名（如 红队优先RCE）" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          <Textarea rows={4} placeholder="条令正文（作战方针、优先级、红线…）" value={draft.text} onChange={(e) => setDraft({ ...draft, text: e.target.value })} />
          <div className="flex gap-2">
            <Button size="sm" onClick={save}>{editing ? "保存修改" : "创建"}</Button>
            {editing ? <Button size="sm" variant="ghost" onClick={() => { setEditing(null); setDraft({ name: "", text: "" }); }}>取消</Button> : null}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ContainerCard() {
  const [cfg, setCfg] = React.useState<{ enabled: boolean; image: string; network: string }>({ enabled: false, image: "kalilinux/kali-rolling:latest", network: "host" });
  React.useEffect(() => { fetch("/api/task-container", { headers: authHeaders() }).then((r) => r.json()).then(setCfg).catch(() => undefined); }, []);
  const save = (patch: object) =>
    fetch("/api/task-container", { method: "PUT", headers: authHeaders(), body: JSON.stringify(patch) })
      .then((r) => r.json()).then((d) => { setCfg(d); toast.success("已保存"); });
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><BoxIcon className="size-4" />任务容器化</CardTitle>
        <CardDescription>
          开启后任务内的 Bash 在每任务专属 Kali 容器里执行（docker exec，懒创建，平台数据同路径挂载），扫描/爆破/装工具的污染不再落在宿主 VM。对话不容器化（需要宿主 adb 等设备工具）。容器内工具自行 apt install。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center gap-2">
          <Switch checked={cfg.enabled} onCheckedChange={(v) => save({ enabled: v })} />
          <span className="text-sm">{cfg.enabled ? "已启用" : "已关闭"}</span>
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          <div>
            <Label className="text-xs">镜像（可带镜像源前缀）</Label>
            <Input value={cfg.image} onChange={(e) => setCfg({ ...cfg, image: e.target.value })} onBlur={() => save({ image: cfg.image })} />
          </div>
          <div>
            <Label className="text-xs">网络</Label>
            <div className="flex gap-2">
              {["host", "bridge"].map((n) => (
                <Button key={n} size="sm" variant={cfg.network === n ? "default" : "outline"} onClick={() => save({ network: n })}>{n}</Button>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface PluginEntry { id: string; name: string; description: string; capabilities: string[]; enabled: boolean }

function PluginsCard() {
  const [items, setItems] = React.useState<PluginEntry[]>([]);
  const [busy, setBusy] = React.useState(false);
  const load = React.useCallback(() => {
    fetch("/api/plugins", { headers: authHeaders() }).then((r) => r.json()).then((d) => setItems(d.items ?? [])).catch(() => undefined);
  }, []);
  React.useEffect(() => { load(); }, [load]);
  const upload = (file: File) => {
    setBusy(true);
    const fd = new FormData();
    fd.append("package", file);
    const token = typeof window !== "undefined" ? window.localStorage.getItem("forang_token") : "";
    fetch("/api/plugins", { method: "POST", headers: token ? { Authorization: `Bearer ${token}` } : {}, body: fd })
      .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d.error || "上传失败"); toast.success(`插件 ${d.name} 已安装（未启用）`); load(); })
      .catch((e) => toast.error(e.message))
      .finally(() => setBusy(false));
  };
  const toggle = (id: string, enabled: boolean) =>
    fetch(`/api/plugins/${id}`, { method: "PUT", headers: authHeaders(), body: JSON.stringify({ enabled }) })
      .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d.error || "操作失败"); return d; })
      .then(() => { toast.success(enabled ? "已启用（MCP 已注册，对之后的会话生效）" : "已停用"); load(); })
      .catch((e) => toast.error(e.message));
  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><PuzzleIcon className="size-4" />插件中心</CardTitle>
        <CardDescription>
          插件 = zip（根或一层子目录内 plugin.json：name/description/capabilities/mcp + 随包文件）。启用后声明的 MCP 服务以 plugin-&lt;id&gt;-&lt;name&gt; 注册，工具走既有 MCP 通路挂给 agent；stdio 相对命令按插件目录解析。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {items.map((p) => (
          <div key={p.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm">
            <span className="font-medium">{p.name}</span>
            <span className="max-w-64 truncate text-xs text-muted-foreground">{p.description}</span>
            {p.capabilities && p.capabilities.length > 0 ? <Badge variant="outline">{p.capabilities.join("/")}</Badge> : null}
            <div className="ml-auto flex items-center gap-2">
              <Switch checked={p.enabled} onCheckedChange={(v) => toggle(p.id, v)} />
              <Button size="sm" variant="ghost" className="text-destructive"
                onClick={() => { if (window.confirm(`删除插件「${p.name}」及其 MCP 注册？`)) fetch(`/api/plugins/${p.id}`, { method: "DELETE", headers: authHeaders() }).then(load); }}>删除</Button>
            </div>
          </div>
        ))}
        <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed p-3 text-sm text-muted-foreground hover:bg-muted/50">
          <UploadIcon className="size-4" />
          {busy ? "上传解析中…" : "上传插件 zip"}
          <input type="file" accept=".zip" className="hidden" disabled={busy}
            onChange={(e) => { const f = e.target.files && e.target.files[0]; if (f) upload(f); e.target.value = ""; }} />
        </label>
      </CardContent>
    </Card>
  );
}

export function P2IntegrationCards() {
  return (
    <>
      <GateCard />
      <DoctrinesCard />
      <ContainerCard />
      <PluginsCard />
    </>
  );
}
