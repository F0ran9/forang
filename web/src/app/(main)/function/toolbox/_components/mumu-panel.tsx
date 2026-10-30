"use client";

// mumu-panel.tsx — MuMu 模拟器一键启动 + 联动渗透：
//   配置：物理机 MuMu 启动路径（用户输入，存服务端 settings）+ agent 地址/token
//   一键启动：agent 按路径拉起 MuMu → 等 Android ready → 平台侧 adb connect
//   联动渗透：就绪后一键创建 APP 动态测试任务（droid 工具直连模拟器）
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { SmartphoneIcon, PlayIcon, RefreshCw, SettingsIcon, ZapIcon } from "lucide-react";

export default function MumuPanel() {
  const [st, setSt] = React.useState<{ agent_online?: boolean; android_started?: boolean; process_started?: boolean; launch_path?: string; manager?: string; error?: string } | null>(null);
  const [cfg, setCfg] = React.useState<{ agent_url?: string; token_masked?: string; launch_path?: string }>({});
  const [path, setPath] = React.useState("");
  const [cfgOpen, setCfgOpen] = React.useState(false);
  const [cfgUrl, setCfgUrl] = React.useState("");
  const [cfgToken, setCfgToken] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [log, setLog] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const [s, c] = await Promise.all([api.mumuStatus(), api.mumuConfig()]);
      setSt(s.data || {});
      setCfg(c || {});
      setPath(c?.launch_path || "");
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const append = (s: string) => setLog((o) => `${o}${o ? "\n" : ""}[${new Date().toLocaleTimeString()}] ${s}`);

  const savePath = async () => {
    try {
      await api.mumuConfigSet({ launch_path: path, agent_url: cfgUrl || undefined, token: cfgToken || undefined });
      append(`已保存启动路径：${path || "（空，agent 用默认）"}`);
      load();
    } catch (e) {
      append("保存失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  const launch = async () => {
    if (!path.trim() && !cfg.launch_path) return void window.alert("请先输入 MuMu 启动路径（物理机安装目录或 MuMuManager.exe 完整路径）并保存");
    setBusy(true);
    setLog("");
    append("一键启动中：agent 拉起 MuMu 并等待 Android 就绪（约 30-60 秒）…");
    try {
      const r = await api.mumuLaunch();
      const d = r.data as { launch?: Record<string, unknown>; adb?: Record<string, unknown> };
      const L = d.launch || {};
      append(`MuMu：${String(L.message || "")}（android=${L.android_started}）`);
      const A = d.adb || {};
      if (A.error) append(`adb：${A.error}`);
      else append(`adb connect ${A.target} → ${A.connect}`);
      if (A.devices) append(`设备：\n${A.devices}`);
      load();
    } catch (e) {
      append("启动失败: " + (e instanceof Error ? e.message : String(e)));
    } finally { setBusy(false); }
  };

  const connectAdb = async () => {
    setBusy(true);
    try {
      const r = await api.mumuConnect();
      const A = r.data as Record<string, unknown>;
      if (A.error) append(`adb：${A.error}`);
      else append(`adb connect ${A.target} → ${A.connect}\n${A.devices}`);
    } finally { setBusy(false); }
  };

  // 联动渗透：创建 APP 动态测试任务（droid 工具直连模拟器）
  const startPentest = async () => {
    const host = (cfg.agent_url || "").replace(/^https?:\/\//, "").split(":")[0] || "192.168.17.1";
    const goal = [
      "对 MuMu 模拟器内的移动 APP 进行动态渗透测试（授权测试环境）。",
      `步骤：1) droid_connect 连接设备 ${host}:16384（已由平台一键启动并 adb connect）；`,
      "2) droid_devices 确认设备；droid_shell 检查已安装应用（pm list packages -3）取目标包名；",
      "3) 依据目标 APP 类型执行：导出组件检查（dumpsys package）、日志敏感信息（logcat）、",
      "流量抓取（可将 droid_proxy 指向平台代理 127.0.0.1:8788）；",
      "4) 发现的每个漏洞用 report_finding 提交，截图/日志用 bind_finding_evidence 绑定；",
      "5) 汇总输出测试结论。红线：模拟器内为自建测试环境，可执行常规动态分析，不做破坏性操作。",
    ].join("\n");
    try {
      const r = await fetch("/api/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({
          name: `MuMu APP 动态测试（${new Date().toLocaleDateString()}）`,
          goal,
          description: `MuMu 模拟器 ${host}:16384`,
          category: "App",
        }),
      });
      const j = await r.json() as { id?: number; error?: string };
      if (j.id) {
        append(`联动任务已创建：#${j.id}，跳转任务详情…`);
        window.open(`/function/tasks/detail?id=${j.id}`, "_self");
      } else append("建任务失败: " + (j.error || r.status));
    } catch (e) {
      append("建任务失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  const ready = st?.android_started;

  return (
    <div className="mx-auto max-w-3xl space-y-3">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between py-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <SmartphoneIcon className="size-5 text-blue-500" /> MuMu 模拟器
          </CardTitle>
          <div className="flex items-center gap-2 text-xs">
            <span className={`rounded px-2 py-1 ${st?.agent_online ? "bg-green-500/15 text-green-600" : "bg-red-500/15 text-red-500"}`}>
              {st?.agent_online ? "agent 在线" : "agent 不可达"}
            </span>
            <span className={`rounded px-2 py-1 ${ready ? "bg-green-500/15 text-green-600" : "bg-muted text-muted-foreground"}`}>
              {ready ? "Android 已就绪" : st?.process_started ? "启动中…" : "未启动"}
            </span>
            <Button variant="outline" size="sm" onClick={() => setCfgOpen(!cfgOpen)}><SettingsIcon className="mr-1 size-3.5" /> 高级</Button>
            <Button variant="outline" size="sm" onClick={load}><RefreshCw className="size-3.5" /></Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div>
            <div className="mb-1 text-xs text-muted-foreground">MuMu 启动路径（物理机安装目录或 MuMuManager.exe 完整路径，如 D:\Program Files\Netease\MuMu Player 12）</div>
            <div className="flex gap-2">
              <Input placeholder="D:\sectools\app\MuMu Player 12" value={path} onChange={(e) => setPath(e.target.value)} />
              <Button variant="outline" size="sm" onClick={savePath}>保存路径</Button>
            </div>
            {st?.manager && <div className="mt-1 font-mono text-[10px] text-muted-foreground">agent 解析：{st.manager}</div>}
          </div>

          {cfgOpen && (
            <div className="space-y-2 rounded border bg-muted/30 p-2">
              <div className="text-xs font-semibold">高级配置（通常无需修改）</div>
              <div className="flex gap-2">
                <Input className="font-mono text-xs" placeholder="agent URL（http://192.168.17.1:18911）" value={cfgUrl} onChange={(e) => setCfgUrl(e.target.value)} />
                <Input className="font-mono text-xs" placeholder="agent token（留空不改）" value={cfgToken} onChange={(e) => setCfgToken(e.target.value)} />
              </div>
              <div className="text-[10px] text-muted-foreground">当前：{cfg.agent_url} · token {cfg.token_masked || "默认"}（token 只存服务端）</div>
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <Button onClick={launch} disabled={busy}>
              <PlayIcon className="mr-1 size-4" /> {busy ? "启动中…" : "一键启动"}
            </Button>
            <Button variant="outline" onClick={connectAdb} disabled={busy}>
              <RefreshCw className="mr-1 size-4" /> adb connect
            </Button>
            <Button variant="secondary" onClick={startPentest} disabled={!ready || busy}>
              <ZapIcon className="mr-1 size-4" /> 联动渗透（创建 APP 测试任务）
            </Button>
          </div>
          <div className="text-xs text-muted-foreground">
            一键启动 = agent 按上述路径拉起 MuMu → 等待 Android 就绪 → 自动 adb connect（模拟器端口 16384）。
            就绪后点「联动渗透」自动创建 droid 工具任务，对模拟器内 APP 做动态测试。
          </div>
          {log && (
            <pre className="max-h-52 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-[11px]">{log}</pre>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
