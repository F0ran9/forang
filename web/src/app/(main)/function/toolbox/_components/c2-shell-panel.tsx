"use client";

// c2-shell-panel.tsx — C2 反弹 Shell 面板：SSE 推输出 + POST 发命令（交互式）
// c2-agent-builder.tsx — Agent 生成器面板：参数 → API → 下载
import React from "react";
import { api } from "@/lib/api";
import { TerminalIcon, XIcon, PackageIcon, DownloadIcon, CogIcon } from "lucide-react";

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
    const token = localStorage.getItem("forang_token") || "";
    const es = new EventSource(`/api/tools/c2/shell/ws?session_id=${beaconId}&token=${token}`);
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
export function C2AgentBuilder() {
  const [config, setConfig] = React.useState({
    os: "linux",
    arch: "amd64",
    interval: 5,
    jitter: 20,
    persist: "none", // none / cron / systemd
    disguise: "none", // none / polkitd / systemd-udevd
  });
  const [buildResult, setBuildResult] = React.useState<{ downloadUrl?: string; size?: number; sha256?: string } | null>(null);
  const [busy, setBusy] = React.useState(false);

  const build = async () => {
    setBusy(true);
    try {
      // 生成 beacon 配置 JSON（goc2 实际生成由 goc2-server 承担）
      const cfg = {
        ...config,
        server: window.location.origin,
        generated: new Date().toISOString(),
      };
      // 模拟：生成配置 JSON（真实场景调 goc2 生成 API）
      const blob = new Blob([JSON.stringify(cfg, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      setBuildResult({ downloadUrl: url, size: blob.size });
    } finally { setBusy(false); }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-3 text-sm">
      <div className="flex items-center gap-2">
        <PackageIcon className="size-5 text-blue-500" />
        <span className="text-base font-semibold">Agent 生成器</span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">操作系统</label>
          <select className="w-full rounded border bg-transparent p-2 text-sm" value={config.os} onChange={(e) => setConfig({ ...config, os: e.target.value })}>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
            <option value="darwin">macOS</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">架构</label>
          <select className="w-full rounded border bg-transparent p-2 text-sm" value={config.arch} onChange={(e) => setConfig({ ...config, arch: e.target.value })}>
            <option value="amd64">x86_64</option>
            <option value="arm64">aarch64</option>
            <option value="386">x86</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">回连间隔（秒）</label>
          <input type="number" className="w-full rounded border bg-transparent p-2 text-sm" value={config.interval}
                 onChange={(e) => setConfig({ ...config, interval: Number(e.target.value) || 5 })} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">抖动（%）</label>
          <input type="number" className="w-full rounded border bg-transparent p-2 text-sm" value={config.jitter}
                 onChange={(e) => setConfig({ ...config, jitter: Number(e.target.value) || 20 })} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">持久化</label>
          <select className="w-full rounded border bg-transparent p-2 text-sm" value={config.persist} onChange={(e) => setConfig({ ...config, persist: e.target.value })}>
            <option value="none">无</option>
            <option value="cron">Cron</option>
            <option value="systemd">Systemd 用户服务</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">进程伪装</label>
          <select className="w-full rounded border bg-transparent p-2 text-sm" value={config.disguise} onChange={(e) => setConfig({ ...config, disguise: e.target.value })}>
            <option value="none">无</option>
            <option value="polkitd">polkitd</option>
            <option value="systemd-udevd">systemd-udevd</option>
            <option value="accounts-daemon">accounts-daemon</option>
          </select>
        </div>
      </div>

      <button
        className="flex items-center gap-2 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-500 disabled:opacity-40"
        onClick={build}
        disabled={busy}
      >
        <CogIcon className="size-4" /> {busy ? "生成中…" : "生成 Agent 配置"}
      </button>

      {buildResult && (
        <div className="rounded border border-green-500/40 bg-green-500/10 p-3">
          <div className="flex items-center justify-between">
            <span className="text-sm text-green-600">✓ 配置生成完成（{buildResult.size} 字节）</span>
            <a href={buildResult.downloadUrl} download="agent-config.json"
               className="flex items-center gap-1 rounded border border-green-600 px-3 py-1 text-xs text-green-600 hover:bg-green-500/20">
              <DownloadIcon className="size-3" /> 下载
            </a>
          </div>
          <div className="mt-1 text-[10px] text-muted-foreground">
            配置文件含服务器地址/回连参数/持久化选项——用 goc2 工具链编译为二进制后部署
          </div>
        </div>
      )}
    </div>
  );
}
