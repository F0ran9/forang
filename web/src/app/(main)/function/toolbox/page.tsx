// 工具箱 · Repeater：原始报文手工重放（发送/构造请求/选项）+ 带时间取证截图。
// 与 agent 的 repeater_send / repeater_capture 同一后端内核（repeater 包）。
"use client";

import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { CameraIcon, HammerIcon, PlayIcon, WandIcon } from "lucide-react";

interface Hop {
  request_sent: string;
  status_line: string;
  headers: string;
  body: string;
  elapsed_ms: number;
  err: string;
}

interface RepeaterResult {
  scheme: string;
  host: string;
  port: number;
  hops: Hop[];
  final: Hop;
  total_ms: number;
}

export default function ToolboxPage() {
  const [raw, setRaw] = React.useState(
    "GET / HTTP/1.1\nHost: \nUser-Agent: FORANG-Repeater\nAccept: */*\nConnection: close",
  );
  const [forceHTTPS, setForceHTTPS] = React.useState(false);
  const [followRedirect, setFollowRedirect] = React.useState(true);
  const [maxBodyKB, setMaxBodyKB] = React.useState(1024);
  const [timeoutSec, setTimeoutSec] = React.useState(30);
  const [busy, setBusy] = React.useState(false);
  const [capBusy, setCapBusy] = React.useState(false);
  const [result, setResult] = React.useState<RepeaterResult | null>(null);
  const [error, setError] = React.useState("");
  const [shot, setShot] = React.useState<{ png: string; size: number } | null>(null);
  const [note, setNote] = React.useState("");

  const send = async () => {
    setBusy(true);
    setError("");
    setShot(null);
    try {
      const r = await api.repeaterSend({
        raw, force_https: forceHTTPS, follow_redirect: followRedirect,
        max_body_kb: maxBodyKB, timeout: timeoutSec,
      });
      if (r.status !== "done") throw new Error(r.error || "发送失败");
      setResult(r.result as RepeaterResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const capture = async () => {
    setCapBusy(true);
    setError("");
    try {
      const n = window.prompt("留证说明（显示在取证面板，如：未授权访问 /admin 的证据）", "");
      setNote(n || "");
      if (n === null) return;
      const r = await api.repeaterCapture({ raw, note: n, force_https: forceHTTPS, max_body_kb: maxBodyKB });
      if (r.status !== "done" || !r.png) throw new Error(r.error || "截图失败");
      setShot({ png: r.png, size: r.size || 0 });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCapBusy(false);
    }
  };

  const buildFromURL = () => {
    const u = window.prompt("输入目标 URL（https://example.com/path）", "http://");
    if (!u) return;
    try {
      const p = new URL(u);
      setRaw(
        `GET ${p.pathname}${p.search || "/"} HTTP/1.1\nHost: ${p.host}\nUser-Agent: FORANG-Repeater\nAccept: */*\nConnection: close`,
      );
      if (p.protocol === "https:") setForceHTTPS(true);
    } catch {
      window.alert("URL 不合法");
    }
  };

  const f = result?.final;
  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          <HammerIcon className="size-5" /> 工具箱 · Repeater
        </h1>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={buildFromURL}>
            <WandIcon className="mr-1 size-4" /> 构造请求
          </Button>
          <Button size="sm" onClick={send} disabled={busy}>
            <PlayIcon className="mr-1 size-4" /> {busy ? "发送中…" : "发送请求"}
          </Button>
          <Button variant="secondary" size="sm" onClick={capture} disabled={capBusy}>
            <CameraIcon className="mr-1 size-4" /> {capBusy ? "截图中…" : "截图留证"}
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-4 py-3 text-sm">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={forceHTTPS} onChange={(e) => setForceHTTPS(e.target.checked)} />
            强制 HTTPS
          </label>
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={followRedirect} onChange={(e) => setFollowRedirect(e.target.checked)} />
            跟随重定向
          </label>
          <label className="flex items-center gap-1.5">
            响应体限制
            <Input
              className="h-7 w-24"
              type="number"
              value={maxBodyKB}
              onChange={(e) => setMaxBodyKB(Number(e.target.value) || 1024)}
            />
            KB
          </label>
          <label className="flex items-center gap-1.5">
            超时
            <Input
              className="h-7 w-16"
              type="number"
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(Number(e.target.value) || 30)}
            />
            秒
          </label>
          <span className="text-xs text-muted-foreground">
            TCP 直写忠实重放；截图带北京时间取证面板，可直接作为漏洞证据。
          </span>
        </CardContent>
      </Card>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 p-2 text-sm text-red-500">{error}</div>
      )}

      <div className="grid grid-cols-2 gap-2">
        <Card>
          <CardHeader className="py-2">
            <CardTitle className="text-sm">Request</CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <textarea
              className="h-[420px] w-full resize-y rounded bg-muted/40 p-3 font-mono text-xs leading-relaxed"
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              spellCheck={false}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="py-2">
            <CardTitle className="text-sm">
              Response{f ? ` · ${f.status_line}（${f.elapsed_ms} ms）` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <textarea
              className="h-[420px] w-full resize-y rounded bg-muted/40 p-3 font-mono text-xs leading-relaxed"
              readOnly
              value={f ? `${f.headers}\n\n${f.body}${f.err ? `\n\n[错误] ${f.err}` : ""}` : "（发送后显示响应）"}
              spellCheck={false}
            />
          </CardContent>
        </Card>
      </div>

      {shot && (
        <Card>
          <CardHeader className="py-2">
            <CardTitle className="text-sm">
              留证截图（已存 {shot.png}，{Math.round(shot.size / 1024)} KB —— 可在漏洞/报告中引用该路径）
            </CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={shot.png} alt="取证截图" className="max-h-[520px] w-auto rounded border" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
