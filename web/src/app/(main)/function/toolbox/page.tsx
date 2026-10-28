// 工具箱 · Repeater：原始报文手工重放（发送/停止/构造请求/选项）+ 带时间取证截图。
// 与 agent 的 repeater_send / repeater_capture 同一后端内核（repeater 包）。
// 请求/响应带语法高亮（方法紫、路径蓝、头名绿、状态码按段变色）。
"use client";

import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { CameraIcon, HammerIcon, PlayIcon, SquareIcon, WandIcon } from "lucide-react";

interface Hop {
  request_sent: string;
  status_line: string;
  headers: string;
  body: string;
  elapsed_ms: number;
  err?: string;
}

interface RepeaterResult {
  scheme: string;
  host: string;
  port: number;
  hops: Hop[];
  final: Hop;
  total_ms: number;
}

interface JobResp {
  job_id: string;
  state: string;
  kind?: string;
  result?: RepeaterResult;
  png?: string;
  html?: string;
  size?: number;
  error?: string;
}

const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// hlRequest 请求高亮：首行 方法(紫) 路径(蓝) 版本(紫)，头名(绿)+值。
function hlRequest(text: string): string {
  return esc(text)
    .split("\n")
    .map((line, i) => {
      if (i === 0) {
        const m = line.match(/^([A-Za-z]+) (\S+) (HTTP\/[\d.]+)$/);
        if (m)
          return (
            `<span style="color:#c084fc">${m[1]}</span>` +
            ` <span style="color:#60a5fa">${m[2]}</span>` +
            ` <span style="color:#c084fc">${m[3]}</span>`
          );
      }
      const h = line.match(/^([A-Za-z0-9-]+):(.*)$/);
      if (h) return `<span style="color:#4ade80">${h[1]}:</span>${h[2]}`;
      return line;
    })
    .join("\n");
}

// hlResponse 响应高亮：状态行按码段变色（2xx绿/3xx黄/4xx橙/5xx红），头名绿。
function hlResponse(text: string): string {
  return esc(text)
    .split("\n")
    .map((line) => {
      if (line.startsWith("HTTP/")) {
        const m = line.match(/HTTP\/[\d.]+ (\d{3})/);
        if (m) {
          const c = Number(m[1]);
          const color = c < 300 ? "#4ade80" : c < 400 ? "#fbbf24" : c < 500 ? "#fb923c" : "#f87171";
          return `<span style="color:${color};font-weight:700">${line}</span>`;
        }
      }
      const h = line.match(/^([A-Za-z0-9-]+):(.*)$/);
      if (h) return `<span style="color:#4ade80">${h[1]}:</span>${h[2]}`;
      return line;
    })
    .join("\n");
}

export default function ToolboxPage() {
  const [raw, setRaw] = React.useState(
    "GET / HTTP/1.1\nHost: \nUser-Agent: FORANG-Repeater\nAccept: */*\nConnection: close",
  );
  const [forceHTTPS, setForceHTTPS] = React.useState(false);
  const [followRedirect, setFollowRedirect] = React.useState(true);
  const [maxBodyKB, setMaxBodyKB] = React.useState(1024);
  const [timeoutSec, setTimeoutSec] = React.useState(30);
  const [busy, setBusy] = React.useState(false); // send 运行中
  const [capBusy, setCapBusy] = React.useState(false); // capture 运行中
  const [jobId, setJobId] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<RepeaterResult | null>(null);
  const [error, setError] = React.useState("");
  const [shot, setShot] = React.useState<{ png: string; size: number } | null>(null);
  const preRef = React.useRef<HTMLPreElement>(null);

  const running = busy || capBusy;

  const waitForJob = (id: string): Promise<JobResp> =>
    new Promise((resolve, reject) => {
      const tick = async () => {
        try {
          const r: JobResp = await api.repeaterJob(id);
          if (r.state === "done") return resolve(r);
          if (r.state === "error") return reject(new Error(r.error || "执行失败"));
          if (r.state === "stopped") return reject(new Error("已停止"));
          setTimeout(tick, 400);
        } catch (e) {
          reject(e instanceof Error ? e : new Error(String(e)));
        }
      };
      tick();
    });

  const stop = async () => {
    if (jobId) {
      try {
        await api.repeaterStop(jobId);
      } catch {
        /* 轮询侧会以 stopped/结束收尾 */
      }
    }
  };

  const startJob = async (kind: "send" | "capture") => {
    setError("");
    setShot(null);
    if (kind === "send") setBusy(true);
    else setCapBusy(true);
    try {
      const payload =
        kind === "send"
          ? { raw, force_https: forceHTTPS, follow_redirect: followRedirect, max_body_kb: maxBodyKB, timeout: timeoutSec }
          : { raw, note: "", force_https: forceHTTPS, max_body_kb: maxBodyKB };
      const st = await api[kind === "send" ? "repeaterSend" : "repeaterCapture"](payload as never);
      const id = (st as { job_id: string }).job_id;
      setJobId(id);
      const r = await waitForJob(id);
      const res = r.result as RepeaterResult | undefined;
      if (kind === "send") {
        setResult(res || null);
      } else {
        if (!r.png) throw new Error("截图未生成");
        setShot({ png: r.png, size: r.size || 0 });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setJobId(null);
      if (kind === "send") setBusy(false);
      else setCapBusy(false);
    }
  };

  const capture = async () => {
    const n = window.prompt("留证说明（显示在取证面板，如：未授权访问 /admin 的证据）", "");
    if (n === null) return;
    await startJob("capture");
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
  const respText = f
    ? `${f.status_line}\n${f.headers}\n\n${f.body}${f.err ? `\n\n[错误] ${f.err}` : ""}`
    : "（发送后显示响应）";

  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
          <HammerIcon className="size-5" /> 工具箱 · Repeater
        </h1>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={buildFromURL} disabled={running}>
            <WandIcon className="mr-1 size-4" /> 构造请求
          </Button>
          <Button size="sm" onClick={() => startJob("send")} disabled={running}>
            <PlayIcon className="mr-1 size-4" /> {busy ? "发送中…" : "发送请求"}
          </Button>
          {running ? (
            <Button
              size="sm"
              className="bg-amber-400 text-black hover:bg-amber-300"
              onClick={stop}
            >
              <SquareIcon className="mr-1 size-4" /> 停止
            </Button>
          ) : (
            <Button variant="secondary" size="sm" onClick={capture}>
              <CameraIcon className="mr-1 size-4" /> 截图留证
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-4 py-3 text-sm">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={forceHTTPS} onChange={(e) => setForceHTTPS(e.target.checked)} disabled={running} />
            强制 HTTPS
          </label>
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={followRedirect} onChange={(e) => setFollowRedirect(e.target.checked)} disabled={running} />
            跟随重定向
          </label>
          <label className="flex items-center gap-1.5">
            响应体限制
            <Input
              className="h-7 w-24"
              type="number"
              value={maxBodyKB}
              onChange={(e) => setMaxBodyKB(Number(e.target.value) || 1024)}
              disabled={running}
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
              disabled={running}
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
            <div className="relative h-[420px]">
              <pre
                aria-hidden
                ref={preRef}
                className="pointer-events-none absolute inset-0 overflow-auto whitespace-pre-wrap break-all rounded bg-muted/40 p-3 font-mono text-xs leading-relaxed"
                dangerouslySetInnerHTML={{ __html: hlRequest(raw) }}
              />
              <textarea
                className="absolute inset-0 h-full w-full resize-none rounded bg-transparent p-3 font-mono text-xs leading-relaxed text-transparent caret-foreground outline-none"
                value={raw}
                onChange={(e) => setRaw(e.target.value)}
                onScroll={(e) => {
                  if (preRef.current) {
                    preRef.current.scrollTop = (e.target as HTMLTextAreaElement).scrollTop;
                    preRef.current.scrollLeft = (e.target as HTMLTextAreaElement).scrollLeft;
                  }
                }}
                spellCheck={false}
                disabled={running}
              />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="py-2">
            <CardTitle className="text-sm">
              Response{f ? ` · ${f.status_line}（${f.elapsed_ms} ms）` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-2">
            <pre
              className="h-[420px] overflow-auto whitespace-pre-wrap break-all rounded bg-muted/40 p-3 font-mono text-xs leading-relaxed"
              dangerouslySetInnerHTML={{ __html: hlResponse(respText) }}
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
