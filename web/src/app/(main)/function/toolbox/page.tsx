// 工具箱 · Repeater（原始报文忠实重放 + 历史收藏）+ 综合解码（CyberChef）+
// 端口扫描 / 目录扫描（Go 原生任务制）。工具矩阵移植自 AI-PENTEST 工具模块。
"use client";

import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type RepHistoryItem, type ScanJob } from "@/lib/api";
import {
  CameraIcon, HammerIcon, PlayIcon, SquareIcon, WandIcon, StarIcon, TrashIcon,
  RadarIcon, FolderSearchIcon, ChefHatIcon, TerminalIcon, ShieldIcon,
} from "lucide-react";
import WebshellConsole from "./_components/webshell-console";
import C2Console from "./_components/c2-console";

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

const defaultRaw =
  "GET / HTTP/1.1\nHost: example.com\nUser-Agent: FORANG-Repeater\nAccept: */*\nConnection: close";

type Tab = "repeater" | "cyberchef" | "portscan" | "dirscan" | "webshell" | "c2";

export default function ToolboxPage() {
  const [tab, setTab] = React.useState<Tab>("repeater");
  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: "repeater", label: "Repeater 重放", icon: <HammerIcon className="size-4" /> },
    { key: "cyberchef", label: "综合解码", icon: <ChefHatIcon className="size-4" /> },
    { key: "portscan", label: "端口扫描", icon: <RadarIcon className="size-4" /> },
    { key: "dirscan", label: "目录扫描", icon: <FolderSearchIcon className="size-4" /> },
    { key: "webshell", label: "Webshell", icon: <ShieldIcon className="size-4" /> },
    { key: "c2", label: "C2 指挥", icon: <TerminalIcon className="size-4" /> },
  ];
  return (
    <div className="space-y-4 p-4">
      <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
        <HammerIcon className="size-5" /> 工具箱
      </h1>
      <div className="flex flex-wrap gap-1 border-b pb-2">
        {tabs.map((t) => (
          <button
            key={t.key}
            className={`flex items-center gap-1.5 rounded-t px-3 py-1.5 text-sm ${
              tab === t.key ? "bg-muted font-semibold" : "text-muted-foreground hover:bg-muted/50"
            }`}
            onClick={() => setTab(t.key)}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>
      {tab === "repeater" && <RepeaterTab />}
      {tab === "cyberchef" && <CyberChefTab />}
      {tab === "portscan" && <PortScanTab />}
      {tab === "dirscan" && <DirScanTab />}
      {tab === "webshell" && <WebshellConsole />}
      {tab === "c2" && <C2Console />}
    </div>
  );
}

// ==================== Repeater ====================

function RepeaterTab() {
  const [raw, setRaw] = React.useState(defaultRaw);
  const [forceHTTPS, setForceHTTPS] = React.useState(false);
  const [followRedirect, setFollowRedirect] = React.useState(true);
  const [maxBodyKB, setMaxBodyKB] = React.useState(1024);
  const [timeoutSec, setTimeoutSec] = React.useState(30);
  const [busy, setBusy] = React.useState(false);
  const [capBusy, setCapBusy] = React.useState(false);
  const [jobId, setJobId] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<RepeaterResult | null>(null);
  const [error, setError] = React.useState("");
  const [shot, setShot] = React.useState<{ png: string; size: number } | null>(null);
  const [copied, setCopied] = React.useState(false);
  const preRef = React.useRef<HTMLPreElement>(null);

  // 历史（移植自 AI-PENTEST Repeater）
  const [history, setHistory] = React.useState<RepHistoryItem[]>([]);
  const [histOpen, setHistOpen] = React.useState(true);
  const [histSearch, setHistSearch] = React.useState("");
  const [starOnly, setStarOnly] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [saveTitle, setSaveTitle] = React.useState("");
  const searchDeb = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const running = busy || capBusy;

  const loadHistory = React.useCallback(async (q?: string, starred?: boolean) => {
    try {
      const r = await api.repHistoryList(q, starred);
      setHistory(r.data || []);
    } catch {
      /* 历史加载失败不打断主流程 */
    }
  }, []);

  React.useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const onHistSearch = (v: string) => {
    setHistSearch(v);
    if (searchDeb.current) clearTimeout(searchDeb.current);
    searchDeb.current = setTimeout(() => loadHistory(v.trim() || undefined, starOnly), 300);
  };

  const waitForJob = (id: string): Promise<JobResp> =>
    new Promise((resolve, reject) => {
      const tick = async () => {
        try {
          const r: JobResp = await api.repeaterJob(id);
          if (r.state === "running") return void setTimeout(tick, 400);
          if (r.state === "error") throw new Error(r.error || "任务失败");
          resolve(r);
        } catch (e) {
          reject(e);
        }
      };
      tick();
    });

  const stop = async () => {
    if (!jobId) return;
    try {
      await api.repeaterStop(jobId);
    } catch {
      /* 已结束 */
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

  // 保存/更新历史
  const onSave = async () => {
    if (!raw.trim()) return void window.alert("请求内容为空");
    const guess = raw.split("\n")[0].slice(0, 80);
    const title = window.prompt("保存标题", selectedId ? history.find((h) => h.id === selectedId)?.title || guess : guess);
    if (title === null) return;
    try {
      if (selectedId) {
        await api.repHistoryUpdate(selectedId, {
          title, raw, follow_redirect: followRedirect, force_https: forceHTTPS, max_body_kb: maxBodyKB, timeout_sec: timeoutSec,
        });
      } else {
        const r = await api.repHistoryCreate({
          title, raw, follow_redirect: followRedirect, force_https: forceHTTPS, max_body_kb: maxBodyKB, timeout_sec: timeoutSec,
        });
        setSelectedId(r.data?.id ?? null);
      }
      loadHistory(histSearch.trim() || undefined, starOnly);
    } catch (e) {
      window.alert("保存失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  const onSelectHistory = (h: RepHistoryItem) => {
    setRaw(h.raw);
    setFollowRedirect(h.follow_redirect);
    setForceHTTPS(h.force_https);
    setMaxBodyKB(h.max_body_kb);
    setTimeoutSec(h.timeout_sec);
    setSelectedId(h.id);
  };

  const toggleStar = async (h: RepHistoryItem) => {
    await api.repHistoryStar(h.id, !h.starred);
    loadHistory(histSearch.trim() || undefined, starOnly);
  };

  const removeHistory = async (h: RepHistoryItem) => {
    if (!window.confirm(`删除「${h.title || h.preview}」？`)) return;
    if (selectedId === h.id) setSelectedId(null);
    await api.repHistoryDelete(h.id);
    loadHistory(histSearch.trim() || undefined, starOnly);
  };

  // copyURL 从当前报文提取目标 URL 并复制到剪贴板。
  const copyURL = async () => {
    const CR = String.fromCharCode(13);
    const LF = String.fromCharCode(10);
    const lines = raw.split(LF).map((x) => x.split(CR)[0]);
    const parts = (lines[0] || "").split(" ");
    let path = parts[1] || "/";
    let host = "";
    for (const l of lines.slice(1)) {
      if (l.toLowerCase().startsWith("host:")) {
        host = l.slice(5).trim();
        break;
      }
    }
    let scheme = forceHTTPS ? "https" : "http";
    let port = scheme === "https" ? 443 : 80;
    const absRe = new RegExp("^https?:" + String.fromCharCode(47) + String.fromCharCode(47), "i");
    if (absRe.test(path)) {
      try {
        const u = new URL(path);
        path = u.pathname + u.search;
        scheme = u.protocol.replace(":", "");
        host = u.hostname;
        port = Number(u.port) || (scheme === "https" ? 443 : 80);
      } catch {
        /* 保持头信息推导 */
      }
    } else if (host.includes(":")) {
      const seg = host.split(":");
      host = seg[0];
      const pn = Number(seg[1]);
      if (pn) port = pn;
    }
    if (!host) {
      window.alert("报文里没有 Host 头，无法生成 URL");
      return;
    }
    const defaultPort = (scheme === "https" && port === 443) || (scheme === "http" && port === 80);
    const url = scheme + "://" + host + (defaultPort ? "" : ":" + port) + path;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      window.alert(url);
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
  const respText = f
    ? `${f.status_line}\n${f.headers}\n\n${f.body}${f.err ? `\n\n[错误] ${f.err}` : ""}`
    : "（发送后显示响应）";
  const redirects = (result?.hops || []).slice(0, -1); // 跳变链（最后一跳是最终响应）

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setHistOpen(!histOpen)}>
            历史 ({history.length}) {histOpen ? "▸" : "▾"}
          </Button>
          <Button variant="outline" size="sm" onClick={onSave} disabled={running}>
            <StarIcon className="mr-1 size-4" /> {selectedId ? "更新" : "保存"}
          </Button>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={copyURL} disabled={running}>
            {copied ? "已复制 ✓" : "复制 URL"}
          </Button>
          <Button variant="outline" size="sm" onClick={buildFromURL} disabled={running}>
            <WandIcon className="mr-1 size-4" /> 构造请求
          </Button>
          <Button size="sm" onClick={() => startJob("send")} disabled={running}>
            <PlayIcon className="mr-1 size-4" /> {busy ? "发送中…" : "发送请求"}
          </Button>
          {running ? (
            <Button size="sm" className="bg-amber-400 text-black hover:bg-amber-300" onClick={stop}>
              <SquareIcon className="mr-1 size-4" /> 停止
            </Button>
          ) : (
            <Button variant="secondary" size="sm" onClick={capture}>
              <CameraIcon className="mr-1 size-4" /> 截图留证
            </Button>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 p-2 text-sm text-red-500">{error}</div>
      )}

      <div className="flex gap-3">
        <div className={histOpen ? "w-56 shrink-0 space-y-2" : "hidden"}>
          <Card>
            <CardContent className="space-y-2 p-2">
              <Input
                className="h-7 text-xs"
                placeholder="搜索标题/报文…"
                value={histSearch}
                onChange={(e) => onHistSearch(e.target.value)}
              />
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={starOnly}
                  onChange={(e) => {
                    setStarOnly(e.target.checked);
                    loadHistory(histSearch.trim() || undefined, e.target.checked);
                  }}
                />
                只看收藏
              </label>
              <div className="max-h-[560px] space-y-1 overflow-auto">
                {history.length === 0 && (
                  <div className="py-4 text-center text-xs text-muted-foreground">暂无历史</div>
                )}
                {history.map((h) => (
                  <div
                    key={h.id}
                    className={`group cursor-pointer rounded border p-1.5 text-xs hover:bg-muted/60 ${
                      selectedId === h.id ? "border-primary bg-muted" : ""
                    }`}
                    onClick={() => onSelectHistory(h)}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="truncate font-medium">{h.title || h.preview}</span>
                      <span className="hidden shrink-0 gap-0.5 group-hover:flex">
                        <button
                          title={h.starred ? "取消收藏" : "收藏"}
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleStar(h);
                          }}
                        >
                          <StarIcon className={`size-3.5 ${h.starred ? "fill-amber-400 text-amber-400" : ""}`} />
                        </button>
                        <button
                          title="删除"
                          onClick={(e) => {
                            e.stopPropagation();
                            removeHistory(h);
                          }}
                        >
                          <TrashIcon className="size-3.5 text-red-400" />
                        </button>
                      </span>
                      {h.starred && (
                        <StarIcon className="shrink-0 fill-amber-400 text-amber-400 size-3.5 group-hover:hidden" />
                      )}
                    </div>
                    <div className="truncate text-muted-foreground">{h.preview}</div>
                    <div className="text-[10px] text-muted-foreground">{h.updated_at}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 flex-1 space-y-3">
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
                TCP 直写忠实重放；二进制响应自动转 hex 预览。
              </span>
            </CardContent>
          </Card>

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

          {redirects.length > 0 && (
            <Card>
              <CardHeader className="py-2">
                <CardTitle className="text-sm">重定向链（{redirects.length} 跳）</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap items-center gap-1 p-2 text-xs">
                {result && (
                  <span className="rounded bg-muted px-1.5 py-0.5 font-mono">
                    {result.scheme}://{result.host}:{result.port}
                  </span>
                )}
                {redirects.map((h, i) => (
                  <React.Fragment key={i}>
                    <span className="text-muted-foreground">→</span>
                    <span
                      className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-amber-500"
                      title={h.headers}
                    >
                      {(h.headers.match(/^location:\s*(.+)$/im) || [])[1]?.trim() || "?"} ({h.status_line.split(" ")[1]})
                    </span>
                  </React.Fragment>
                ))}
                <span className="text-muted-foreground">→</span>
                <span className="rounded bg-green-500/15 px-1.5 py-0.5 font-mono text-green-600">
                  {f?.status_line.split(" ")[1]} 最终响应
                </span>
              </CardContent>
            </Card>
          )}

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
      </div>
    </div>
  );
}

// ==================== CyberChef ====================

function CyberChefTab() {
  return (
    <Card>
      <CardContent className="p-0">
        <iframe
          title="综合解码 CyberChef"
          src="/cyberchef/CyberChef_v10.5.2.html"
          className="h-[calc(100vh-220px)] min-h-[480px] w-full rounded border bg-white"
        />
      </CardContent>
    </Card>
  );
}

// ==================== 端口扫描 ====================

function PortScanTab() {
  const [targets, setTargets] = React.useState("");
  const [ports, setPorts] = React.useState("top100");
  const [timeoutSec, setTimeoutSec] = React.useState(300);
  const [jobs, setJobs] = React.useState<ScanJob[]>([]);
  const [cur, setCur] = React.useState<ScanJob | null>(null);
  const [busy, setBusy] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const loadJobs = React.useCallback(async () => {
    try {
      const r = await api.portScanList();
      setJobs(r.data || []);
    } catch {
      /* ignore */
    }
  }, []);

  React.useEffect(() => {
    loadJobs();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [loadJobs]);

  const start = async () => {
    if (!targets.trim()) return void window.alert("targets 不能为空");
    setBusy(true);
    try {
      const r = await api.portScanStart({ targets, ports, timeout_sec: timeoutSec });
      await loadJobs();
      poll(r.data?.job_id ?? 0);
    } catch (e) {
      window.alert("启动失败: " + (e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };

  const poll = (id: number) => {
    if (pollRef.current) clearInterval(pollRef.current);
    if (!id) return;
    pollRef.current = setInterval(async () => {
      try {
        const r = await api.portScanDetail(id);
        setCur(r.data || null);
        if (r.data?.status === "done" || r.data?.status === "error") {
          if (pollRef.current) clearInterval(pollRef.current);
          loadJobs();
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    }, 1500);
  };

  const openJob = (id: number) => {
    if (pollRef.current) clearInterval(pollRef.current);
    api.portScanDetail(id).then((r) => setCur(r.data || null));
    const j = jobs.find((x) => x.id === id);
    if (j && j.status === "running") poll(id);
  };

  const fin = cur?.findings;
  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="grid gap-2 py-3 text-sm md:grid-cols-4">
          <div className="md:col-span-2">
            <div className="mb-1 text-xs text-muted-foreground">目标（逗号分隔 / a-b 区间 / CIDR）</div>
            <Input value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="192.168.1.10-20, 192.168.1.0/24" />
          </div>
          <div>
            <div className="mb-1 text-xs text-muted-foreground">端口（top100 / 80,443 / 8000-8100）</div>
            <Input value={ports} onChange={(e) => setPorts(e.target.value)} />
          </div>
          <div>
            <div className="mb-1 text-xs text-muted-foreground">总超时（秒）</div>
            <Input type="number" value={timeoutSec} onChange={(e) => setTimeoutSec(Number(e.target.value) || 300)} />
          </div>
          <div className="md:col-span-4">
            <Button size="sm" onClick={start} disabled={busy}>
              <PlayIcon className="mr-1 size-4" /> {busy ? "启动中…" : "开始扫描"}
            </Button>
            <span className="ml-2 text-xs text-muted-foreground">Go 原生并发 TCP 探测（无 nmap 依赖），任务落库可回看。</span>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-3 md:grid-cols-3">
        <Card className="md:col-span-1">
          <CardHeader className="py-2">
            <CardTitle className="text-sm">最近任务</CardTitle>
          </CardHeader>
          <CardContent className="max-h-[460px] space-y-1 overflow-auto p-2 text-xs">
            {jobs.length === 0 && <div className="py-4 text-center text-muted-foreground">暂无任务</div>}
            {jobs.map((j) => (
              <div
                key={j.id}
                className={`cursor-pointer rounded border p-1.5 hover:bg-muted/60 ${cur?.id === j.id ? "border-primary bg-muted" : ""}`}
                onClick={() => openJob(j.id)}
              >
                <div className="flex items-center justify-between">
                  <span className="truncate font-mono">{j.targets}</span>
                  <span
                    className={`shrink-0 rounded px-1 ${
                      j.status === "done" ? "bg-green-500/15 text-green-600" : j.status === "running" ? "bg-amber-500/15 text-amber-500" : "bg-red-500/15 text-red-500"
                    }`}
                  >
                    {j.status}
                  </span>
                </div>
                <div className="text-[10px] text-muted-foreground">#{j.id} · {j.created_at}</div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="md:col-span-2">
          <CardHeader className="py-2">
            <CardTitle className="text-sm">
              扫描结果
              {fin && fin.total ? ` · ${fin.scanned}/${fin.total} 主机 · ${fin.open_total || 0} 开放端口` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-[460px] overflow-auto p-2">
            {!fin && <div className="py-8 text-center text-sm text-muted-foreground">（启动后显示）</div>}
            {fin && (
              <div className="space-y-1 font-mono text-xs">
                {(fin.hosts || []).length === 0 && (fin.scanned || 0) >= (fin.total || 0) && (
                  <div className="text-muted-foreground">无开放端口</div>
                )}
                {(fin.hosts || []).map((h) => (
                  <div key={h.host} className="rounded border p-1.5">
                    <div className="font-semibold text-blue-400">{h.host}</div>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {h.ports.map((p) => (
                        <span key={p} className="rounded bg-green-500/15 px-1.5 py-0.5 text-green-400">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ==================== 目录扫描 ====================

function DirScanTab() {
  const [baseURL, setBaseURL] = React.useState("");
  const [wordlist, setWordlist] = React.useState("");
  const [extensions, setExtensions] = React.useState("");
  const [jobs, setJobs] = React.useState<ScanJob[]>([]);
  const [cur, setCur] = React.useState<ScanJob | null>(null);
  const [busy, setBusy] = React.useState(false);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const loadJobs = React.useCallback(async () => {
    try {
      const r = await api.dirScanList();
      setJobs(r.data || []);
    } catch {
      /* ignore */
    }
  }, []);

  React.useEffect(() => {
    loadJobs();
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [loadJobs]);

  const start = async () => {
    if (!baseURL.trim().startsWith("http")) return void window.alert("base_url 需以 http(s):// 开头");
    setBusy(true);
    try {
      await api.dirScanStart({ base_url: baseURL, wordlist, extensions });
      await loadJobs();
      const r = await api.dirScanList();
      const j = (r.data || [])[0];
      if (j) poll(j.id);
    } catch (e) {
      window.alert("启动失败: " + (e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };

  const poll = (id: number) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const r = await api.dirScanDetail(id);
        setCur(r.data || null);
        if (r.data?.status === "done" || r.data?.status === "error") {
          if (pollRef.current) clearInterval(pollRef.current);
          loadJobs();
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    }, 1500);
  };

  const openJob = (id: number) => {
    if (pollRef.current) clearInterval(pollRef.current);
    api.dirScanDetail(id).then((r) => setCur(r.data || null));
    const j = jobs.find((x) => x.id === id);
    if (j && j.status === "running") poll(id);
  };

  const fin = cur?.findings;
  const hits = fin?.hits || [];
  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="grid gap-2 py-3 text-sm md:grid-cols-4">
          <div className="md:col-span-2">
            <div className="mb-1 text-xs text-muted-foreground">目标 Base URL</div>
            <Input value={baseURL} onChange={(e) => setBaseURL(e.target.value)} placeholder="http://target.example.com" />
          </div>
          <div>
            <div className="mb-1 text-xs text-muted-foreground">附加扩展名（逗号分隔，如 php,jsp）</div>
            <Input value={extensions} onChange={(e) => setExtensions(e.target.value)} placeholder="php,jsp,html" />
          </div>
          <div>
            <div className="mb-1 text-xs text-muted-foreground">自定义字典（留空用内置 ~180 条）</div>
            <textarea
              className="h-[52px] w-full rounded border bg-transparent p-1.5 font-mono text-xs"
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              placeholder={"admin\nbackup\napi/v1\n..."}
            />
          </div>
          <div className="md:col-span-4">
            <Button size="sm" onClick={start} disabled={busy}>
              <PlayIcon className="mr-1 size-4" /> {busy ? "启动中…" : "开始扫描"}
            </Button>
            <span className="ml-2 text-xs text-muted-foreground">非 404 即命中；301/302 标注跳转位置（可能是目录）。</span>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-3 md:grid-cols-3">
        <Card className="md:col-span-1">
          <CardHeader className="py-2">
            <CardTitle className="text-sm">最近任务</CardTitle>
          </CardHeader>
          <CardContent className="max-h-[460px] space-y-1 overflow-auto p-2 text-xs">
            {jobs.length === 0 && <div className="py-4 text-center text-muted-foreground">暂无任务</div>}
            {jobs.map((j) => (
              <div
                key={j.id}
                className={`cursor-pointer rounded border p-1.5 hover:bg-muted/60 ${cur?.id === j.id ? "border-primary bg-muted" : ""}`}
                onClick={() => openJob(j.id)}
              >
                <div className="flex items-center justify-between">
                  <span className="truncate font-mono">{j.targets}</span>
                  <span
                    className={`shrink-0 rounded px-1 ${
                      j.status === "done" ? "bg-green-500/15 text-green-600" : j.status === "running" ? "bg-amber-500/15 text-amber-500" : "bg-red-500/15 text-red-500"
                    }`}
                  >
                    {j.status}
                  </span>
                </div>
                <div className="text-[10px] text-muted-foreground">#{j.id} · {j.created_at}</div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="md:col-span-2">
          <CardHeader className="py-2">
            <CardTitle className="text-sm">
              命中结果
              {fin ? ` · ${fin.scanned}/${fin.total} 已探测 · ${hits.length} 命中` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-[460px] overflow-auto p-2">
            {!fin && <div className="py-8 text-center text-sm text-muted-foreground">（启动后显示）</div>}
            {fin && (
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="py-1">路径</th>
                    <th className="w-16">状态</th>
                    <th className="w-20">大小</th>
                    <th>跳转</th>
                  </tr>
                </thead>
                <tbody>
                  {hits.map((h) => (
                    <tr key={h.path} className="border-b border-border/40">
                      <td className="py-1">/{h.path}</td>
                      <td>
                        <span
                          className={`rounded px-1 ${
                            h.status < 300 ? "bg-green-500/15 text-green-600" : h.status < 400 ? "bg-amber-500/15 text-amber-500" : "bg-orange-500/15 text-orange-500"
                          }`}
                        >
                          {h.status}
                        </span>
                      </td>
                      <td className="text-muted-foreground">{h.size > 0 ? Math.round(h.size / 1024) + "K" : "-"}</td>
                      <td className="truncate text-muted-foreground" title={h.location}>
                        {h.location ? "→ " + h.location : ""}
                      </td>
                    </tr>
                  ))}
                  {hits.length === 0 && (fin.scanned || 0) >= (fin.total || 0) && (
                    <tr>
                      <td colSpan={4} className="py-4 text-center text-muted-foreground">
                        无命中
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
