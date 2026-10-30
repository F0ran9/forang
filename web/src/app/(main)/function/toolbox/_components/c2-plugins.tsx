"use client";

// c2-plugins.tsx — CS 插件面板（后渗透动作库）：内置/自定义插件一键在目标机
// 逐条执行并聚合回显；支持新建自定义插件（命令序列）。
import React from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PlayIcon, RefreshCw, TrashIcon, PlusIcon, PuzzleIcon } from "lucide-react";

interface Plugin { id: number; name: string; description: string; commands: string[]; builtin: boolean }

export default function C2PluginsPanel({ beaconId }: { beaconId: string }) {
  const [plugins, setPlugins] = React.useState<Plugin[]>([]);
  const [running, setRunning] = React.useState<number | null>(null);
  const [result, setResult] = React.useState<{ plugin: string; steps: { cmd: string; output: string; error?: string; ms: number }[] } | null>(null);
  const [addOpen, setAddOpen] = React.useState(false);
  const [form, setForm] = React.useState({ name: "", description: "", commands: "" });

  const load = React.useCallback(async () => {
    try {
      const r = await api.c2Plugins();
      setPlugins(r.data || []);
    } catch { /* ignore */ }
  }, []);
  React.useEffect(() => { load(); }, [load]);

  const run = async (p: Plugin) => {
    setRunning(p.id);
    setResult(null);
    try {
      const r = await api.c2PluginRun(beaconId, p.id);
      setResult(r.data);
    } catch (e) {
      setResult({ plugin: p.name, steps: [{ cmd: "（执行失败）", output: "", error: e instanceof Error ? e.message : String(e), ms: 0 }] });
    } finally { setRunning(null); }
  };

  const del = async (p: Plugin) => {
    if (!window.confirm(`删除插件「${p.name}」？`)) return;
    await api.c2PluginDelete(p.id);
    load();
  };

  const save = async () => {
    const cmds = form.commands.split("\n").map((x) => x.trim()).filter(Boolean);
    if (!form.name.trim() || cmds.length === 0) return void window.alert("名称与命令必填");
    try {
      await api.c2PluginCreate({ name: form.name.trim(), description: form.description, commands: cmds });
      setAddOpen(false);
      setForm({ name: "", description: "", commands: "" });
      load();
    } catch (e) {
      window.alert("失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  return (
    <div className="flex h-full flex-col text-[11px]">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-2 py-1">
        <PuzzleIcon className="size-3.5 text-red-400" />
        <span className="font-semibold text-zinc-300">后渗透插件</span>
        <span className="text-zinc-500">一键在目标机执行命令序列并聚合回显</span>
        <div className="ml-auto flex gap-1">
          <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={load}><RefreshCw className="size-3" /> 刷新</button>
          <button className="flex items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 hover:bg-zinc-700" onClick={() => setAddOpen(!addOpen)}><PlusIcon className="size-3" /> 新插件</button>
        </div>
      </div>
      {addOpen && (
        <div className="space-y-1 border-b border-zinc-800 bg-zinc-900 px-2 py-1.5">
          <div className="flex gap-1">
            <Input className="h-6 w-32 border-zinc-700 bg-zinc-800 text-[11px] text-zinc-200" placeholder="插件名" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <Input className="h-6 flex-1 border-zinc-700 bg-zinc-800 text-[11px] text-zinc-200" placeholder="描述（可选）" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <textarea className="h-20 w-full rounded border border-zinc-700 bg-zinc-800 p-1.5 font-mono text-[11px] text-zinc-200" placeholder={"每行一条命令（≤10 条），如：\nid\nnetstat -antp | head -20"} value={form.commands} onChange={(e) => setForm({ ...form, commands: e.target.value })} />
          <Button size="sm" onClick={save}>保存插件</Button>
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-auto p-2">
        <div className="grid grid-cols-2 gap-1.5 lg:grid-cols-3">
          {plugins.map((p) => (
            <div key={p.id} className={`group rounded border p-1.5 ${running === p.id ? "border-blue-500 bg-blue-950/30" : "border-zinc-700 bg-zinc-800/60"} hover:border-blue-600`}>
              <div className="flex items-center justify-between">
                <span className="font-semibold text-zinc-100">{p.name}</span>
                <span className="flex gap-1">
                  <button title="执行" disabled={running !== null} onClick={() => run(p)} className="text-blue-400 hover:text-blue-300 disabled:opacity-40">
                    <PlayIcon className={`size-3.5 ${running === p.id ? "animate-pulse" : ""}`} />
                  </button>
                  {!p.builtin && (
                    <button title="删除" onClick={() => del(p)} className="text-red-400 opacity-0 group-hover:opacity-100"><TrashIcon className="size-3" /></button>
                  )}
                </span>
              </div>
              <div className="truncate text-[10px] text-zinc-500" title={p.description}>{p.description || `${p.commands.length} 条命令`}</div>
            </div>
          ))}
          {plugins.length === 0 && <div className="col-span-3 py-6 text-center text-zinc-500">（暂无插件）</div>}
        </div>
        {result && (
          <div className="mt-2 space-y-1">
            <div className="font-semibold text-blue-400">「{result.plugin}」执行结果</div>
            {result.steps.map((st, i) => (
              <div key={i} className="rounded border border-zinc-800 bg-black/50">
                <div className="border-b border-zinc-800 px-2 py-1 font-mono text-[10px] text-amber-300">
                  $ {st.cmd} <span className="text-zinc-600">（{st.ms}ms{st.error ? " · 失败" : ""}）</span>
                </div>
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap px-2 py-1 font-mono text-[10px] text-zinc-300">{st.error || st.output || "（无输出）"}</pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
