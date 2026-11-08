"use client";

import { useEffect, useState } from "react";

// C2 指挥（Classic）— 内嵌 github-C2 风格控制台（goc2 适配层驱动）。
// 顶栏挂 React 版载荷生成器（含回连地址覆盖/9 平台格式/免杀 loader）——
// Classic 自身的 builder 面板是参考项目壳（后端桩），真正可用的生成器是 React 版。
import { TerminalIcon, PackageIcon, XIcon } from "lucide-react";

import { C2AgentBuilder } from "../toolbox/_components/c2-shell-panel";

export default function C2Page() {
  const [genOpen, setGenOpen] = useState(false);

  // Esc 关闭生成器弹层
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setGenOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex h-[calc(100vh-56px)] flex-col">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-2">
        <TerminalIcon className="size-4" />
        <span className="text-sm font-semibold">C2 指挥</span>
        <span className="text-xs text-zinc-500">Classic Console · goc2 通道</span>
        <button
          className="ml-auto flex items-center gap-1.5 rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500"
          onClick={() => setGenOpen(true)}
        >
          <PackageIcon className="size-3.5" /> 载荷生成器
        </button>
      </div>
      <iframe
        src="/api/tools/c2/classic/page"
        className="min-h-0 w-full flex-1 border-0"
        title="FORANG C2 Classic"
      />
      {genOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setGenOpen(false)}>
          <div className="relative max-h-[92vh] w-[min(1100px,94vw)] overflow-auto rounded-lg border border-zinc-700 bg-zinc-900 p-4 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <button
              className="absolute right-3 top-3 rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
              onClick={() => setGenOpen(false)}
              aria-label="关闭"
            >
              <XIcon className="size-4" />
            </button>
            <C2AgentBuilder />
          </div>
        </div>
      )}
    </div>
  );
}
