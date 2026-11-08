"use client";

// C2 指挥（Classic）— 内嵌 github-C2 风格控制台（goc2 适配层驱动）。
// iframe 同源：内页 fetch 垫片自动从 localStorage 取 forang_token 鉴权。
import { TerminalIcon } from "lucide-react";

export default function C2Page() {
  return (
    <div className="flex h-[calc(100vh-56px)] flex-col">
      <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-2">
        <TerminalIcon className="size-4" />
        <span className="text-sm font-semibold">C2 指挥</span>
        <span className="text-xs text-zinc-500">Classic Console · goc2 通道</span>
      </div>
      <iframe
        src="/api/tools/c2/classic/page"
        className="min-h-0 w-full flex-1 border-0"
        title="FORANG C2 Classic"
      />
    </div>
  );
}
