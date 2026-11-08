"use client";

// Webshell 独立模块（原工具箱子页拆出——连接管理/文件/命令/AI 生成）。
import { ShieldIcon } from "lucide-react";

import WebshellConsole from "../toolbox/_components/webshell-console";

export default function WebshellPage() {
  return (
    <div className="space-y-4 p-4">
      <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
        <ShieldIcon className="size-5" /> Webshell
      </h1>
      <WebshellConsole />
    </div>
  );
}
