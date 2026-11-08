"use client";

// C2 指挥独立模块（原工具箱子页拆出——beacon 管理/交互/后渗透/攻击链路图）。
import { TerminalIcon } from "lucide-react";

import C2Console from "../toolbox/_components/c2-console";

export default function C2Page() {
  return (
    <div className="space-y-4 p-4">
      <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
        <TerminalIcon className="size-5" /> C2 指挥
      </h1>
      <C2Console />
    </div>
  );
}
