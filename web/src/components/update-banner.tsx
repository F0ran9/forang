"use client";

// update-banner.tsx — 登录后自动检查新版本并提示：
//   登录进入主界面 → 延迟 8s 静默查 /api/update/check（不 force，命中服务端缓存）
//   → 有新版且资产可用 → 右下角非阻塞提示条（当前版本 → 最新版本，
//     「去更新」跳系统设置页，「下次再说」关闭；每版本只提示一次，记 localStorage）。
//   GitHub 不可达/已是最新/开发构建不可比 → 静默，绝不打扰。

import * as React from "react";
import Link from "next/link";

import { ArrowUpCircleIcon, XIcon } from "lucide-react";

import { api } from "@/lib/api";

const DISMISS_KEY = "forang.update.dismissed";

export function UpdateBanner() {
  const [update, setUpdate] = React.useState<{ current: string; latest: string } | null>(null);

  React.useEffect(() => {
    // 登录落稳后再查：避开首屏 API 竞争；失败静默（离线/内网部署是常态）。
    const timer = setTimeout(() => {
      api
        .checkUpdate()
        .then((r) => {
          if (!r || r.error || !r.latest || !r.has_update) return;
          // 本平台发布包缺失（如只发了源码）也不提示——点了也装不上。
          if (r.asset_available === false) return;
          // 每个版本只提示一次；用户点过「下次再说」的版本不再弹。
          try {
            if (localStorage.getItem(DISMISS_KEY) === r.latest) return;
          } catch {
            /* localStorage 不可用照常提示 */
          }
          setUpdate({ current: r.current || "dev", latest: r.latest });
        })
        .catch(() => undefined);
    }, 8000);
    return () => clearTimeout(timer);
  }, []);

  if (!update) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 w-80 rounded-lg border border-primary/30 bg-card p-3 shadow-lg">
      <div className="flex items-start gap-2">
        <ArrowUpCircleIcon className="mt-0.5 size-5 shrink-0 text-primary" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">发现新版本 {update.latest}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            当前 {update.current} → {update.latest}，建议更新获得最新功能与修复。
          </p>
          <div className="mt-2 flex gap-2">
            <Link
              href="/system/settings"
              className="inline-flex h-7 items-center rounded-md bg-primary px-2.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
            >
              去更新
            </Link>
            <button
              type="button"
              className="inline-flex h-7 items-center rounded-md border px-2.5 text-xs hover:bg-muted"
              onClick={() => {
                try {
                  localStorage.setItem(DISMISS_KEY, update.latest);
                } catch {
                  /* 忽略 */
                }
                setUpdate(null);
              }}
            >
              下次再说
            </button>
          </div>
        </div>
        <button
          type="button"
          aria-label="关闭"
          className="shrink-0 rounded p-0.5 text-muted-foreground hover:bg-muted"
          onClick={() => setUpdate(null)}
        >
          <XIcon className="size-3.5" />
        </button>
      </div>
    </div>
  );
}
