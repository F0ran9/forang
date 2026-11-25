#!/usr/bin/env bash
# tunnel-run.sh — FORANG 版 cloudflared 前台运行器（供 systemd 托管）。
# 直连应用 :8787（由 Cloudflare 提供公网 TLS），不经过本地 nginx。
#
# 与 new-tunnel.sh 的区别：
#   - 本脚本前台运行、不主动杀进程，交给 systemd 的 Restart=always 做存活保障；
#   - 启动后自动把「公网入口链接」写入 data/entry-url.txt（每换一次域名都会更新）。
#
# 注意：quick tunnel 每次**进程重启**都会分配新域名；而仅仅是网络抖动/切换，
# cloudflared 自己重连，域名保持不变。
set -uo pipefail

LOG=/root/Desktop/artex/data/tunnel.log
OUT=/root/Desktop/artex/data/entry-url.txt
CFG=/root/Desktop/artex/config.json

pkill -f 'cloudflared tunnel --url http://127.0.0.1:8787' 2>/dev/null || true
sleep 1
: >"$LOG"

cloudflared tunnel --url http://127.0.0.1:8787 \
  --no-autoupdate --protocol http2 >>"$LOG" 2>&1 &
CF_PID=$!

# 后台守候：等域名出现后拼出完整入口链接并落盘
(
  url=""
  for _ in $(seq 1 60); do
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" 2>/dev/null | head -1 || true)
    [ -n "$url" ] && break
    sleep 1
  done
  if [ -n "$url" ]; then
    token=""
    DSN=$(python3 -c "import json;print(json.load(open('$CFG'))['database']['dsn'])" 2>/dev/null || true)
    [ -n "${DSN:-}" ] && token=$(psql "$DSN" -tAc "select value from settings where key='gate.token'" 2>/dev/null | tr -d '[:space:]' || true)
    # 只有 gate 启用时入口才需要 token 路径；gate 关闭时拼上去反而是个 404
    gateon="false"
    [ -n "${DSN:-}" ] && gateon=$(psql "$DSN" -tAc "select coalesce(value,'false') from settings where key='gate.enabled'" 2>/dev/null | tr -d '[:space:]')
    if [ "$gateon" = "true" ] && [ -n "$token" ]; then echo "$url/$token" >"$OUT"; else echo "$url" >"$OUT"; fi
    logger -t forang-tunnel "新入口: $(cat "$OUT")"
    # 自动把「带 token 的公网基址」写进推送回连地址（tunnel.auto_sync=true 时）。
    # 否则飞书卡片里的审批/详情链接仍指向旧域名或内网，点开无效。
    if [ -n "${DSN:-}" ]; then
      autosync=$(psql "$DSN" -tAc "select coalesce(value,'true') from settings where key='tunnel.auto_sync'" 2>/dev/null | tr -d '[:space:]')
      if [ "${autosync:-true}" != "false" ]; then
        SHARE="$url"
        [ "$gateon" = "true" ] && [ -n "$token" ] && SHARE="$url/$token"
        psql "$DSN" -c "insert into settings(key,value) values('notify_public_base_url','$SHARE') on conflict (key) do update set value=excluded.value" >/dev/null 2>&1 \
          && logger -t forang-tunnel "回连地址已同步: $SHARE"
      fi
    fi
  fi
) &

wait "$CF_PID"
