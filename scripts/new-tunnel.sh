#!/usr/bin/env bash
# new-tunnel.sh — 重建 Cloudflare 临时隧道并输出新的公网入口链接。
#
# 背景：trycloudflare 的临时隧道每次重启都会换域名，VM 重启或隧道进程挂掉后
# 旧链接即失效。跑一次本脚本即可拿到新链接（同时把链接写到 data/entry-url.txt）。
#
# 用法（在 VM 上）：
#   bash /root/Desktop/artex/scripts/new-tunnel.sh
# 用法（从 Windows 远程触发）：
#   ssh root@192.168.17.150 "bash /root/Desktop/artex/scripts/new-tunnel.sh"
set -uo pipefail

CFG=/root/Desktop/artex/config.json
LOG=/root/Desktop/artex/data/tunnel.log
OUT=/root/Desktop/artex/data/entry-url.txt

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "[x] 未找到 cloudflared，请先安装："
  echo "    curl -L -o /usr/local/bin/cloudflared \\"
  echo "      https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
  echo "    chmod +x /usr/local/bin/cloudflared"
  exit 1
fi

echo "[1/4] 关闭旧隧道…"
pkill -f 'cloudflared tunnel --url http://127.0.0.1:8787' 2>/dev/null || true
sleep 1

echo "[2/4] 建立新隧道（出站连接，公网零入站端口）…"
# 走本机 nginx 443（HTTPS 终结 + 安全头），自签证书故跳过校验；
# --protocol http2 在 UDP/QUIC 被运营商限制时更稳。
nohup cloudflared tunnel --url http://127.0.0.1:8787 \
  --no-autoupdate --protocol http2 >"$LOG" 2>&1 &

url=""
for _ in $(seq 1 40); do
  url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG" 2>/dev/null | head -1 || true)
  [ -n "$url" ] && break
  sleep 1
done
if [ -z "$url" ]; then
  echo "[x] 隧道启动失败，最后 10 行日志："
  tail -10 "$LOG" 2>/dev/null
  exit 1
fi

echo "[3/4] 读取隐身入口 token…"
token=""
if [ -f "$CFG" ]; then
  DSN=$(python3 -c "import json;print(json.load(open('$CFG'))['database']['dsn'])" 2>/dev/null || true)
  if [ -n "${DSN:-}" ]; then
    token=$(psql "$DSN" -tAc "select value from settings where key='gate.token'" 2>/dev/null | tr -d '[:space:]' || true)
  fi
fi

echo "[4/4] 自检…"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 "$url/api/health" 2>/dev/null)
[ -z "$code" ] && code="000"
if [ "$code" != "200" ]; then
  echo "    提示：本机 DNS 可能还没解析到新域名（热点 DNS 负缓存）。"
  echo "    可临时验证：curl --resolve ${url#https://}:443:104.16.230.132 ${url}/api/health"
fi

if [ -n "$token" ]; then entry="$url/$token"; else entry="$url"; fi
echo "$entry" > "$OUT" 2>/dev/null || true

echo
echo "============================================"
echo "  公网入口 : $entry"
echo "  健康检查 : HTTP $code （200 为正常）"
echo "  入口文件 : $OUT"
echo "  隧道日志 : $LOG"
echo "============================================"
echo "提示：链接等同于密码，请勿公开分享；换链接后旧链接立即失效。"
