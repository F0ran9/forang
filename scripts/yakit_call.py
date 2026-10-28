#!/usr/bin/env python3
# yakit_call.py — Yakit MCP 客户端（最终版：抓 result + 通知流）
import sys, json, threading, time, queue
import requests

BASE = "http://127.0.0.1:11432"

def main():
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    q = queue.Queue()
    endpoint = {"url": None}

    def listen():
        with requests.get(f"{BASE}/sse", stream=True, timeout=(10, 300)) as r:
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                k, _, v = line.partition(":")
                q.put((k.strip(), v.strip()))

    threading.Thread(target=listen, daemon=True).start()

    deadline = time.time() + 10
    msg_url = None
    while time.time() < deadline:
        try:
            kind, val = q.get(timeout=1)
        except queue.Empty:
            continue
        if kind == "data" and "/message" in val:
            msg_url = val
            break
    if not msg_url:
        print(json.dumps({"error": "no endpoint"}))
        return

    def post(msg):
        requests.post(msg_url, json=msg, timeout=15)

    post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "forang-cli", "version": "1.0"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # 在飞通知收集（http_fuzzer 的结果走 notifications）
    notes = []
    post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}})

    deadline = time.time() + 90
    result = None
    while time.time() < deadline:
        try:
            kind, val = q.get(timeout=1)
        except queue.Empty:
            continue
        if kind != "data":
            continue
        try:
            msg = json.loads(val)
        except Exception:
            continue
        if msg.get("id") == 2:
            result = msg
            break
        method = msg.get("method", "")
        if method.endswith("/info") or method.endswith("/progress"):
            notes.append(msg.get("params", {}))

    if result is None:
        print(json.dumps({"error": "timeout", "notes": notes[-2:]}))
        return

    content = (result.get("result") or {}).get("content", [])
    texts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
    # 合并通知里的最终数据（通知内容往往是完整结果）
    note_text = ""
    for n in notes:
        c = n.get("content", "")
        if isinstance(c, str) and len(c) > len(note_text):
            note_text = c
    print(json.dumps({"ok": True,
                      "result": texts[0] if texts else "",
                      "notification": note_text[:12000]}, ensure_ascii=False))

main()
