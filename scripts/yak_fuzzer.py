#!/usr/bin/env python3
# yak_fuzzer.py v3 — SSE 混合流：正确处理 event/data 行对，result 与 notification 都接
import json, threading, time, queue, sys
import requests

BASE = "http://127.0.0.1:11432"

def call_fuzzer(request_text: str) -> dict:
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
    url = None
    while time.time() < deadline:
        try:
            k, v = q.get(timeout=1)
        except queue.Empty:
            continue
        if k == "data" and "/message" in v:
            url = v
            break
    if not url:
        return {"error": "no endpoint"}

    def post(m):
        requests.post(url, json=m, timeout=15)

    post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "forang-cli", "version": "1.0"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "http_fuzzer", "arguments": {"request": request_text}}})

    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            k, v = q.get(timeout=1)
        except queue.Empty:
            continue
        if k != "data":
            continue
        try:
            m = json.loads(v)
        except Exception:
            continue
        text = ""
        if m.get("id") == 2 and "result" in m:
            try:
                text = m["result"]["content"][0]["text"]
            except Exception:
                text = ""
        elif (m.get("method") or "").endswith("info"):
            text = (m.get("params") or {}).get("content", "")
        if text and len(text) > 50:
            return {"text": text}
    return {"error": "timeout"}

if __name__ == "__main__":
    req = sys.argv[1] if len(sys.argv) > 1 else "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    req = req.replace("\\r\\n", "\r\n")
    out = call_fuzzer(req)
    text = out.get("text", "")
    if not text:
        print(json.dumps(out, ensure_ascii=False)[:500])
        sys.exit(1)
    try:
        inner = json.loads(text, strict=False)
        if isinstance(inner, str):
            inner = json.loads(inner, strict=False)
        print(json.dumps(inner, ensure_ascii=False)[:200000])
    except Exception as e:
        print(json.dumps({"parse_error": str(e), "raw_head": text[:600]}, ensure_ascii=False))
