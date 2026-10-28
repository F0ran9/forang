import json

raw = open("/tmp/ykf.txt").read()
marker = 'id":2,"result":{"content":[{"type":"text","text":"'
start = raw.find(marker)
if start < 0:
    print("no match")
    raise SystemExit
start += len(marker)
i = start
while i < len(raw):
    c = raw[i]
    if c == "\\":
        i += 2
        continue
    if c == '"':
        break
    i += 1
text = raw[start:i]
real = json.loads('"' + text + '"', strict=False)
d = json.loads(real, strict=False)
print("keys:", list(d.keys()))
print("statusCode:", d.get("statusCode"))
body = d.get("responseBody") or d.get("body") or ""
print("body len:", len(str(body)))
print(str(body)[:400])
