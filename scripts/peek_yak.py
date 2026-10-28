import json

raw = open("/tmp/ykf.txt").read()
marker = '"id":2,"result":{"content":[{"type":"text","text":"'
start = raw.find(marker)
start += len(marker)
# 双重转义：\\\\\" 在外层 JSON 解码后成为 \"，需要解两层
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
# 第一层：外层 JSON 字符串解码
real = json.loads('"' + text + '"', strict=False)
# real 现在形如 {"durationMs":402,...}（还是字符串），但内层引号是 \" 形式
# 第二层：再解一次
d = json.loads('"' + real + '"', strict=False)
try:
    obj = json.loads(d, strict=False)
except Exception:
    obj = d
print("keys:", list(obj.keys()) if isinstance(obj, dict) else type(obj).__name__)
print("statusCode:", obj.get("statusCode") if isinstance(obj, dict) else None)
for k in ("responseBody", "body", "response"):
    v = obj.get(k) if isinstance(obj, dict) else None
    if v:
        print(f"{k} len: {len(str(v))}")
        print(str(v)[:400])
        break
