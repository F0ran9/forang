import re
raw = open("/tmp/ykf3.txt").read()
lines = re.findall(r"\[recv data\] (.*)", raw)
print("data lines:", len(lines))
for ln in lines:
    if '"id":2' in ln:
        print("result line len:", len(ln))
        # 提取 text 字段
        m = re.search(r'"text":"(.*)"\}\]\}', ln)
        if m:
            text = m.group(1)
            print("text escaped len:", len(text))
            # 双重转义：\\\" -> \" ; \\\\ -> \\
            real = text.replace('\\\\', '\x00').replace('\\"', '"').replace('\x00', '\\')
            print("real head:", real[:300])
        break
