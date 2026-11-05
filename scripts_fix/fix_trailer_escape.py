# fix_trailer_escape.py — 修 trailer JSON 注入的双引号转义
import io
p = r'server\evasion.go'
src = io.open(p, encoding='utf-8').read()
BT = chr(96)   # backtick
BS = chr(92)   # backslash
DQ = chr(34)   # double quote

lines = src.split(chr(10))
found = False
for i, ln in enumerate(lines):
    if '__TRAILER_JSON__' in ln and 'ReplaceAll' in ln and 'esc' not in ln:
        # esc = tj: \ → \\, " → \"
        lines[i] = (
            '\tesc := strings.ReplaceAll(strings.ReplaceAll(tj, ' + BT + BS + BT + ', ' + BT + BS + BS + BT + '), '
            + BT + DQ + BT + ', ' + BT + BS + DQ + BT + '))'
        )
        lines.insert(i + 1, '\tsrc = strings.ReplaceAll(src, "__TRAILER_JSON__", esc)')
        found = True
        print('line', i + 1, 'rewritten')
        break
assert found, 'injection line not found'
io.open(p, 'w', encoding='utf-8', newline='').write(chr(10).join(lines))
print('ok')
