# fix_insert.py — 修 insert-before-main 代码块的换行转义
import io
p = r'server\evasion.go'
data = open(p, 'rb').read()
LF = bytes([10])
BS = bytes([92])
bad = b'mut := mutated[:insAt] + dataBlock + "' + LF + b'" + mutated[insAt:]'
good = b'mut := mutated[:insAt] + dataBlock + "' + BS + b'n" + mutated[insAt:]'
n = data.count(bad)
assert n == 1, n
data = data.replace(bad, good)
open(p, 'wb').write(data)
print('nl escape fixed')
