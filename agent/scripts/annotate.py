# -*- coding: utf-8 -*-
# APP 截图标注助手：在截图上画红圈标注点击位置 + 可选标签文字（自动找中文字体）。
# 由 agent 的 droid_annotate 工具调用。
import argparse
import glob

from PIL import Image, ImageDraw, ImageFont

p = argparse.ArgumentParser()
p.add_argument("--img", required=True)
p.add_argument("--out", required=True)
p.add_argument("--x", type=int, required=True)
p.add_argument("--y", type=int, required=True)
p.add_argument("--label", default="")
p.add_argument("--note", default="")
a = p.parse_args()

img = Image.open(a.img).convert("RGB")
d = ImageDraw.Draw(img)
R = 26
# 红圈 + 十字准星
d.ellipse([a.x - R, a.y - R, a.x + R, a.y + R], outline=(255, 40, 40), width=5)
d.line([a.x - R - 14, a.y, a.x - R + 6, a.y], fill=(255, 40, 40), width=4)
d.line([a.x, a.y - R - 14, a.x, a.y - R + 6], fill=(255, 40, 40), width=4)

# 标签（自动找支持中文的字体；找不到就用默认字体只画 ASCII）
font = None
for pat in (
    "/usr/share/fonts/truetype/wqy/*",
    "/usr/share/fonts/opentype/noto/*CJK*",
    "/usr/share/fonts/truetype/noto/*CJK*",
    "/usr/share/fonts/**/*.ttf",
):
    hits = glob.glob(pat, recursive=True)
    if hits:
        try:
            font = ImageFont.truetype(hits[0], 26)
            break
        except Exception:
            pass
if a.label and font:
    tw = d.textlength(a.label, font=font)
    lx, ly = max(10, min(a.x + R + 18, img.width - int(tw) - 20)), max(10, a.y - 20)
    d.rectangle([lx - 8, ly - 6, lx + tw + 8, ly + 40], fill=(255, 40, 40))
    d.text((lx, ly), a.label, fill=(255, 255, 255), font=font)

if a.note:
    nfont = font or ImageFont.load_default()
    d.text((12, img.height - 44), a.note, fill=(255, 230, 120), font=nfont)

img.save(a.out)
print("annotated:", a.out)
