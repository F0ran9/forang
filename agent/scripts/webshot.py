# -*- coding: utf-8 -*-
# FORANG web 截图助手（带登录态）：Cookie 注入 / 自定义 Header / 截图前 JS / 整页。
# 由 agent 的 web_screenshot 工具调用（需要 cookie/js 时走本脚本，否则走 chromium CLI）。
import argparse

from playwright.sync_api import sync_playwright

p = argparse.ArgumentParser()
p.add_argument("--url", required=True)
p.add_argument("--out", required=True)
p.add_argument("--cookie", action="append", default=[])   # name=value
p.add_argument("--header", action="append", default=[])   # "Name: value"
p.add_argument("--js", default="")                        # 截图前执行的 JS
p.add_argument("--wait", type=int, default=3000)          # 加载后等待 ms
p.add_argument("--width", type=int, default=1440)
p.add_argument("--height", type=int, default=900)
p.add_argument("--full", action="store_true")             # 整页截图
a = p.parse_args()

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
    ctx = browser.new_context(
        viewport={"width": a.width, "height": a.height},
        ignore_https_errors=True,
    )
    if a.header:
        headers = {}
        for h in a.header:
            if ":" in h:
                name, _, val = h.partition(":")
                headers[name.strip()] = val.strip()
        if headers:
            ctx.set_extra_http_headers(headers)
    page = ctx.new_page()
    for c in a.cookie:
        if "=" in c:
            name, _, val = c.partition("=")
            ctx.add_cookies([{"name": name.strip(), "value": val.strip(),
                              "url": a.url}])
    page.goto(a.url, wait_until="domcontentloaded", timeout=max(a.wait + 15000, 20000))
    page.wait_for_timeout(a.wait)
    if a.js:
        try:
            page.evaluate(a.js)
            page.wait_for_timeout(800)
        except Exception as e:
            print("js eval warn:", e)
    page.screenshot(path=a.out, full_page=a.full)
    # 顺带把最终 URL 打出来（重定向后可核对）
    print("final-url:", page.url)
    browser.close()
