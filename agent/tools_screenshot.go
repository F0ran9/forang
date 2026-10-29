package agent

// tools_screenshot.go — web_screenshot 工具：用宿主 Chromium headless 截取目标页面，
// 落盘到工作目录供 report_finding 以 kind=screenshot 引用。
// 也支持传入本地 HTML 文件路径（file:// 协议）截取离线报告页面。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) screenshotTool() actool.CoreTool {
	return writeTool("web_screenshot",
		"截取目标网页截图（Chromium headless，支持 http/https/file 协议）。产出 PNG 落到工作目录 evidence/screenshots/，返回文件路径——在 report_finding 的 evidence 列表里用 kind=screenshot 引用该路径即可把截图附进漏洞报告。",
		obj(map[string]any{
			"url":       str("目标 URL（http://… / https://… / file://…）"),
			"width":     intp("可选，视口宽，默认 1280"),
			"height":    intp("可选，视口高，默认 720"),
			"wait_ms":   intp("可选，页面加载后等待毫秒（让 JS 渲染完），默认 3000"),
			"full_page": str("可选，true=截整页（可能很长），默认只截视口"),
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				URL      string   `json:"url"`
				Width    int      `json:"width"`
				Height   int      `json:"height"`
				WaitMs   int      `json:"wait_ms"`
				FullPage string   `json:"full_page"`
				Cookies  []string `json:"cookie"`
				Headers  []string `json:"header"`
				JS       string   `json:"js"`
			}
			if err := json.Unmarshal(in, &a); err != nil || strings.TrimSpace(a.URL) == "" {
				return actool.Errorf("url 必填"), nil
			}
			if a.Width <= 0 {
				a.Width = 1280
			}
			if a.Height <= 0 {
				a.Height = 720
			}
			if a.WaitMs <= 0 {
				a.WaitMs = 3000
			}

			outDir := filepath.Join(dir, "evidence", "screenshots")
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return actool.Errorf("建目录失败: " + err.Error()), nil
			}
			name := fmt.Sprintf("shot-%s.png", time.Now().Format("0102-150405"))
			outPath := filepath.Join(outDir, name)

			// 带登录态/注入 JS 时走 Playwright 渲染（chromium CLI 不支持自定义请求头）
			if len(a.Cookies) > 0 || len(a.Headers) > 0 || strings.TrimSpace(a.JS) != "" {
				helper := filepath.Join(dir, "tools", "webshot.py")
				if err := os.WriteFile(helper, []byte(webshotScript), 0o644); err != nil {
					return actool.Errorf("释放助手脚本失败: " + err.Error()), nil
				}
				var pargs []string
				pargs = append(pargs, "--url", a.URL, "--out", outPath,
					"--width", strconv.Itoa(a.Width), "--height", strconv.Itoa(a.Height),
					"--wait", strconv.Itoa(a.WaitMs))
				if a.FullPage == "true" {
					pargs = append(pargs, "--full")
				}
				for _, c := range a.Cookies {
					pargs = append(pargs, "--cookie", c)
				}
				for _, h := range a.Headers {
					pargs = append(pargs, "--header", h)
				}
				if strings.TrimSpace(a.JS) != "" {
					pargs = append(pargs, "--js", a.JS)
				}
				cmd := exec.CommandContext(ctx, "python3", append([]string{helper}, pargs...)...)
				var pout strings.Builder
				cmd.Stdout, cmd.Stderr = &pout, &pout
				if err := cmd.Run(); err != nil {
					return actool.Errorf("Playwright 截图失败: " + err.Error() + "; " + strings.TrimSpace(pout.String())), nil
				}
				st, serr := os.Stat(outPath)
				if serr != nil || st.Size() < 1000 {
					return actool.Errorf("截图产物异常（不存在或 <1KB）"), nil
				}
				return actool.Text("截图已保存（带登录态）: " + outPath + "。用 bind_finding_evidence 绑到漏洞，报告附录与 Word 自动嵌图。"), nil
			}
			args := []string{
				"--headless", "--disable-gpu", "--no-sandbox",
				"--hide-scrollbars",
				fmt.Sprintf("--window-size=%d,%d", a.Width, a.Height),
				fmt.Sprintf("--virtual-time-budget=%d", a.WaitMs),
				fmt.Sprintf("--screenshot=%s", outPath),
			}
			if a.FullPage == "true" {
				// Chromium headless full-page: 用超大高度模拟
				args = append(args, fmt.Sprintf("--window-size=%d,%d", a.Width, 10000))
			}
			args = append(args, a.URL)

			cmd := exec.CommandContext(ctx, "chromium", args...)
			var out strings.Builder
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				return actool.Errorf(fmt.Sprintf("截图失败: %v\n%s", err, vulnPreview(out.String(), 300))), nil
			}
			st, serr := os.Stat(outPath)
			if serr != nil || st.Size() < 1000 {
				return actool.Errorf("截图产物异常（不存在或 <1KB）"), nil
			}
			return actool.Text(fmt.Sprintf("✅ 截图已保存: %s（%d KB）\n在 report_finding evidence 里用 {\"kind\":\"screenshot\",\"path\":\"%s\"} 引用。", outPath, st.Size()/1024, outPath)), nil
		})
}
