package agent

// tools_websearch.go — web_extract 工具（Tavily /extract，移植自哨兵 websearch-tool.ts：
// 1-10 个 URL 抓正文，4000 字/页，失败列出）。web_search 仍由 norma SDK 提供，
// 本工具只在 tavily 后端可用时追加。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// NewTavilyExtractTool builds the web_extract tool for one Tavily key.
func NewTavilyExtractTool(key string) actool.CoreTool {
	return readTool("web_extract",
		"抓取 1-10 个 http(s) 页面的正文（Tavily extract）。用于读取 web_search 命中的页面内容、公开报告/文档正文做情报收集。",
		obj(map[string]any{
			"urls": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "要抓取的页面地址，1-10 个", "minItems": 1, "maxItems": 10},
			"extract_depth": str("可选：basic（默认）/ advanced"),
		}, "urls"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URLs []string `json:"urls"`
				ExtractDepth string `json:"extract_depth"`
			}
			if err := json.Unmarshal(in, &a); err != nil || len(a.URLs) == 0 {
				return actool.Errorf("urls 必填（1-10 个 http(s) 地址）"), nil
			}
			var urls []string
			for _, u := range a.URLs {
				if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
					urls = append(urls, u)
				}
			}
			if len(urls) == 0 {
				return actool.Errorf("没有合法的 http(s) URL"), nil
			}
			if len(urls) > 10 {
				urls = urls[:10]
			}
			depth := a.ExtractDepth
			if depth != "advanced" {
				depth = "basic"
			}
			body, _ := json.Marshal(map[string]any{"urls": urls, "extract_depth": depth})
			c, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(c, "POST", "https://api.tavily.com/extract", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return actool.Errorf("抓取失败: " + err.Error()), nil
			}
			defer resp.Body.Close()
			var raw struct {
				Results []struct{ URL, RawContent string } `json:"results"`
				Failed  []struct{ URL, Error string } `json:"failed_results"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&raw); err != nil {
				return actool.Errorf("响应解析失败（key 是否有效？）"), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "抓取 %d 个页面：成功 %d，失败 %d\n", len(urls), len(raw.Results), len(raw.Failed))
			for _, r := range raw.Results {
				content := strings.TrimSpace(r.RawContent)
				fmt.Fprintf(&sb, "\n=== %s ===\n%s\n", r.URL, vulnPreview(content, 4000))
			}
			for _, f := range raw.Failed {
				fmt.Fprintf(&sb, "\n失败：%s — %s\n", f.URL, f.Error)
			}
			return actool.Text(vulnPreview(sb.String(), 12000)), nil
		})
}
