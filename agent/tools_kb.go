package agent

// tools_kb.go — kb_search：知识库检索（移植自 AI-PENTEST agent/tools/knowledge_search.py）。
// 检索对象：任务终态自动蒸馏的四章知识总结（执行概况/漏洞与可复用手法/经验教训/下次建议），
// bigram 余弦 + 词面命中混合打分。让 agent 开新任务前先查过往同目标/同技术沉淀，
// 复用已验证手法、避开已知弯路。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// kbSearcher 检索回调（server 注入，避免 agent 直接依赖 server 包）。
var kbSearchHook func(query string, topK int) (results []KBHit, totalChunks int, err error)

type KBHit struct {
	TaskID int64   `json:"task_id"`
	Title  string  `json:"title"`
	Score  float64 `json:"score"`
	Text   string  `json:"text"`
}

// SetKBSearcher server 启动时注入检索内核。
func SetKBSearcher(fn func(string, int) ([]KBHit, int, error)) {
	kbSearchHook = fn
}

func (t *ToolSet) kbSearchTool() actool.CoreTool {
	return readTool("kb_search",
		"检索历史任务知识库（跨任务经验沉淀复用）。每个终态任务会自动蒸馏成知识总结：执行概况/漏洞与可复用手法（含目标、payload/POC）/经验教训/下次建议。使用场景：①开始测试新目标前先查同目标/同技术关键词，复用已验证手法；②遇到卡点时查类似场景的经验教训。检索词建议「目标特征 + 技术关键词」，如「nacos 未授权」「SQL注入 union」。",
		obj(map[string]any{
			"query": str("检索词，建议含目标特征 + 技术关键词"),
			"top_k": intp("返回条数 3-10，默认 5"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
				TopK  int    `json:"top_k"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query 必填"), nil
			}
			if kbSearchHook == nil {
				return actool.Errorf("知识库检索不可用（未接通）"), nil
			}
			hits, total, err := kbSearchHook(a.Query, a.TopK)
			if err != nil {
				return actool.Errorf("检索失败: " + err.Error()), nil
			}
			if len(hits) == 0 {
				return actool.Text(fmt.Sprintf("知识库无相关沉淀（检索词：%s；索引 chunk 数 %d）。", a.Query, total)), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "知识库命中 %d 条（相关度降序）：\n", len(hits))
			for i, h := range hits {
				text := h.Text
				if len(text) > 1500 {
					text = text[:1500] + "…(截断)"
				}
				fmt.Fprintf(&b, "\n---- [%d] 任务#%d %s（score %.3f）----\n%s\n", i+1, h.TaskID, h.Title, h.Score, text)
			}
			return actool.Text(b.String()), nil
		})
}
