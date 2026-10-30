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

// ---- 字典中心工具（知识库二期）：沉淀 + 复用 ----

// dictHooks server 注入的字典读写回调（解耦 agent 与 server 包）。
var dictHooks struct {
	add    func(kind, value, note string) error
	query  func(kind, q string, limit int) ([]DictEntry, error)
}

// DictEntry 字典条目（agent 侧视图）。
type DictEntry struct {
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Note     string `json:"note"`
	Context  string `json:"context"`
	HitCount int    `json:"hit_count"`
	LastStatus int `json:"last_status"`
}

// SetDictHooks server 启动时注入。
func SetDictHooks(add func(kind, value, note string) error, query func(kind, q string, limit int) ([]DictEntry, error)) {
	dictHooks.add = add
	dictHooks.query = query
}

// dictAddTool 测试中沉淀字典：发现有效路径/可用凭据/敏感参数时记录，跨任务复用。
func (t *ToolSet) dictAddTool() actool.CoreTool {
	return writeTool("dict_add",
		"把测试中验证有效的条目沉淀进字典中心（跨任务复用）。kind：path(Web 路径/目录/API 统一)/user(用户名)/pass(密码)/param(敏感参数名)/subdomain(子域)。使用场景：①发现未授权可访问的路径（如 /actuator/env）→ path；②拿到有效凭据（弱口令/默认口令/泄露凭据）→ user+pass；③发现敏感参数（debug/file/url 等可利用参数）→ param。",
		obj(map[string]any{
			"kind":  str("类别：path / user / pass / param / subdomain"),
			"value": str("条目值（path 类不带前导斜杠更佳，自动规整）"),
			"note":  str("可选：一句话说明（如：nacos 默认口令，2024 常见）"),
		}, "kind", "value"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
				Note  string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if dictHooks.add == nil {
				return actool.Errorf("字典中心不可用（未接通）"), nil
			}
			if err := dictHooks.add(a.Kind, a.Value, a.Note); err != nil {
				return actool.Errorf("沉淀失败: " + err.Error()), nil
			}
			return actool.Text("✅ 已沉淀到字典中心（" + a.Kind + "）：" + a.Value), nil
		})
}

// dictQueryTool 查询字典：拿候选路径去测 / 拿用户名密码候选做登录尝试。
func (t *ToolSet) dictQueryTool() actool.CoreTool {
	return readTool("dict_query",
		"查询字典中心（跨任务沉淀 + 内置种子）。kind：path(路径/目录/API)/user/pass/param/subdomain；q 可选模糊过滤。使用场景：①指纹识别后查相关路径（q=nacos）逐个验证；②登录点测试前查 user/pass 字典组合候选（配合 repeater_send 或自行构造请求）；③Fuzz 参数名时取 param 候选。返回按历史命中次数降序。",
		obj(map[string]any{
			"kind":  str("类别：path / user / pass / param / subdomain"),
			"q":     str("可选：模糊过滤（值/说明/上下文）"),
			"limit": intp("返回条数，默认 30，最大 100"),
		}, "kind"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind  string `json:"kind"`
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if dictHooks.query == nil {
				return actool.Errorf("字典中心不可用（未接通）"), nil
			}
			if a.Limit <= 0 || a.Limit > 100 {
				a.Limit = 30
			}
			entries, err := dictHooks.query(a.Kind, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf("查询失败: " + err.Error()), nil
			}
			if len(entries) == 0 {
				return actool.Text("字典中心该类别暂无匹配（kind=" + a.Kind + " q=" + a.Q + "）。"), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "字典 %s 命中 %d 条（按历史命中降序）：\n", a.Kind, len(entries))
			for i, e := range entries {
				v := e.Value
				if a.Kind == "path" {
					v = "/" + strings.TrimLeft(v, "/")
				}
				fmt.Fprintf(&b, "%d. %s", i+1, v)
				if e.HitCount > 1 {
					fmt.Fprintf(&b, "（命中 %d 次", e.HitCount)
					if e.LastStatus > 0 {
						fmt.Fprintf(&b, "，最近 %d", e.LastStatus)
					}
					b.WriteString("）")
				}
				if e.Note != "" {
					b.WriteString("  — " + e.Note)
				}
				b.WriteByte('\n')
			}
			return actool.Text(b.String()), nil
		})
}
