package agent

// tools_apimodel.go — 业务建模 agent 工具（移植自哨兵 apimodel-tool.ts，MIT）。
// api_model_submit 可多次调用：大站接口多，单次装不下就按 paths/components
// 分片提交合并；api_model_done 声明完成；api_model_read 读回（含挂载记录）。
// 纪律照抄：工具描述开头声明「只在操作员要求业务建模时调用」。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/artex/db"
)

// SetApiModels wires the api-model store (nil = tools unavailable).
func (t *ToolSet) SetApiModels(ms *db.ApiModelStore) { t.apimodels = ms }

func (t *ToolSet) apiModelTools() []actool.CoreTool {
	return []actool.CoreTool{t.apiModelSubmitTool(), t.apiModelDoneTool(), t.apiModelReadTool()}
}

func (t *ToolSet) apiModelSubmitTool() actool.CoreTool {
	return writeTool("api_model_submit",
		"业务建模提交（只在操作员要求业务建模时调用）。把目标站点还原成 OpenAPI 3.x 文档：可整文档（openapi），或按路径分片（paths，如 {\"/api/users\":{\"get\":{...},\"post\":{...}}}，同路径整体替换）、按段分片（components，如 {\"schemas\":{\"User\":{...}}}，按段内名称合并）；entities 给业务实体与关系（给了就整份替换）。可多次调用逐步合并，返回合并后的统计与告警。",
		obj(map[string]any{
			"openapi":    map[string]any{"type": "object", "description": `OpenAPI 3.x 文档对象，如 {"openapi":"3.0.3","info":{...},"paths":{...}}`},
			"paths":      map[string]any{"type": "object", "description": `按路径分片：{"/api/users":{"get":{"summary":...,"parameters":...,"responses":{...}}}}`},
			"components": map[string]any{"type": "object", "description": "按段分片：{\"schemas\":{\"User\":{...}}}"},
			"entities":   map[string]any{"type": "array", "description": "业务实体与关系（整份替换）", "items": obj(map[string]any{
				"name": str("实体名，如 用户/订单"), "description": str("业务含义"),
				"fields": map[string]any{"type": "array", "items": obj(map[string]any{"name": str("字段名"), "type": str("类型，如 string/array<Order>"), "description": str("业务含义")})},
				"relations": map[string]any{"type": "array", "items": obj(map[string]any{"target": str("关联实体名"), "kind": str("关系，如 1:N/属于/包含")})},
			})},
			"target": str("建模目标：站点根地址或主机"),
			"title":  str("本次建模名称，如「商城前台 API」"),
			"note":   str("本次提交补了什么"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.apimodels == nil {
				return actool.Errorf("业务建模存储不可用"), nil
			}
			var a struct {
				Openapi, Paths, Components, Entities json.RawMessage
				Target, Title, Note string
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(a.Openapi)+len(a.Paths)+len(a.Components)+len(a.Entities) == 0 {
				return actool.Errorf("至少提交 openapi / paths / components / entities 之一"), nil
			}
			m, err := t.apimodels.EnsureDraft(t.taskID, a.Title, a.Target)
			if err != nil {
				return actool.Errorf("打开建模记录失败: " + err.Error()), nil
			}
			pc, oc, ec, warns, err := t.apimodels.SubmitMerge(m.ID, a.Openapi, a.Paths, a.Components, a.Entities, a.Title, a.Target)
			if err != nil {
				return actool.Errorf("合并失败: " + err.Error()), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "✅ 已合并到建模记录 #%d《%s》（draft）：路径 %d / 操作 %d / 实体 %d", m.ID, m.Title, pc, oc, ec)
			if len(warns) > 0 {
				sb.WriteString("\n告警：\n- " + strings.Join(warns, "\n- "))
			}
			if a.Note != "" {
				sb.WriteString("\n本次提交：" + a.Note)
			}
			return actool.Text(sb.String()), nil
		})
}

func (t *ToolSet) apiModelDoneTool() actool.CoreTool {
	return writeTool("api_model_done",
		"业务建模收口（只在操作员要求业务建模时调用）：声明当前建模文档已完整，记录转为 done。之后如需补充，新一次 api_model_submit 会开新的 draft。",
		obj(map[string]any{"summary": str("完成说明：覆盖了哪些模块/还差什么")}, "summary"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.apimodels == nil {
				return actool.Errorf("业务建模存储不可用"), nil
			}
			var a struct{ Summary string }
			_ = json.Unmarshal(in, &a)
			ms, err := t.apimodels.List(t.taskID)
			if err != nil || len(ms) == 0 {
				return actool.Errorf("没有进行中的建模记录"), nil
			}
			for _, m := range ms {
				if m.Status == "draft" {
					if err := t.apimodels.Finish(m.ID); err == nil {
						return actool.Text(fmt.Sprintf("✅ 建模记录 #%d《%s》已完成。%s", m.ID, m.Title, a.Summary)), nil
					}
				}
			}
			return actool.Errorf("没有 draft 状态的建模记录"), nil
		})
}

func (t *ToolSet) apiModelReadTool() actool.CoreTool {
	return readTool("api_model_read",
		"读取业务建模记录（操作员要求基于建模数据继续渗透时调用）。不传 id 列出本任务全部记录摘要；传 id 返回完整 OpenAPI 文档与实体（长文截断）。",
		obj(map[string]any{"id": intp("可选，记录 id；省略=列清单")}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.apimodels == nil {
				return actool.Errorf("业务建模存储不可用"), nil
			}
			id := droidInt(in, "id", 0)
			if id == 0 {
				ms, err := t.apimodels.List(t.taskID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if len(ms) == 0 {
					return actool.Text("（暂无建模记录）"), nil
				}
				var sb strings.Builder
				for _, m := range ms {
					fmt.Fprintf(&sb, "#%d [%s] %s · 目标 %s\n", m.ID, m.Status, m.Title, m.Target)
				}
				return actool.Text(sb.String()), nil
			}
			m, err := t.apimodels.Get(int64(id))
			if err != nil {
				return actool.Errorf("记录不存在"), nil
			}
			return actool.Text(fmt.Sprintf("#%d [%s] %s · %s\nOpenAPI:\n%s\n\n实体:\n%s",
				m.ID, m.Status, m.Title, m.Target, vulnPreview(string(m.Doc), 6000), vulnPreview(string(m.Entities), 2000))), nil
		})
}
