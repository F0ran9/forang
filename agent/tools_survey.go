package agent

// tools_survey.go — 资产测绘 agent 工具（FOFA/Quake/Hunter，移植自哨兵 asset-tool.ts，MIT）。
// 三个独立工具而非一个 query 参数：三家语法不同，统一入口会静默查空。
// 输出格式照抄：命中头行 + 编号记录（banner 截 400）+ 尾注（空结果提示/翻页/
// 配额/证据路径），全文 12000 字符截断。未配置/未验证的平台直接报错引导配置。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/artex/survey"
)

// SetSurveyService wires the asset-survey service (nil = tools report 未配置).
func (t *ToolSet) SetSurveyService(svc *survey.Service) { t.surveySvc = svc }

func (t *ToolSet) surveyTool(p survey.Platform) actool.CoreTool {
	return readTool(string(p)+"_search",
		fmt.Sprintf("%s 资产测绘：按 %s 自己的语法查询公网资产（域名/IP/端口/标题/服务/指纹），返回归一化记录并落证据。语法示例：%s。翻页用 page。", survey.Label(p), survey.Label(p), survey.Syntax(p)),
		obj(map[string]any{
			"query": str(fmt.Sprintf("%s 语法的查询语句，如 ip=\"1.1.1.1\" / domain=\"example.com\"", survey.Label(p))),
			"page":  intp("页码，从 1 开始，默认 1"),
			"size":  intp("每页条数，默认 20，最大 100"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.surveySvc == nil {
				return actool.Errorf("资产测绘服务不可用"), nil
			}
			var a struct {
				Query string
				Page, Size int
			}
			if err := json.Unmarshal(in, &a); err != nil || strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query 必填（空查询不支持，语法见工具说明）"), nil
			}
			res, err := t.surveySvc.Search(ctx, p, strings.TrimSpace(a.Query), a.Page, a.Size)
			if err != nil {
				return actool.Errorf("查询失败: " + err.Error() + "；若提示令牌或额度问题，请让操作员在「设置-资产测绘」检查"), nil
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s 查询 %s 第 %d 页（每页 %d）：命中 %d 条，本页 %d 条\n",
				survey.Label(p), res.Query, res.Page, res.Size, res.Total, res.Count)
			for i, r := range res.Records {
				fmt.Fprintf(&sb, "\n%d. %s:%s\n", i+1, r.IP, r.Port)
				if r.Host != "" || r.Domain != "" {
					fmt.Fprintf(&sb, "   host=%s domain=%s\n", r.Host, r.Domain)
				}
				if r.URL != "" {
					fmt.Fprintf(&sb, "   url=%s\n", r.URL)
				}
				if r.Title != "" {
					fmt.Fprintf(&sb, "   title=%s server=%s protocol=%s\n", r.Title, r.Server, r.Protocol)
				}
				loc := strings.TrimSpace(strings.Join(nonEmpty(r.Country, r.Province, r.City), " "))
				if loc != "" || r.Org != "" || r.OS != "" {
					fmt.Fprintf(&sb, "   %s org=%s os=%s updated=%s\n", loc, r.Org, r.OS, r.Updated)
				}
				if r.Banner != "" {
					fmt.Fprintf(&sb, "   banner: %s\n", clipStr(r.Banner, 400))
				}
			}
			sb.WriteString("\n")
			if res.Count == 0 {
				fmt.Fprintf(&sb, "（本页无结果。空结果 ≠ 目标不存在；检查语法：%s；换更宽的条件或去掉限定再试）\n", survey.Syntax(p))
			} else if int64(res.Page*res.Size) < res.Total {
				fmt.Fprintf(&sb, "还有更多结果：用 page=%d 取下一页\n", res.Page+1)
			}
			if res.Quota != "" {
				fmt.Fprintf(&sb, "额度：%s\n", res.Quota)
			}
			if res.EvidencePath != "" {
				fmt.Fprintf(&sb, "原始响应已写入：%s\n", res.EvidencePath)
			}
			return actool.Text(vulnPreview(sb.String(), 12000)), nil
		})
}

func nonEmpty(vs ...string) []string {
	var out []string
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func clipStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (t *ToolSet) surveyTools() []actool.CoreTool {
	if t.surveySvc == nil {
		return nil
	}
	return []actool.CoreTool{t.surveyTool(survey.Fofa), t.surveyTool(survey.Quake), t.surveyTool(survey.Hunter)}
}
