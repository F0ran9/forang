package agent

// POC 闭环只读/受控写入工具（移植自 AI-PENTEST 平台）：
//   - match_poc       指纹 → POC 候选批量匹配（只读）
//   - run_poc_verify  对单目标跑 nuclei 模板验证（写：会真实发请求，走拦截审批）
//   - save_poc        验证成功后把 AI 起草的模板入库（写）
// 验证成功的 POC 才允许 save_poc；未验证成功不要存库。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	pgdb "github.com/Autumn-27/artex/db"
)

// SetPocStore wires the POC store (nil = poc tools unavailable).
func (t *ToolSet) SetPocStore(ps *pgdb.PocStore) { t.pocs = ps }

func (t *ToolSet) needPocs(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) func(context.Context, json.RawMessage) (actool.Result, error) {
	return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if t.pocs == nil {
			return actool.Errorf("POC 存储不可用（本 agent 未接通 poc store）"), nil
		}
		return run(ctx, in)
	}
}

func (t *ToolSet) matchPocTool() actool.CoreTool {
	return readTool("match_poc",
		"POC 库批量匹配：输入 [{target, component}]（component 为指纹名/关键字，如 shiro、ruoyi 4.7.1、thinkphp 5.0.23），返回命中的 POC 候选（id/title/cve/severity/匹配关键字）。先跑 run_web_recon 拿指纹，再调本工具一次批量查全；然后对每条候选读 run_poc_verify 精确验证。",
		obj(map[string]any{
			"assets": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"target":    str("目标 URL 或 host"),
						"component": str("指纹名/版本关键字"),
					},
					"required": []string{"target", "component"},
				},
			},
		}, "assets"),
		t.needPocs("match_poc", func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Assets []pgdb.PocTargetMatchInput `json:"assets"`
			}
			if err := json.Unmarshal(in, &a); err != nil || len(a.Assets) == 0 {
				return actool.Text("ERROR: assets 必填（[{target,component}]，单次最多 500 条）"), nil
			}
			if len(a.Assets) > 500 {
				a.Assets = a.Assets[:500]
			}
			matches, err := t.pocs.MatchPocs(a.Assets)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("POC 匹配失败: %v", err)), nil
			}
			if len(matches) == 0 {
				return actool.Text("（POC 库无匹配候选。可依据指纹与响应特征自行构造 nuclei yaml，验证成功后用 save_poc 入库。）"), nil
			}
			out := make([]map[string]any, 0, len(matches))
			for _, m := range matches {
				out = append(out, map[string]any{
					"target": m.Target, "poc_id": m.Poc.ID, "title": m.Poc.Title,
					"cve": m.Poc.CVE, "severity": m.Poc.Severity,
					"verified": m.Poc.Verified, "matched_on": m.Reason,
				})
			}
			b, _ := json.Marshal(out)
			return actool.Text(string(b)), nil
		}))
}

func (t *ToolSet) runPocVerifyTool() actool.CoreTool {
	return writeTool("run_poc_verify",
		"POC 精确验证：对单个目标执行库里某条 nuclei 模板（真实发请求）。target 填完整 URL。返回 matched/not_matched；命中后立即 report_finding（vulnclass=组件名/cve，evidence 附 nuclei 输出），失败最多 3 次 payload 变体重试后放弃。宿主机未装 nuclei 时会明确报错。",
		obj(map[string]any{
			"poc_id": idp("POC 库条目 id（match_poc 返回的 poc_id）"),
			"target": str("完整目标 URL，如 https://example.com"),
		}, "poc_id", "target"),
		t.needPocs("run_poc_verify", func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				PocID  int64  `json:"poc_id"`
				Target string `json:"target"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.PocID <= 0 || strings.TrimSpace(a.Target) == "" {
				return actool.Text("ERROR: poc_id 与 target 必填"), nil
			}
			if !strings.HasPrefix(a.Target, "http://") && !strings.HasPrefix(a.Target, "https://") {
				return actool.Text("ERROR: target 必须是完整 URL（http/https 开头）"), nil
			}
			p, err := t.pocs.GetPoc(a.PocID)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("读取 POC 失败: %v", err)), nil
			}
			if p == nil {
				return actool.Text(fmt.Sprintf("ERROR: POC #%d 不存在", a.PocID)), nil
			}
			if strings.TrimSpace(p.Template) == "" {
				return actool.Text("ERROR: 该 POC 模板为空"), nil
			}
			nuclei, err := exec.LookPath("nuclei")
			if err != nil {
				return actool.Text("ERROR: 宿主机未安装 nuclei，无法验证。请提示用户安装，或改用平台其他检测工具。"), nil
			}
			tmp, err := osCreateTempFile("artex-agent-poc-*.yaml", p.Template)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("写临时模板失败: %v", err)), nil
			}
			defer osRemoveTempFile(tmp.Name())

			runCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			cmd := exec.CommandContext(runCtx, nuclei, "-u", a.Target, "-t", tmp.Name(), "-silent", "-duc")
			var outBuf, errBuf strings.Builder
			cmd.Stdout = &outBuf
			cmd.Stderr = &errBuf
			runErr := cmd.Run()
			output := strings.TrimSpace(outBuf.String())
			if output != "" && strings.Contains(output, "flag provided but not defined") {
				_ = t.pocs.RecordVerifyResult(p.ID, a.Target, "error: nuclei 参数不兼容: "+truncateRunes(output, 200), false)
				return actool.Text("ERROR: 宿主机 nuclei 版本过旧，参数不兼容。请升级 nuclei 后重试。"), nil
			}
			if output != "" {
				_ = t.pocs.RecordVerifyResult(p.ID, a.Target, truncateRunes("matched: "+output, 4000), true)
				return actool.Text(fmt.Sprintf("MATCHED: POC #%d 在 %s 命中。立即 report_finding（evidence 附以下输出，勿伪造）：\n%s",
					p.ID, a.Target, truncateRunes(output, 3000))), nil
			}
			if runErr != nil {
				res := fmt.Sprintf("error: nuclei 运行失败: %v；stderr: %s", runErr, truncateRunes(errBuf.String(), 300))
				_ = t.pocs.RecordVerifyResult(p.ID, a.Target, res, false)
				return actool.Text("NOT_MATCHED（运行异常）: " + res), nil
			}
			_ = t.pocs.RecordVerifyResult(p.ID, a.Target, "not_matched", false)
			return actool.Text(fmt.Sprintf("NOT_MATCHED: POC #%d 在 %s 未命中。分析原因（路径/参数变形/已修补），最多 3 次变体重试；仍失败记录原因跳过，不要无据硬打。", p.ID, a.Target)), nil
		}))
}

func (t *ToolSet) savePocTool() actool.CoreTool {
	return writeTool("save_poc",
		"POC 入库：仅当 run_poc_verify 已验证命中（或模板来自可信来源且已人工确认）才调用。保存 AI 起草的 nuclei yaml + 指纹关键字，供后续资产批量复用。source 固定填 ai。",
		obj(map[string]any{
			"title":     str("POC 标题（漏洞名+组件）"),
			"component": str("指纹匹配关键字，逗号分隔多个（如 ruoyi,若依）"),
			"cve":       str("CVE 编号（可空）"),
			"severity":  str("critical/high/medium/low"),
			"template":  str("nuclei yaml 模板全文"),
		}, "title", "component", "template"),
		t.needPocs("save_poc", func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Title     string `json:"title"`
				Component string `json:"component"`
				CVE       string `json:"cve"`
				Severity  string `json:"severity"`
				Template  string `json:"template"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Text("ERROR: 参数非法"), nil
			}
			if strings.TrimSpace(a.Title) == "" || strings.TrimSpace(a.Component) == "" || strings.TrimSpace(a.Template) == "" {
				return actool.Text("ERROR: title / component / template 必填"), nil
			}
			p, err := t.pocs.CreatePoc(a.Title, a.Component, a.CVE, a.Severity, a.Template, "ai")
			if err != nil {
				return actool.Errorf(fmt.Sprintf("POC 入库失败: %v", err)), nil
			}
			return actool.Text(fmt.Sprintf("✅ POC #%d 已入库：%s（component=%s）。后续 BatchMatchPoc/管理页可直接复用。", p.ID, p.Title, p.Component)), nil
		}))
}

// ensureNucleiAuthor injects `author` into the info block when missing.
func ensureNucleiAuthor(tpl string) string {
	if strings.Contains(tpl, "author:") {
		return tpl
	}
	idx := strings.Index(tpl, "info:")
	if idx < 0 {
		return tpl
	}
	rest := tpl[idx+len("info:"):]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		return tpl + "\n  author: artex\n"
	}
	return tpl[:idx+len("info:")+nl+1] + "  author: artex\n" + rest[nl+1:]
}

func osCreateTempFile(pattern, content string) (*os.File, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(ensureNucleiAuthor(content)); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return f, nil
}

func osRemoveTempFile(path string) { os.Remove(path) }
