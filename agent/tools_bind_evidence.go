package agent

// tools_bind_evidence.go — bind_finding_evidence：把 repeater_capture / web_screenshot
// 产出的截图（或命令输出）绑定为漏洞（findings 表）的正式证据。
// 报告附录与 Word 嵌图都读取 finding_evidence 表——这是"截图进报告"的绑定环节。

import (
	"strconv"
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) bindFindingEvidence() actool.CoreTool {
	return writeTool("bind_finding_evidence",
		"把证据文件（截图 PNG / 输出文本）绑定为漏洞的正式证据。使用场景：repeater_capture 或 web_screenshot 生成截图后，先 report_finding 提交漏洞拿到 finding_id，再调用本工具把截图绑定到该漏洞——绑定的截图会自动嵌入漏洞中台报告（Markdown 附录与 Word）。kind 仅支持 screenshot / command / file。",
		obj(map[string]any{
			"finding_id": idp("漏洞 ID（report_finding 返回的 finding_id）"),
			"kind":       str("证据类型：screenshot / command / file"),
			"path":       str("文件绝对路径（如 repeater_capture 返回的 PNG 路径）"),
			"note":       str("证据说明（一句话，如：未授权用户列表接口响应）"),
			"command":    str("可选：产生该证据的命令"),
			"output":     str("可选：命令/接口输出文本"),
		}, "finding_id", "kind", "path", "note"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64  `json:"finding_id"`
				Kind      string `json:"kind"`
				Path      string `json:"path"`
				Note      string `json:"note"`
				Command   string `json:"command"`
				Output    string `json:"output"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if a.FindingID <= 0 {
				return actool.Errorf("finding_id 必填"), nil
			}
			if a.Kind != "screenshot" && a.Kind != "command" && a.Kind != "file" {
				return actool.Errorf("kind 仅支持 screenshot/command/file"), nil
			}
			if strings.TrimSpace(a.Note) == "" {
				return actool.Errorf("note 必填：一句话说明证据内容"), nil
			}
			if strings.TrimSpace(a.Path) != "" {
				if _, err := os.Stat(a.Path); err != nil {
					return actool.Errorf("文件不存在: " + a.Path), nil
				}
			} else if a.Kind == "screenshot" || a.Kind == "file" {
				return actool.Errorf("screenshot/file 类型必须提供 path"), nil
			}
			if t.findingRecorder == nil {
				return actool.Errorf("证据存储不可用（本 agent 未接通 findingRecorder）"), nil
			}
			if err := t.findingRecorder.AppendFindingEvidence(a.FindingID, db.FindingEvidence{
				Kind: a.Kind, Command: a.Command, Output: a.Output, Path: a.Path, Note: a.Note,
			}); err != nil {
				return actool.Errorf("绑定失败: " + err.Error()), nil
			}
			return actool.Text("✅ 证据已绑定到漏洞 " + itoa64(a.FindingID) +
				"（" + a.Kind + "）。该截图将出现在漏洞中台附录与 Word 报告中。"), nil
		})
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }


