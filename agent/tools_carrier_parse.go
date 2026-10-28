package agent

// carrier_parse — 在线解析载体文件：对话/任务里用户直接发来的 wxapkg、反编译
// 源码 zip、APK/IPA/HAR，不用先去控制台建目标。path 相对当前工作目录（对话
// 附件落在 uploads/ 下），也接受绝对路径。要沉淀进载体库仍在控制台上传。

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/carriers"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) carrierParse() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "carrier_parse",
		Description: "解析载体文件（wxapkg 小程序包 / 反编译源码 zip / APK / IPA / HAR），返回 appid、页面清单、后端域名、API 端点、硬编码密钥。用户在对话/任务里发来客户端包后调用；path 为相对当前工作目录的路径（对话附件通常在 uploads/ 下），也接受绝对路径。",
		Schema: obj(map[string]any{
			"path": str("文件路径（相对当前工作目录或绝对路径）"),
		}, "path"),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Path string `json:"path"`
			}
			_ = json.Unmarshal(in, &a)
			p := strings.TrimSpace(a.Path)
			if p == "" {
				return actool.Errorf("path 必填"), nil
			}
			full := p
			if !filepath.IsAbs(full) {
				wd := "."
				if tc != nil && tc.WorkingDir != "" {
					wd = tc.WorkingDir
				}
				full = filepath.Join(wd, full)
			}
			kind := carriers.DetectKind(full)
			if kind == "other" {
				return actool.Errorf("无法识别的载体类型（支持 wxapkg / 解包源码 zip / apk / ipa / har / json / js；.zip 请确认是反编译源码包）"), nil
			}
			an, err := carriers.Analyze(full, kind)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("解析失败: %v", err)), nil
			}
			b, _ := json.Marshal(an)
			return actool.Text(string(b)), nil
		},
	})
}
