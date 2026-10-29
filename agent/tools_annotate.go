package agent

// tools_annotate.go — droid_annotate：在 APP/网页截图上标注点击位置（红圈+标签），
// 证明"点的是哪个位置"。标注后的 PNG 可 bind_finding_evidence 绑进漏洞报告。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) annotateTool() actool.CoreTool {
	return writeTool("droid_annotate",
		"在截图上标注点击/操作位置（红圈+十字准星+标签），证明\"点的是哪个按钮、哪个输入框\"。使用场景：droid_screencap 截 APP 页面后标注点击坐标（uiautomator dump 可拿到元素坐标）；网页截图也可标注。输入为已存在的截图路径，输出标注版 PNG 到同目录 evidence/repeater/ 或原图旁。",
		obj(map[string]any{
			"img":   str("原图截图路径（绝对路径，如 droid_screencap 返回的路径）"),
			"x":     intp("点击/目标的 X 坐标（截图像素坐标，uiautomator dump bounds 中心）"),
			"y":     intp("点击/目标的 Y 坐标"),
			"label": str("标注文字（如：点击「登录」按钮）"),
			"note":  str("可选：底部注释（如：越权操作演示步骤 2/3）"),
		}, "img", "x", "y", "label"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Img   string `json:"img"`
				X     int    `json:"x"`
				Y     int    `json:"y"`
				Label string `json:"label"`
				Note  string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.Img) == "" || a.X <= 0 || a.Y <= 0 {
				return actool.Errorf("img/x/y 必填"), nil
			}
			if _, err := os.Stat(a.Img); err != nil {
				return actool.Errorf("截图不存在: " + a.Img), nil
			}
			dir, derr := t.needDroidDir()
			if derr != nil {
				return actool.Errorf(derr.Error()), nil
			}
			// 释放标注助手脚本
			helperDir := filepath.Join(dir, "tools")
			_ = os.MkdirAll(helperDir, 0o755)
			helper := filepath.Join(helperDir, "annotate.py")
			if err := os.WriteFile(helper, []byte(annotateScript), 0o644); err != nil {
				return actool.Errorf("释放标注脚本失败: " + err.Error()), nil
			}
			out := strings.TrimSuffix(a.Img, filepath.Ext(a.Img)) + "-annotated.png"
			args := []string{helper,
				"--img", a.Img, "--out", out,
				"--x", fmt.Sprintf("%d", a.X), "--y", fmt.Sprintf("%d", a.Y),
			}
			if a.Label != "" {
				args = append(args, "--label", a.Label)
			}
			if a.Note != "" {
				args = append(args, "--note", a.Note)
			}
			probe := execPy(args...)
			if probe.err != nil {
				return actool.Errorf(fmt.Sprintf("标注失败: %v；%s", probe.err, probe.out)), nil
			}
			st, serr := os.Stat(out)
			if serr != nil {
				return actool.Errorf("标注产物缺失"), nil
			}
			return actool.Text(fmt.Sprintf("✅ 标注完成: %s（%d KB）\n用 bind_finding_evidence 绑定到漏洞，报告自动嵌图。",
				out, st.Size()/1024)), nil
		})
}

type pyResult struct {
	err error
	out string
}

func execPy(args ...string) pyResult {
	cmd := exec.CommandContext(context.Background(), "python3", args...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return pyResult{err: err, out: strings.TrimSpace(out.String())}
}
