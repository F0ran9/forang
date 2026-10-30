package agent

// tools_c2.go — C2 指挥工具（对接独立运行的 goc2-server 管理 API）。
// goc2-server 契约：/api/v1/c2/*，Bearer 认证，{"data":...} 包裹。
// c2_beacons 列会话 → c2_exec 下发命令并轮询取回输出 → c2_tasks 查任务状态。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/c2client"
	actool "github.com/Autumn-27/norma/tool"
)

// pickStr 从 map 里按候选键序取第一个非空字符串。
func pickStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// c2ExecTool c2_exec：enqueue exec 任务 → 轮询 /clients/{id}/tasks 直到出结果或超时。
func (t *ToolSet) c2ExecTool() actool.CoreTool {
	return writeTool("c2_exec",
		"对指定 C2 beacon（会话）下发命令并等待取回输出。先 c2_beacons 拿 session_id。命令在受害主机上由 beacon 执行，timeout 秒内每 2 秒轮询一次结果；超时未完成会返回 task_id，稍后用 c2_tasks 查询。授权渗透测试场景专用。",
		obj(map[string]any{
			"session_id": str("beacon 会话 ID（c2_beacons 返回）"),
			"cmd":        str("要执行的命令"),
			"timeout":    intp("可选：等待结果秒数，默认 30"),
		}, "session_id", "cmd"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				SessionID string `json:"session_id"`
				Cmd       string `json:"cmd"`
				Timeout   int    `json:"timeout"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if strings.TrimSpace(a.SessionID) == "" || strings.TrimSpace(a.Cmd) == "" {
				return actool.Errorf("session_id 与 cmd 必填"), nil
			}
			if a.Timeout <= 0 {
				a.Timeout = 30
			}
			if a.Timeout > 120 {
				a.Timeout = 120
			}
			cli := c2client.New(c2client.FromEnv())
			taskID, err := cli.EnqueueTask(ctx, a.SessionID, "exec", map[string]any{"cmd": a.Cmd})
			if err != nil {
				return actool.Errorf("任务下发失败: " + err.Error()), nil
			}
			if taskID == "" {
				return actool.Errorf("任务已下发但服务端未返回 taskId，请用 c2_tasks 查看"), nil
			}
			deadline := time.Now().Add(time.Duration(a.Timeout) * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return actool.Errorf("已取消（task_id=" + taskID + "，可用 c2_tasks 查询）"), nil
				case <-time.After(2 * time.Second):
				}
				tasks, err := cli.ListTasks(ctx, a.SessionID, url.Values{})
				if err != nil {
					continue // 轮询抖动不致命
				}
				for _, it := range tasks {
					tm, ok := it.(map[string]any)
					if !ok {
						continue
					}
					id := pickStr(tm, "taskId", "task_id", "id")
					if id != taskID {
						continue
					}
					status := pickStr(tm, "status", "state")
					out := pickStr(tm, "output", "result", "stdout", "response")
					done := status == "completed" || status == "done" || status == "success" || out != ""
					if !done {
						break // 还在跑，继续等
					}
					if len(out) > 8000 {
						out = out[:8000] + "\n...(截断)"
					}
					return actool.Text(fmt.Sprintf("✅ c2_exec（%s @ %s）\n%s", taskID, a.SessionID, out)), nil
				}
			}
			return actool.Text(fmt.Sprintf("⏳ %ds 内未取到结果。task_id=%s，稍后用 c2_tasks（session_id=%s）查询。", a.Timeout, taskID, a.SessionID)), nil
		})
}

func (t *ToolSet) c2Tools() []actool.CoreTool {
	tools := []actool.CoreTool{
		writeTool("c2_beacons",
			"列出 C2 服务器（goc2 teamserver）当前全部 beacon 会话：session_id、主机、用户、IP、系统、最后上线时间等原始字段。C2 未运行或不可达时报错。后续用 c2_exec 对某会话下发命令。",
			obj(map[string]any{}),
			func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				cli := c2client.New(c2client.FromEnv())
				clients, err := cli.ListClients(ctx, url.Values{})
				if err != nil {
					return actool.Errorf("goc2 不可达: " + err.Error()), nil
				}
				if len(clients) == 0 {
					return actool.Text("当前无活跃 beacon 会话。"), nil
				}
				b, _ := json.MarshalIndent(clients, "", "  ")
				return actool.Text(fmt.Sprintf("共 %d 个 beacon 会话：\n%s", len(clients), string(b))), nil
			}),
		t.c2ExecTool(),
		writeTool("c2_tasks",
			"查询某 beacon 会话的任务列表与结果（含 c2_exec 超时后补查）。可传 task_id 只看该任务。",
			obj(map[string]any{
				"session_id": str("beacon 会话 ID"),
				"task_id":    str("可选：只查这个任务"),
			}, "session_id"),
			func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					SessionID string `json:"session_id"`
					TaskID    string `json:"task_id"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf("参数解析失败: " + err.Error()), nil
				}
				if strings.TrimSpace(a.SessionID) == "" {
					return actool.Errorf("session_id 必填"), nil
				}
				cli := c2client.New(c2client.FromEnv())
				params := url.Values{}
				if a.TaskID != "" {
					params.Set("taskId", a.TaskID)
				}
				tasks, err := cli.ListTasks(ctx, a.SessionID, params)
				if err != nil {
					return actool.Errorf("查询失败: " + err.Error()), nil
				}
				b, _ := json.MarshalIndent(tasks, "", "  ")
				return actool.Text(fmt.Sprintf("共 %d 条任务：\n%s", len(tasks), string(b))), nil
			}),
		writeTool("c2_listeners",
			"列出 C2 服务器全部监听器（协议/端口/状态）。",
			obj(map[string]any{}),
			func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				cli := c2client.New(c2client.FromEnv())
				listeners, err := cli.ListListeners(ctx)
				if err != nil {
					return actool.Errorf("goc2 不可达: " + err.Error()), nil
				}
				if len(listeners) == 0 {
					return actool.Text("当前无监听器。"), nil
				}
				b, _ := json.MarshalIndent(listeners, "", "  ")
				return actool.Text(fmt.Sprintf("共 %d 个监听器：\n%s", len(listeners), string(b))), nil
			}),
	}
	return tools
}
