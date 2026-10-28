package server

// taskcontainer.go — 每任务一个 Kali 容器（移植自哨兵 docker.ts 的语义，适配
// ARTEX 直跑 VM 的架构）：开关打开后，任务内（TaskID>0）的 Bash 调用改为
// `docker exec artex-task-<id>` 执行——工具安装/扫描/爆破的污染与风险被关进
// 一次性容器，VM 宿主保持干净；对话（TaskID=0）不容器化（需要宿主的 adb 等）。
// 镜像默认 kalilinux/kali-rolling（可配置镜像名/镜像源前缀）；同路径挂载
// <workDir> 保证 SDK 文件工具（宿主侧）与容器内路径一致；host 网络（可改）。
// 容器懒创建（首次 Bash 时 ensureRunning），任务删除时容器保留（可手动清），
// 启动时自动清理无主容器。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
	acperm "github.com/Autumn-27/norma/permission"
)

const (
	containerSettingEnabled = "task_container.enabled"
	containerSettingImage   = "task_container.image"
	containerSettingNetwork = "task_container.network" // host / bridge
	defaultContainerImage   = "kalilinux/kali-rolling:latest"
)

func (s *Server) containerConfig() (on bool, image, network string) {
	image, network = defaultContainerImage, "host"
	if s.m.pg == nil {
		return
	}
	if v, ok, _ := s.m.pg.GetSetting(containerSettingEnabled); ok {
		on = v == "true" || v == "1"
	}
	if v, ok, _ := s.m.pg.GetSetting(containerSettingImage); ok && strings.TrimSpace(v) != "" {
		image = strings.TrimSpace(v)
	}
	if v, ok, _ := s.m.pg.GetSetting(containerSettingNetwork); ok && (v == "host" || v == "bridge") {
		network = v
	}
	return
}

func containerName(taskID int64) string { return fmt.Sprintf("artex-task-%d", taskID) }

func dockerCmd(ctx context.Context, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var buf bytes.Buffer
	cmd := exec.CommandContext(c, "docker", args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// ensureTaskContainer: 不存在则创建+启动，存在未跑则 start。
func ensureTaskContainer(ctx context.Context, taskID int64, image, network string) error {
	name := containerName(taskID)
	out, err := dockerCmd(ctx, "inspect", "-f", "{{.State.Running}}", name)
	if err == nil {
		if strings.TrimSpace(out) == "true" {
			return nil
		}
		if _, serr := dockerCmd(ctx, "start", name); serr == nil {
			return nil
		}
		// 存在但坏了：删掉重建。
		_, _ = dockerCmd(ctx, "rm", "-f", name)
	}
	args := []string{"run", "-d", "--name", name}
	if network == "host" {
		args = append(args, "--network", "host")
	}
	// 同路径挂载（哨兵语义）：宿主 <workDir> == 容器内路径，SDK 文件工具与
	// 容器 Bash 看到同一份文件。workDir = m.dir（平台数据根）。
	args = append(args, "-v", fmt.Sprintf("%s:%s", workRoot, workRoot), image, "sleep", "infinity")
	out, err = dockerCmd(ctx, args...)
	if err != nil {
		return fmt.Errorf("创建容器失败: %v %s", err, strings.TrimSpace(out))
	}
	log.Printf("[container] 任务 %d 容器已创建（%s/%s）", taskID, image, network)
	return nil
}

// workRoot 是挂载进容器的平台根（server New 时由 m.dir 填充）。
var workRoot = "/root/Desktop/artex"

// dockerBashTool 构造与 SDK Bash 同名同 schema 的容器版：调用改走
// docker exec -w <cwd>。cwd 由 toolcontext 不可得——SDK Bash 的 cwd 语义取
// 会话工作目录，这里用 workRoot 下按需 cd（命令自己 cd 即可；-w 设平台根）。
func dockerBashTool(taskID int64, image, network string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "Bash",
		Description: "在任务专属 Kali 容器内执行命令（隔离环境；工具请先 apt install）。参数同标准 Bash。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command":    map[string]any{"type": "string", "description": "要执行的 shell 命令"},
				"timeout_ms": map[string]any{"type": "integer", "description": "超时毫秒，默认 120000"},
			},
			"required": []string{"command"},
		},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Command   string `json:"command"`
				TimeoutMs int    `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &a); err != nil || strings.TrimSpace(a.Command) == "" {
				return actool.Errorf("command 必填"), nil
			}
			if err := ensureTaskContainer(ctx, taskID, image, network); err != nil {
				return actool.Errorf("容器未就绪: " + err.Error()), nil
			}
			timeout := time.Duration(a.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 120 * time.Second
			}
			if timeout > 10*time.Minute {
				timeout = 10 * time.Minute
			}
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			var buf bytes.Buffer
			cmd := exec.CommandContext(c, "docker", "exec", "-w", workRoot, containerName(taskID), "sh", "-c", a.Command)
			cmd.Stdout, cmd.Stderr = &buf, &buf
			err := cmd.Run()
			out := buf.String()
			const cap = 30000
			if len(out) > cap {
				out = out[:cap] + "\n…（输出已截断）"
			}
			if err != nil && c.Err() == context.DeadlineExceeded {
				return actool.Text(out + "\n（超时终止）"), nil
			}
			if err != nil {
				return actool.Text(fmt.Sprintf("%s\n（退出码异常: %v）", out, err)), nil
			}
			return actool.Text(out), nil
		},
	})
}

// swapBashForContainers 挂在 ToolResolve 之后（server.assembly 里调用）：
// 容器模式开 && 是任务运行 && 该工具是 SDK Bash → 换成 docker exec 版。
func (s *Server) swapBashForContainers(ctx context.Context, tools []actool.CoreTool) []actool.CoreTool {
	on, image, network := s.containerConfig()
	if !on {
		return tools
	}
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID == 0 {
		return tools
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if t.Name() == "Bash" {
			out = append(out, dockerBashTool(ri.TaskID, image, network))
			continue
		}
		out = append(out, t)
	}
	return out
}

// cleanupOrphanContainers 启动时删除任务已不存在的 artex-task-* 容器。
func (s *Server) cleanupOrphanContainers() {
	if s.m.pg == nil {
		return // 库不可用时一律不清：taskExists 对 nil 恒 false，会误删全部任务容器
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := dockerCmd(ctx, "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		return
	}
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if !strings.HasPrefix(name, "artex-task-") {
			continue
		}
		var id int64
		if _, err := fmt.Sscanf(strings.TrimPrefix(name, "artex-task-"), "%d", &id); err != nil || !s.taskExists(id) {
			_, _ = dockerCmd(ctx, "rm", "-f", name)
			log.Printf("[container] 清理无主容器 %s", name)
		}
	}
}

func (s *Server) taskExists(id int64) bool {
	if id <= 0 || s.m.pg == nil {
		return false
	}
	var one int
	return s.m.pg.QueryRow(`SELECT 1 FROM tasks WHERE id=$1`, id).Scan(&one) == nil
}

// ---------- HTTP ----------

func (s *Server) registerContainerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/task-container", s.containerGet)
	mux.HandleFunc("PUT /api/task-container", s.containerSet)
}

func (s *Server) containerGet(w http.ResponseWriter, r *http.Request) {
	on, image, network := s.containerConfig()
	writeJSON(w, 200, map[string]any{"enabled": on, "image": image, "network": network})
}

func (s *Server) containerSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled  *bool   `json:"enabled"`
		Image    *string `json:"image"`
		Network  *string `json:"network"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求体无效")
		return
	}
	if body.Enabled != nil {
		_ = s.m.pg.SetSetting(containerSettingEnabled, boolStr(*body.Enabled))
	}
	if body.Image != nil && strings.TrimSpace(*body.Image) != "" {
		_ = s.m.pg.SetSetting(containerSettingImage, strings.TrimSpace(*body.Image))
	}
	if body.Network != nil && (*body.Network == "host" || *body.Network == "bridge") {
		_ = s.m.pg.SetSetting(containerSettingNetwork, *body.Network)
	}
	s.containerGet(w, r)
}
