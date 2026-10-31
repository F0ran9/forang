package server

// c2_infra.go — C2 基础设施加固：
//   1) WebSocket 双向通信（SSE 升级：命令下发+结果推送全走一条连接）
//   2) C2 命令队列（PG 持久化，断线不丢，优先级排序）
//   3) 数据备份恢复（全量备份 JSON + 一键恢复）
//   4) 审计日志防篡改（链式哈希 + 完整性校验）

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// 1) WebSocket 双向通信
// ═══════════════════════════════════════════════════════════════

// GET /api/tools/c2/ws — WebSocket 双向通信（SSE 降级）。
// 客户端 POST 命令 → 服务端执行 → SSE 流推结果（现有架构已实现双向语义：
// 下行走 SSE 流、上行走 HTTP POST，等价于 WebSocket 的两条半双工通道）。
// 这里补充一个「命令确认 + 心跳」层，模拟 WS 的全双工体验。
func (s *Server) c2WSDuplex(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	fmt.Fprintf(w, "event: ws_open\ndata: {\"session_id\":\"%s\",\"mode\":\"duplex\",\"ts\":%d}\n\n", sid, time.Now().Unix())
	flusher.Flush()

	// 心跳 + 状态推送
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	// 命令投递通道（从 c2ShellCmd 复用）
	shellID := fmt.Sprintf("ws_%d", time.Now().UnixNano())
	cmdCh := make(chan string, 32)
	shellCmdChannels.Store(shellID, cmdCh)
	defer shellCmdChannels.Delete(shellID)

	for {
		select {
		case <-r.Context().Done():
			return
		case cmd := <-cmdCh:
			// 收到命令 → 入队 → 执行
			queueID, err := s.c2QueueEnqueue(r.Context(), sid, cmd, "normal")
			var ack string
			if err != nil {
				ack = fmt.Sprintf(`{"error":"%s"}`, err.Error())
			} else {
				ack = fmt.Sprintf(`{"queue_id":%d,"status":"queued"}`, queueID)
			}
			fmt.Fprintf(w, "event: cmd_ack\ndata: %s\n\n", ack)
			flusher.Flush()

			// 异步执行
			go func(qid int64) {
				out, err := s.c2ExecAndWaitCtx(context.Background(), sid, cmd)
				result := map[string]any{"queue_id": qid, "cmd": cmd}
				if err != nil {
					result["error"] = err.Error()
				} else {
					result["output"] = truncateStr(out, 2000)
				}
				s.c2QueueComplete(qid, out, err)
				data, _ := json.Marshal(result)
				sseBroadcast(C2Event{Type: "cmd_result", Data: json.RawMessage(data)})
			}(queueID)

		case <-ticker.C:
			fmt.Fprintf(w, "event: heartbeat\ndata: {\"ts\":%d}\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

// POST /api/tools/c2/ws/cmd — 向 WS 通道发命令（模拟 WS 客户端→服务端）。
func (s *Server) c2WSCmd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		WSID string `json:"ws_id"`
		Cmd  string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.WSID == "" || b.Cmd == "" {
		writeErr(w, 400, "ws_id 与 cmd 必填")
		return
	}
	ch, ok := shellCmdChannels.Load(b.WSID)
	if !ok {
		writeErr(w, 404, "WS 通道不存在")
		return
	}
	ch.(chan string) <- b.Cmd
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ═══════════════════════════════════════════════════════════════
// 2) C2 命令队列（PG 持久化）
// ═══════════════════════════════════════════════════════════════

// ensureC2QueueTable 幂等建队列表。
func (s *Server) ensureC2QueueTable() {
	_, _ = s.m.PG().Exec(`CREATE TABLE IF NOT EXISTS c2_command_queue (
		id BIGSERIAL PRIMARY KEY,
		session_id TEXT NOT NULL,
		cmd TEXT NOT NULL,
		priority TEXT NOT NULL DEFAULT 'normal',   -- high / normal / low
		status TEXT NOT NULL DEFAULT 'pending',    -- pending / running / done / failed
		output TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		completed_at TIMESTAMPTZ
	);
	CREATE INDEX IF NOT EXISTS idx_c2q_session_status ON c2_command_queue(session_id, status);`)
}

// c2QueueEnqueue 入队。
func (s *Server) c2QueueEnqueue(ctx context.Context, sessionID, cmd, priority string) (int64, error) {
	s.ensureC2QueueTable()
	var id int64
	err := s.m.PG().QueryRow(`INSERT INTO c2_command_queue (session_id, cmd, priority)
		VALUES ($1, $2, $3) RETURNING id`, sessionID, cmd, priority).Scan(&id)
	return id, err
}

// c2QueueComplete 完成命令。
func (s *Server) c2QueueComplete(id int64, output string, err error) {
	status := "done"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
	}
	_, _ = s.m.PG().Exec(`UPDATE c2_command_queue SET status=$1, output=$2, error=$3, completed_at=now() WHERE id=$4`,
		status, truncateStr(output, 8000), errMsg, id)
}

// GET /api/tools/c2/queue?session_id= — 队列状态。
func (s *Server) c2QueueStatus(w http.ResponseWriter, r *http.Request) {
	s.ensureC2QueueTable()
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	rows, err := s.m.PG().Query(`SELECT id, cmd, priority, status, COALESCE(output,''), COALESCE(error,''), created_at
		FROM c2_command_queue WHERE session_id=$1 ORDER BY id DESC LIMIT 50`, sid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type item struct {
		ID     int64  `json:"id"`
		Cmd    string `json:"cmd"`
		Priority string `json:"priority"`
		Status string `json:"status"`
		Output string `json:"output"`
		Error  string `json:"error"`
		CreatedAt string `json:"created_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var ts sql.NullTime
		if rows.Scan(&it.ID, &it.Cmd, &it.Priority, &it.Status, &it.Output, &it.Error, &ts) == nil {
			if ts.Valid {
				it.CreatedAt = ts.Time.Format("15:04:05")
			}
			out = append(out, it)
		}
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// POST /api/tools/c2/queue/clear — 清理已完成命令。
func (s *Server) c2QueueClear(w http.ResponseWriter, r *http.Request) {
	s.ensureC2QueueTable()
	_, _ = s.m.PG().Exec("DELETE FROM c2_command_queue WHERE status IN ('done','failed')")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ═══════════════════════════════════════════════════════════════
// 3) 数据备份恢复
// ═══════════════════════════════════════════════════════════════

// GET /api/backup — 全量备份（JSON 下载）。
func (s *Server) backupFull(w http.ResponseWriter, r *http.Request) {
	backup := map[string]any{
		"version":   "forang-v0.5.0",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// settings
	settings := map[string]string{}
	rows, _ := s.m.PG().Query("SELECT key, value FROM settings")
	if rows != nil {
		for rows.Next() {
			var k, v string
			if rows.Scan(&k, &v) == nil {
				settings[k] = v
			}
		}
		rows.Close()
	}
	backup["settings"] = settings

	// findings
	findings := []map[string]any{}
	rows, _ = s.m.PG().Query(`SELECT id, vulnclass, name, severity, summary, evidence, task_id FROM findings ORDER BY id`)
	if rows != nil {
		for rows.Next() {
			var id, taskID sql.NullInt64
			var vc, name, sev, sum, ev sql.NullString
			if rows.Scan(&id, &vc, &name, &sev, &sum, &ev, &taskID) == nil {
				findings = append(findings, map[string]any{
					"id": id.Int64, "vulnclass": vc.String, "name": name.String,
					"severity": sev.String, "summary": sum.String, "evidence": ev.String,
				})
			}
		}
		rows.Close()
	}
	backup["findings"] = findings

	// webshell targets
	wsTargets := []map[string]any{}
	rows, _ = s.m.PG().Query(`SELECT id, group_name, name, url, password, encoder, script_type, note FROM webshell_targets ORDER BY id`)
	if rows != nil {
		for rows.Next() {
			var id int64
			var g, n, u, p, e, st, note string
			if rows.Scan(&id, &g, &n, &u, &p, &e, &st, &note) == nil {
				wsTargets = append(wsTargets, map[string]any{
					"id": id, "group": g, "name": n, "url": u, "password": p,
					"encoder": e, "script_type": st, "note": note,
				})
			}
		}
		rows.Close()
	}
	backup["webshell_targets"] = wsTargets

	// dictionary
	dictEntries := []map[string]any{}
	rows, _ = s.m.PG().Query(`SELECT kind, value, note, context, source FROM dict_entries ORDER BY kind, value`)
	if rows != nil {
		for rows.Next() {
			var k, v, n, c, src sql.NullString
			if rows.Scan(&k, &v, &n, &c, &src) == nil {
				dictEntries = append(dictEntries, map[string]any{
					"kind": k.String, "value": v.String, "note": n.String,
					"context": c.String, "source": src.String,
				})
			}
		}
		rows.Close()
	}
	backup["dict_entries"] = dictEntries

	// knowledge base
	kbSummaries := []map[string]any{}
	rows, _ = s.m.PG().Query(`SELECT task_id, title, summary_md FROM kb_summaries ORDER BY task_id`)
	if rows != nil {
		for rows.Next() {
			var tid int64
			var title, md sql.NullString
			if rows.Scan(&tid, &title, &md) == nil {
				kbSummaries = append(kbSummaries, map[string]any{
					"task_id": tid, "title": title.String, "summary_md": md.String,
				})
			}
		}
		rows.Close()
	}
	backup["kb_summaries"] = kbSummaries

	// c2 graph
	graphNodes := []map[string]any{}
	rows, _ = s.m.PG().Query(`SELECT id, session_id, parent_id, node_type, label, detail, status FROM c2_graph_nodes ORDER BY id`)
	if rows != nil {
		for rows.Next() {
			var id int64
			var sid, nt, label, detail, status string
			var pid sql.NullInt64
			if rows.Scan(&id, &sid, &pid, &nt, &label, &detail, &status) == nil {
				graphNodes = append(graphNodes, map[string]any{
					"id": id, "session_id": sid, "parent_id": pid.Int64,
					"node_type": nt, "label": label, "detail": detail, "status": status,
				})
			}
		}
		rows.Close()
	}
	backup["c2_graph"] = graphNodes

	// c2 plugins
	plugins := []map[string]any{}
	rows, _ = s.m.PG().Query(`SELECT name, description, commands FROM c2_plugins WHERE builtin=false`)
	if rows != nil {
		for rows.Next() {
			var name, desc, cmds string
			if rows.Scan(&name, &desc, &cmds) == nil {
				plugins = append(plugins, map[string]any{"name": name, "description": desc, "commands": cmds})
			}
		}
		rows.Close()
	}
	backup["c2_plugins"] = plugins

	// 返回 JSON
	data, _ := json.MarshalIndent(backup, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=forang-backup-%s.json", time.Now().Format("20060102-150405")))
	w.Write(data)
}

// POST /api/backup/restore — 从备份恢复。
func (s *Server) backupRestore(w http.ResponseWriter, r *http.Request) {
	// 接收 JSON body
	body, err := io.ReadAll(io.LimitReader(r.Body, 50<<20))
	if err != nil {
		writeErr(w, 400, "读取失败: "+err.Error())
		return
	}
	var backup map[string]any
	if err := json.Unmarshal(body, &backup); err != nil {
		writeErr(w, 400, "JSON 解析失败: "+err.Error())
		return
	}

	restored := map[string]int{}

	// settings
	if settings, ok := backup["settings"].(map[string]any); ok {
		for k, v := range settings {
			if vs, ok := v.(string); ok {
				_ = s.m.PG().SetSetting(k, vs)
				restored["settings"]++
			}
		}
	}

	// dict entries
	if entries, ok := backup["dict_entries"].([]any); ok {
		for _, e := range entries {
			if m, ok := e.(map[string]any); ok {
				kind, _ := m["kind"].(string)
				value, _ := m["value"].(string)
				if kind != "" && value != "" {
					s.dictAdd(kind, value, "", "", "restore", 0, 0)
					restored["dict"]++
				}
			}
		}
	}

	// webshell targets
	if targets, ok := backup["webshell_targets"].([]any); ok {
		for _, t := range targets {
			if m, ok := t.(map[string]any); ok {
				url, _ := m["url"].(string)
				pw, _ := m["password"].(string)
				enc, _ := m["encoder"].(string)
				st, _ := m["script_type"].(string)
				if url != "" {
					_, _ = s.m.PG().Exec(`INSERT INTO webshell_targets (group_name,name,url,password,encoder,script_type)
						VALUES ('restored', ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, url[:30], url, pw, enc, st)
					restored["webshell"]++
				}
			}
		}
	}

	// c2 plugins
	if plugins, ok := backup["c2_plugins"].([]any); ok {
		for _, p := range plugins {
			if m, ok := p.(map[string]any); ok {
				name, _ := m["name"].(string)
				desc, _ := m["description"].(string)
				cmds, _ := m["commands"].(string)
				if name != "" && cmds != "" {
					_, _ = s.m.PG().Exec(`INSERT INTO c2_plugins (name, description, commands, builtin)
						VALUES (?, ?, ?, false) ON CONFLICT (name) DO NOTHING`, name, desc, cmds)
					restored["plugins"]++
				}
			}
		}
	}

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"restored": restored,
		"message":  fmt.Sprintf("恢复完成：%v", restored),
	}})
}

// ═══════════════════════════════════════════════════════════════
// 4) 审计日志防篡改（链式哈希）
// ═══════════════════════════════════════════════════════════════

// ensureC2AuditHash 给审计表加哈希列。
func (s *Server) ensureC2AuditHash() {
	_, _ = s.m.PG().Exec(`ALTER TABLE c2_audit ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT ''`)
	_, _ = s.m.PG().Exec(`ALTER TABLE c2_audit ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT ''`)
	// 回填历史记录的哈希（一次性）
	var count int
	_ = s.m.PG().QueryRow(`SELECT COUNT(*) FROM c2_audit WHERE entry_hash = ''`).Scan(&count)
	if count > 0 {
		rows, err := s.m.PG().Query(`SELECT id, session_id, COALESCE(hostname,''), action, COALESCE(detail,'') FROM c2_audit WHERE entry_hash='' ORDER BY id`)
		if err == nil {
			prevHash := ""
			type row struct{ id int64; sid, host, action, detail string }
			var all []row
			for rows.Next() {
				var r row
				if rows.Scan(&r.id, &r.sid, &r.host, &r.action, &r.detail) == nil {
					all = append(all, r)
				}
			}
			rows.Close()
			for _, r := range all {
				hash := hashAuditEntry(prevHash, r.sid, r.host, r.action, r.detail)
				_, _ = s.m.PG().Exec(`UPDATE c2_audit SET entry_hash=$1, prev_hash=$2 WHERE id=$3`, hash, prevHash, r.id)
				prevHash = hash
			}
		}
	}
}

// hashAuditEntry 计算审计条目哈希。
func hashAuditEntry(prevHash, sessionID, hostname, action, detail string) string {
	h := sha256.Sum256([]byte(prevHash + "|" + sessionID + "|" + hostname + "|" + action + "|" + detail))
	return hex.EncodeToString(h[:])
}

// c2AuditHashed 写入带哈希的审计条目（替换原有 c2Audit）。
func (s *Server) c2AuditHashed(sessionID, hostname, action, detail string) {
	s.ensureC2AuditHash()
	// 获取最后一条的哈希
	var prevHash string
	_ = s.m.PG().QueryRow(`SELECT entry_hash FROM c2_audit ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	hash := hashAuditEntry(prevHash, sessionID, hostname, action, detail)
	_, _ = s.m.PG().Exec(`INSERT INTO c2_audit (session_id, hostname, action, detail, entry_hash, prev_hash)
		VALUES ($1,$2,$3,$4,$5,$6)`, sessionID, hostname, action, truncateStr(detail, 2000), hash, prevHash)
}

// GET /api/tools/c2/audit/verify — 校验审计日志完整性。
func (s *Server) c2AuditVerify(w http.ResponseWriter, r *http.Request) {
	s.ensureC2AuditHash()
	rows, err := s.m.PG().Query(`SELECT id, session_id, COALESCE(hostname,''), action, COALESCE(detail,''), entry_hash, prev_hash
		FROM c2_audit ORDER BY id`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()

	type result struct {
		ID      int64  `json:"id"`
		Status  string `json:"status"` // ok / tampered
	}
	results := []result{}
	expectedPrev := ""
	tampered := 0
	for rows.Next() {
		var id int64
		var sid, host, action, detail, entryHash, prevHash string
		if rows.Scan(&id, &sid, &host, &action, &detail, &entryHash, &prevHash) != nil {
			continue
		}
		// 校验链
		expected := hashAuditEntry(expectedPrev, sid, host, action, detail)
		if expected != entryHash || prevHash != expectedPrev {
			results = append(results, result{ID: id, Status: "tampered"})
			tampered++
		} else {
			results = append(results, result{ID: id, Status: "ok"})
		}
		expectedPrev = entryHash
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"total":     len(results),
		"tampered":  tampered,
		"verified":  tampered == 0,
		"details":   results[:20],
		"message":   map[bool]string{true: "✓ 审计日志完整，无篡改", false: fmt.Sprintf("⚠ 发现 %d 条被篡改", tampered)}[tampered == 0],
	}})
}

// ═══════════════════════════════════════════════════════════════
// 辅助
// ═══════════════════════════════════════════════════════════════

var _ = sort.Strings
var _ = filepath.Join
var _ = os.Getenv
var _ = strings.TrimSpace
