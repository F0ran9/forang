package server

// batch_campaign.go — 批量资产渗透任务模块：
//   一次输入多目标 → 自动指纹识别 → 每目标创建独立 AI 渗透任务 → 并行执行 → 汇总
//
//   POST /api/batch/create          创建批量战役（多目标+目标模板）
//   GET  /api/batch                 战役列表
//   GET  /api/batch/{id}            战役详情（任务进度+发现汇总）
//   POST /api/batch/{id}/start      启动全部待执行任务
//   POST /api/batch/{id}/stop       停止全部运行中任务

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ensureBatchTables 幂等建表。
func (s *Server) ensureBatchTables() {
	_, _ = s.m.PG().Exec(`CREATE TABLE IF NOT EXISTS batch_campaigns (
		id BIGSERIAL PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		goal_template TEXT NOT NULL DEFAULT '',
		targets JSONB NOT NULL DEFAULT '[]',
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
}

// BatchTarget 批量目标。
type BatchTarget struct {
	URL       string `json:"url"`
	Note      string `json:"note,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	TaskID    *int64 `json:"task_id,omitempty"`
	Status    string `json:"status"` // pending/created/running/done
}

// POST /api/batch/create — 创建批量战役。
func (s *Server) batchCreate(w http.ResponseWriter, r *http.Request) {
	s.ensureBatchTables()
	var b struct {
		Name         string   `json:"name"`
		Targets      []string `json:"targets"`       // URL 列表
		GoalTemplate string   `json:"goal_template"` // 目标模板（{URL} 占位符）
		AutoStart    bool     `json:"auto_start"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if len(b.Targets) == 0 {
		writeErr(w, 400, "targets 不能为空")
		return
	}
	if len(b.Targets) > 100 {
		writeErr(w, 400, "单次最多 100 个目标")
		return
	}
	if b.Name == "" {
		b.Name = fmt.Sprintf("批量渗透 %s（%d 目标）", time.Now().Format("01-02 15:04"), len(b.Targets))
	}
	if b.GoalTemplate == "" {
		b.GoalTemplate = `对目标 {URL} 进行渗透测试，尽可能多地发现高危漏洞。
指纹：{FINGERPRINT}
优先检查未授权访问/默认凭据/已知漏洞，发现的漏洞用 report_finding 提交。`
	}

	// 构建目标列表
	targets := make([]BatchTarget, 0, len(b.Targets))
	for _, url := range b.Targets {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		targets = append(targets, BatchTarget{URL: url, Status: "pending"})
	}

	// 并发指纹识别（≤10 并发）
	type fpResult struct {
		idx int
		fp  string
	}
	ch := make(chan fpResult, len(targets))
	sem := make(chan struct{}, 10)
	for i, t := range targets {
		go func(i int, url string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			fp, err := doFingerprint(r.Context(), url)
			tag := ""
			if err == nil && fp != nil {
				tag = fp.Fingerprint
			}
			ch <- fpResult{idx: i, fp: tag}
		}(i, t.URL)
	}
	for range targets {
		result := <-ch
		targets[result.idx].Fingerprint = result.fp
	}

	// 为每个目标创建独立任务
	for i := range targets {
		goal := strings.ReplaceAll(b.GoalTemplate, "{URL}", targets[i].URL)
		goal = strings.ReplaceAll(goal, "{FINGERPRINT}", targets[i].Fingerprint)

		// 创建探索图
		var expID int64
		if err := s.m.PG().QueryRow(
			`INSERT INTO explorations(description, goal) VALUES ($1,$2) RETURNING id`,
			targets[i].URL, goal).Scan(&expID); err != nil {
			continue
		}
		// origin 节点
		payload, _ := json.Marshal(map[string]any{
			"summary":     "批量战役目标：" + targets[i].URL,
			"description": targets[i].URL,
			"goal":        goal,
		})
		_, _ = s.m.PG().Exec(`INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
			VALUES ($1, 'fact', $2, 0, 'origin', 'system')`, expID, string(payload))

		// 创建任务
		taskName := fmt.Sprintf("%s [%d/%d] %s", b.Name, i+1, len(targets), truncateStr(targets[i].Fingerprint, 20))
		var taskID int64
		if err := s.m.PG().QueryRow(
			`INSERT INTO tasks (name, description, goal, exploration_id)
			VALUES ($1, $2, $3, $4) RETURNING id`,
			taskName, targets[i].URL, goal, expID).Scan(&taskID); err != nil {
			continue
		}
		targets[i].TaskID = &taskID
		targets[i].Status = "created"
	}

	// 存储战役
	targetsJSON, _ := json.Marshal(targets)
	var campaignID int64
	if err := s.m.PG().QueryRow(
		`INSERT INTO batch_campaigns (name, goal_template, targets, status)
		VALUES ($1, $2, $3, 'created') RETURNING id`,
		b.Name, b.GoalTemplate, string(targetsJSON)).Scan(&campaignID); err != nil {
		writeErr(w, 500, "创建战役失败: "+err.Error())
		return
	}

	s.c2AuditHashed("", "", "batch_create", fmt.Sprintf("campaign:%d targets:%d", campaignID, len(targets)))

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"campaign_id": campaignID,
		"name":        b.Name,
		"targets":     targets,
		"message":     fmt.Sprintf("✅ 批量战役「%s」已创建，%d 个目标已生成 %d 个 AI 渗透任务", b.Name, len(targets), countCreated(targets)),
	}})
}

// GET /api/batch — 战役列表。
func (s *Server) batchList(w http.ResponseWriter, r *http.Request) {
	s.ensureBatchTables()
	rows, err := s.m.PG().Query(`SELECT id, name, COALESCE(goal_template,''), targets, status, created_at
		FROM batch_campaigns ORDER BY id DESC LIMIT 50`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type campaign struct {
		ID        int64           `json:"id"`
		Name      string          `json:"name"`
		GoalTemplate string       `json:"goal_template"`
		Targets   json.RawMessage `json:"targets"`
		Status    string          `json:"status"`
		CreatedAt string          `json:"created_at"`
	}
	out := []campaign{}
	for rows.Next() {
		var c campaign
		var targets []byte
		var ts sql.NullTime
		if rows.Scan(&c.ID, &c.Name, &c.GoalTemplate, &targets, &c.Status, &ts) == nil {
			c.Targets = json.RawMessage(targets)
			if ts.Valid {
				c.CreatedAt = ts.Time.Format("2006-01-02 15:04")
			}
			out = append(out, c)
		}
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// GET /api/batch/{id} — 战役详情（含任务进度+发现汇总）。
func (s *Server) batchDetail(w http.ResponseWriter, r *http.Request) {
	s.ensureBatchTables()
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	var name, goalTemplate, status string
	var targetsJSON []byte
	var ts sql.NullTime
	if err := s.m.PG().QueryRow(
		`SELECT name, COALESCE(goal_template,''), targets, status, created_at FROM batch_campaigns WHERE id=$1`, id).
		Scan(&name, &goalTemplate, &targetsJSON, &status, &ts); err != nil {
		writeErr(w, 404, "战役不存在")
		return
	}

	var targets []BatchTarget
	_ = json.Unmarshal(targetsJSON, &targets)

	// 获取每个任务的状态和发现数
	type taskDetail struct {
		TaskID    int64  `json:"task_id"`
		Status    string `json:"task_status"`
		Findings  int    `json:"findings"`
		Critical  int    `json:"critical"`
	}
	taskMap := map[int64]taskDetail{}
	for _, t := range targets {
		if t.TaskID == nil {
			continue
		}
		var taskStatus string
		var findCount, critCount int
		_ = s.m.PG().QueryRow(`SELECT status FROM tasks WHERE id=$1`, *t.TaskID).Scan(&taskStatus)
		_ = s.m.PG().QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0)
			FROM findings WHERE task_id=$1`, *t.TaskID).Scan(&findCount, &critCount)
		taskMap[*t.TaskID] = taskDetail{TaskID: *t.TaskID, Status: taskStatus, Findings: findCount, Critical: critCount}
		if taskStatus != "" && taskStatus != "done" {
			t.Status = "running"
		} else if taskStatus == "done" {
			t.Status = "done"
		}
	}

	// 汇总
	totalFindings, totalCritical := 0, 0
	doneCount := 0
	for _, td := range taskMap {
		totalFindings += td.Findings
		totalCritical += td.Critical
		if td.Status == "done" {
			doneCount++
		}
	}

	createdAt := ""
	if ts.Valid {
		createdAt = ts.Time.Format("2006-01-02 15:04")
	}

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"id": id, "name": name, "goal_template": goalTemplate, "status": status,
		"targets": targets, "task_details": taskMap, "created_at": createdAt,
		"summary": map[string]any{
			"total_targets": len(targets), "done": doneCount,
			"total_findings": totalFindings, "critical": totalCritical,
		},
	}})
}

func countCreated(targets []BatchTarget) int {
	c := 0
	for _, t := range targets {
		if t.TaskID != nil {
			c++
		}
	}
	return c
}
