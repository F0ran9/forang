package server

// batch_campaign.go — 批量资产渗透（集成到任务模块）：
//   在任务页新建任务抽屉里切「批量模式」→ 多 URL → 每目标创建标准任务
//
//   POST /api/batch/create          创建批量（多目标→指纹→任务，任务出现在标准任务列表）
//   GET  /api/batch/{id}            战役详情（任务进度+发现汇总）

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
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint,omitempty"`
	TaskID      *int64 `json:"task_id,omitempty"`
	Status      string `json:"status"`
}

// POST /api/batch/create — 批量创建任务（每目标一个标准任务，出现在任务列表）。
func (s *Server) batchCreate(w http.ResponseWriter, r *http.Request) {
	s.ensureBatchTables()
	var b struct {
		Name         string   `json:"name"`
		Targets      []string `json:"targets"`
		GoalTemplate string   `json:"goal_template"`
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
		b.Name = fmt.Sprintf("批量 %s（%d 目标）", time.Now().Format("01-02 15:04"), len(b.Targets))
	}
	if b.GoalTemplate == "" {
		b.GoalTemplate = `对目标 {URL} 进行渗透测试，尽可能多地发现高危漏洞。
指纹：{FINGERPRINT}
优先检查未授权访问/默认凭据/已知漏洞。发现的漏洞用 report_finding 提交。`
	}

	// 并发指纹识别
	type fpResult struct{ idx int; fp string }
	ch := make(chan fpResult, len(b.Targets))
	sem := make(chan struct{}, 10)
	targets := make([]BatchTarget, 0, len(b.Targets))
	for _, u := range b.Targets {
		u = strings.TrimSpace(u)
		if u != "" {
			targets = append(targets, BatchTarget{URL: u, Status: "pending"})
		}
	}
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
		res := <-ch
		targets[res.idx].Fingerprint = res.fp
	}

	// 创建任务
	created := 0
	for i := range targets {
		goal := strings.ReplaceAll(b.GoalTemplate, "{URL}", targets[i].URL)
		goal = strings.ReplaceAll(goal, "{FINGERPRINT}", targets[i].Fingerprint)
		taskName := fmt.Sprintf("%s [%d/%d]", b.Name, i+1, len(targets))

		var expID int64
		if err := s.m.PG().QueryRow(
			`INSERT INTO explorations(description, goal) VALUES ($1,$2) RETURNING id`,
			targets[i].URL, goal).Scan(&expID); err != nil {
			continue
		}
		payload, _ := json.Marshal(map[string]any{
			"summary":     "批量任务：" + targets[i].URL,
			"description": targets[i].URL,
			"goal":        goal,
		})
		_, _ = s.m.PG().Exec(`INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
			VALUES ($1, 'fact', $2, 0, 'origin', 'system')`, expID, string(payload))

		var taskID int64
		if err := s.m.PG().QueryRow(
			`INSERT INTO tasks (name, description, goal, exploration_id)
			VALUES ($1, $2, $3, $4) RETURNING id`,
			taskName, targets[i].URL, goal, expID).Scan(&taskID); err != nil {
			continue
		}
		targets[i].TaskID = &taskID
		targets[i].Status = "created"
		created++
	}

	// 存战役
	targetsJSON, _ := json.Marshal(targets)
	var campaignID int64
	_ = s.m.PG().QueryRow(
		`INSERT INTO batch_campaigns (name, goal_template, targets, status)
		VALUES ($1, $2, $3, 'created') RETURNING id`,
		b.Name, b.GoalTemplate, string(targetsJSON)).Scan(&campaignID)

	s.c2AuditHashed("", "", "batch_create", fmt.Sprintf("campaign:%d targets:%d created:%d", campaignID, len(targets), created))

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"campaign_id": campaignID, "name": b.Name, "targets": targets,
		"created": created,
		"message": fmt.Sprintf("✅ 已创建 %d 个任务（共 %d 个目标）", created, len(targets)),
	}})
}

// GET /api/batch/{id} — 战役详情。
func (s *Server) batchDetail(w http.ResponseWriter, r *http.Request) {
	s.ensureBatchTables()
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	var name, status string
	var targetsJSON []byte
	var ts sql.NullTime
	if err := s.m.PG().QueryRow(
		`SELECT name, targets, status, created_at FROM batch_campaigns WHERE id=$1`, id).
		Scan(&name, &targetsJSON, &status, &ts); err != nil {
		writeErr(w, 404, "战役不存在")
		return
	}
	var targets []BatchTarget
	_ = json.Unmarshal(targetsJSON, &targets)

	// 任务状态和发现
	totalFind, totalCrit, done := 0, 0, 0
	for i := range targets {
		if targets[i].TaskID == nil {
			continue
		}
		var taskStatus string
		var fc, cc int
		_ = s.m.PG().QueryRow(`SELECT status FROM tasks WHERE id=$1`, *targets[i].TaskID).Scan(&taskStatus)
		_ = s.m.PG().QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0)
			FROM findings WHERE task_id=$1`, *targets[i].TaskID).Scan(&fc, &cc)
		targets[i].Status = taskStatus
		totalFind += fc
		totalCrit += cc
		if taskStatus == "done" {
			done++
		}
	}

	createdAt := ""
	if ts.Valid {
		createdAt = ts.Time.Format("2006-01-02 15:04")
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"id": id, "name": name, "status": status, "targets": targets, "created_at": createdAt,
		"summary": map[string]any{"total": len(targets), "done": done, "findings": totalFind, "critical": totalCrit},
	}})
}
