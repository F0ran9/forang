package server

// kb_distill.go — 知识蒸馏（移植自 AI-PENTEST app/knowledge/distill.py）：
// 任务终态（done/failed/timeout）后收集 数据 → LLM 蒸馏成四章 markdown 总结 →
// kb_summaries 表（UPSERT）+ 切块入 kb_chunks 检索索引。
// LLM 失败/超时/空返回 → 模板降级（status='failed'），保证每任务必有总结。
// 触发：后台轮询（对齐 reviewer.go 的 Pick 模式，不用侵入任务终态路径）+ 手动重建。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"log"
	"math"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

const kbDistillInterval = 30 * time.Second

// kbSystemPrompt 蒸馏提示词（对齐 aipentest DISTILL_SYS_PROMPT 的四章结构）。
const kbSystemPrompt = `你是渗透测试知识管理专家。把一次渗透测试任务的原始记录蒸馏成一份结构化 markdown 知识总结，供团队跨任务沉淀复用。

硬性要求：
1. 只基于给定数据，严禁编造漏洞/数据；某类数据缺失时如实写「本次无」。
2. 漏洞条目必须保留可复现要素：目标、payload/POC、CVE 编号（若有）。
3. 经验教训要可执行（"下次遇到 X 应先做 Y"），不要空话套话。
4. 直接输出 markdown 正文（不要用代码围栏包裹全文），一级标题用「# {title}」，之后固定四章：
## 执行概况
## 漏洞与可复用手法
## 经验教训
## 下次建议`

// startKBDistillLoop 轮询终态任务 → 蒸馏。幂等（进程内一份）。
func (s *Server) startKBDistillLoop() {
	go func() {
		t := time.NewTicker(kbDistillInterval)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				if s.m == nil || s.m.pg == nil {
					continue
				}
				ids, err := s.pickKBPendingTasks(3)
				if err != nil {
					continue
				}
				for _, id := range ids {
					s.distillTask(id, "auto")
				}
			}
		}
	}()
}

// pickKBPendingTasks 终态且无 done 总结（或排队中）的任务，旧→新。
func (s *Server) pickKBPendingTasks(limit int) ([]int64, error) {
	rows, err := s.m.PG().Query(`
SELECT t.id FROM tasks t
WHERE t.status IN ('done','failed','timeout')
  AND NOT EXISTS (
    SELECT 1 FROM kb_summaries k WHERE k.task_id = t.id AND k.status IN ('done','running')
  )
ORDER BY t.id ASC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

type kbTaskInfo struct {
	ID     int64
	Name   string
	Goal   string
	Descr  string
	Status string
}

// kbFinding 蒸馏数据源里的一条漏洞。
type kbFinding struct {
	Vulnclass, Summary, Severity, Target, Evidence string
	Cvss                                         float64
}

// distillTask 收集任务知识数据 → LLM 蒸馏 → UPSERT kb_summaries + 切块索引。
func (s *Server) distillTask(taskID int64, source string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[kb] task %d panic: %v\n%s", taskID, r, debug.Stack())
			s.setKBSummaryFailed(taskID, fmt.Sprint(r))
		}
	}()
	db := s.m.PG()

	// 占位防并发重入（同一任务同时只蒸馏一次）
	res, err := db.Exec(`INSERT INTO kb_summaries (task_id, status, source) VALUES ($1,'running',$2)
		ON CONFLICT (task_id) DO UPDATE SET status='running', source=$2, updated_at=now()
		WHERE kb_summaries.status NOT IN ('running')`, taskID, source)
	if err != nil {
		log.Printf("[kb] task %d 占位失败: %v", taskID, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return // 已在跑
	}

	var t kbTaskInfo
	var goal, descr sql.NullString
	err = db.QueryRow(`SELECT id, COALESCE(name,''), goal, description, status FROM tasks WHERE id=$1`, taskID).
		Scan(&t.ID, &t.Name, &goal, &descr, &t.Status)
	if err != nil {
		s.setKBSummaryFailed(taskID, "任务不存在: "+err.Error())
		return
	}
	t.Goal, t.Descr = goal.String, descr.String

	// findings（按 task_id，severity 排序）
	finds := []kbFinding{}
	frows, err := db.Query(`SELECT COALESCE(vulnclass,''), COALESCE(summary,''), COALESCE(severity,''),
		COALESCE(target,''), COALESCE(evidence,''), COALESCE(cvss,0) FROM findings WHERE task_id=$1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3 ELSE 4 END, created_at DESC LIMIT 60`, taskID)
	if err == nil {
		for frows.Next() {
			var f kbFinding
			if frows.Scan(&f.Vulnclass, &f.Summary, &f.Severity, &f.Target, &f.Evidence, &f.Cvss) == nil {
				finds = append(finds, f)
			}
		}
		frows.Close()
	}

	// facts（探索图 kind='fact' 节点正文摘要 = 测试记忆）
	facts := []string{}
	factRows, err := db.Query(`
SELECT en.body FROM exploration_nodes en
JOIN tasks t ON t.exploration_id = en.exploration_id
WHERE t.id = $1 AND en.kind='fact' ORDER BY en.id DESC LIMIT 50`, taskID)
	if err == nil {
		for factRows.Next() {
			var body sql.NullString
			if factRows.Scan(&body) == nil && strings.TrimSpace(body.String) != "" {
				facts = append(facts, truncateStr(body.String, 300))
			}
		}
		factRows.Close()
	}

	// worker 意图清单（任务做了什么）
	intents := []string{}
	irows, err := db.Query(`
SELECT en.body FROM exploration_nodes en
JOIN tasks t ON t.exploration_id = en.exploration_id
WHERE t.id = $1 AND en.kind='intent' ORDER BY en.id LIMIT 30`, taskID)
	if err == nil {
		for irows.Next() {
			var body sql.NullString
			if irows.Scan(&body) == nil && strings.TrimSpace(body.String) != "" {
				intents = append(intents, truncateStr(body.String, 160))
			}
		}
		irows.Close()
	}

	// ---- 构造数据串 ----
	var parts []string
	parts = append(parts, "## 任务元信息",
		"- task_id: "+fmt.Sprintf("%d", taskID),
		"- 任务名: "+t.Name,
		"- 目标描述: "+truncateStr(t.Descr, 300),
		"- 任务目标: "+truncateStr(t.Goal, 500),
		"- 终态: "+t.Status)
	if len(intents) > 0 {
		parts = append(parts, fmt.Sprintf("\n## 执行意图（%d 条）", len(intents)))
		for _, i := range intents {
			parts = append(parts, "- "+i)
		}
	}
	if len(finds) > 0 {
		parts = append(parts, fmt.Sprintf("\n## Findings（%d 条，严重度降序）", len(finds)))
		for _, f := range finds {
			parts = append(parts, fmt.Sprintf("- [%s/%s] %s\n  目标: %s  CVSS: %.1f\n  描述: %s\n  PoC: %s",
				f.Severity, f.Vulnclass, f.Summary, f.Target, f.Cvss,
				truncateStr(f.Summary, 200), truncateStr(f.Evidence, 200)))
		}
	} else {
		parts = append(parts, "\n## Findings\n（本次无 finding 入库）")
	}
	if len(facts) > 0 {
		parts = append(parts, fmt.Sprintf("\n## 测试记忆/facts（%d 条）", len(facts)))
		for _, m := range facts {
			parts = append(parts, "- "+m)
		}
	} else {
		parts = append(parts, "\n## 测试记忆\n（本次无测试记忆）")
	}
	dataStr := strings.Join(parts, "\n")
	if len(dataStr) > 60000 {
		dataStr = dataStr[:60000] + "\n…（已截断）"
	}

	title := t.Name
	if title == "" {
		title = fmt.Sprintf("task-%d", taskID)
	}

	// ---- LLM 蒸馏（失败降级模板）----
	summaryMD, model, derr := s.kbCallLLM(title, dataStr)
	if derr != nil {
		log.Printf("[kb] task %d LLM 蒸馏失败，模板降级: %v", taskID, derr)
		summaryMD = kbFallbackMarkdown(t, finds, facts, intents, derr)
	} else if strings.TrimSpace(summaryMD) == "" {
		derr = fmt.Errorf("LLM 返回空")
		summaryMD = kbFallbackMarkdown(t, finds, facts, intents, derr)
	}

	status := "done"
	errMsg := ""
	if derr != nil {
		status = "failed"
		errMsg = truncateStr(derr.Error(), 4000)
	}

	// ---- UPSERT + 切块索引 ----
	_, _ = db.Exec(`INSERT INTO kb_summaries (task_id, title, task_status, status, source, model,
		vuln_count, fact_count, summary_md, error, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
ON CONFLICT (task_id) DO UPDATE SET title=$2, task_status=$3, status=$4, source=$5, model=$6,
	vuln_count=$7, fact_count=$8, summary_md=$9, error=$10, updated_at=now()`,
		taskID, title, t.Status, status, source, model, len(finds), len(facts), summaryMD, errMsg)
	s.indexKBSummary(taskID, summaryMD)
	log.Printf("[kb] task %d 蒸馏完成 status=%s vulns=%d facts=%d source=%s", taskID, status, len(finds), len(facts), source)
}

// kbCallLLM 用平台当前（或 reviewer）模型跑蒸馏。
func (s *Server) kbCallLLM(title, dataStr string) (string, string, error) {
	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, cfg, ok := s.providerForProfile(profileID)
	if !ok {
		return "", "", fmt.Errorf("模型 profile 不可用")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	text, err := streamCollectText(ctx, prov, kbSystemPrompt,
		"总结标题："+title+"\n\n请基于以下数据生成知识总结：\n\n"+dataStr)
	if err != nil {
		return "", cfg.Model, err
	}
	return text, cfg.Model, nil
}

func (s *Server) setKBSummaryFailed(taskID int64, reason string) {
	_, _ = s.m.PG().Exec(`INSERT INTO kb_summaries (task_id, status, error, updated_at)
		VALUES ($1,'failed',$2, now())
		ON CONFLICT (task_id) DO UPDATE SET status='failed', error=$2, updated_at=now()`,
		taskID, truncateStr(reason, 4000))
}

// kbFallbackMarkdown 模板降级：保底统计 + 原始条目罗列（对齐 aipentest _fallback_markdown）。
func kbFallbackMarkdown(t kbTaskInfo, finds []kbFinding, facts, intents []string, err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s（模板降级版）\n\n> 注：LLM 蒸馏失败（%s），本总结由模板自动生成（仅原始统计），可在知识库页点「重新生成」。\n", t.Name, err)
	b.WriteString("\n## 执行概况\n")
	fmt.Fprintf(&b, "- task_id: `%d`  终态: %s\n", t.ID, t.Status)
	fmt.Fprintf(&b, "- 目标: %s\n", truncateStr(t.Descr, 300))
	if len(intents) > 0 {
		fmt.Fprintf(&b, "- 执行意图 %d 条\n", len(intents))
	}
	b.WriteString("\n## 漏洞与可复用手法\n")
	if len(finds) > 0 {
		for _, f := range finds {
			fmt.Fprintf(&b, "- **[%s/%s] %s** — 目标 `%s`，CVSS %.1f，PoC: %s\n",
				f.Severity, f.Vulnclass, f.Summary, f.Target, f.Cvss, truncateStr(f.Evidence, 120))
		}
	} else {
		b.WriteString("本次无 finding 入库。\n")
	}
	b.WriteString("\n## 经验教训\n")
	if len(facts) > 0 {
		for i, m := range facts {
			if i >= 30 {
				break
			}
			fmt.Fprintf(&b, "- %s\n", m)
		}
	} else {
		b.WriteString("本次无测试记忆。\n")
	}
	b.WriteString("\n## 下次建议\n\n- LLM 蒸馏失败，建议在知识库页点「重新生成」获取完整分析。\n")
	return b.String()
}

// ============ 检索索引（bigram BOW，对齐 aipentest rag.py 兜底通道思路） ============

const (
	kbChunkSize    = 600
	kbChunkOverlap = 80
	kbBowDim       = 1024
)

// chunkKBText 按段落聚合切块：优先整段进块，超长段硬切，相邻块重叠。
func chunkKBText(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var chunks []string
	var buf strings.Builder
	flush := func() {
		if strings.TrimSpace(buf.String()) != "" {
			chunks = append(chunks, strings.TrimSpace(buf.String()))
		}
		buf.Reset()
	}
	for _, p := range strings.Split(text, "\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for len([]rune(p)) > kbChunkSize {
			flush()
			r := []rune(p)
			chunks = append(chunks, string(r[:kbChunkSize]))
			p = string(r[kbChunkSize-kbChunkOverlap:])
		}
		if buf.Len()+len(p)+1 > kbChunkSize {
			flush()
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(p)
	}
	flush()
	// 合并过短尾块（<80 字符并入前块）
	merged := []string{}
	for _, c := range chunks {
		if len(merged) > 0 && len([]rune(c)) < 80 {
			merged[len(merged)-1] += "\n" + c
		} else {
			merged = append(merged, c)
		}
	}
	return merged
}

// kbBow 稀疏 bigram BOW：unicode 双字 → crc32 → 1024 维桶 → L2 归一化。
func kbBow(text string) map[int]float64 {
	r := []rune(strings.ToLower(text))
	if len(r) < 2 {
		if len(r) == 1 {
			return map[int]float64{int(crc32.ChecksumIEEE([]byte(string(r))) % kbBowDim): 1}
		}
		return nil
	}
	m := map[int]float64{}
	for i := 0; i+1 < len(r); i++ {
		dim := int(crc32.ChecksumIEEE([]byte(string(r[i : i+2]))) % kbBowDim)
		m[dim]++
	}
	var norm float64
	for _, v := range m {
		norm += v * v
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for k := range m {
			m[k] /= norm
		}
	}
	return m
}



// indexKBSummary 总结切块入 kb_chunks（重建式：先删旧块）。
func (s *Server) indexKBSummary(taskID int64, summaryMD string) {
	db := s.m.PG()
	if _, err := db.Exec("DELETE FROM kb_chunks WHERE task_id=$1", taskID); err != nil {
		return
	}
	for seq, chunk := range chunkKBText(summaryMD) {
		bow, _ := json.Marshal(kbBow(chunk))
		_, _ = db.Exec(`INSERT INTO kb_chunks (task_id, seq, text, bow) VALUES ($1,$2,$3,$4)
			ON CONFLICT (task_id, seq) DO UPDATE SET text=$3, bow=$4`, taskID, seq, chunk, string(bow))
	}
}

// KBSearchResult 一条检索命中。
type KBSearchResult struct {
	TaskID int64   `json:"task_id"`
	Title  string  `json:"title"`
	Score  float64 `json:"score"`
	Text   string  `json:"text"`
}

// kbSearchRetrieval 检索入口（agent 工具与 UI 共用）：bigram 余弦 + 词面 LIKE 加成。
func (s *Server) kbSearchRetrieval(query string, topK int) ([]KBSearchResult, int, error) {
	if strings.TrimSpace(query) == "" {
		return nil, 0, fmt.Errorf("query 为空")
	}
	if topK <= 0 || topK > 20 {
		topK = 5
	}
	rows, err := s.m.PG().Query(`
SELECT c.task_id, c.text, c.bow, COALESCE(k.title,'')
FROM kb_chunks c LEFT JOIN kb_summaries k ON k.task_id = c.task_id
ORDER BY c.id DESC LIMIT 4000`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	qBow := kbBow(query)
	qLower := strings.ToLower(query)
	var all []KBSearchResult
	total := 0
	for rows.Next() {
		var taskID int64
		var text, bowJSON string
		var title sql.NullString
		if err := rows.Scan(&taskID, &text, &bowJSON, &title); err != nil {
			continue
		}
		total++
		score := 0.0
		var bow map[int]float64
		if json.Unmarshal([]byte(bowJSON), &bow) == nil {
			for d, w := range qBow {
				if v, ok := bow[d]; ok {
					score += w * v
				}
			}
		}
		// 词面命中加成（标题/正文含查询词，粗粒度）
		if strings.Contains(strings.ToLower(text), qLower) || strings.Contains(strings.ToLower(title.String), qLower) {
			score += 0.15
		}
		if score > 0.01 {
			all = append(all, KBSearchResult{TaskID: taskID, Title: title.String, Score: score, Text: text})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	if len(all) > topK {
		all = all[:topK]
	}
	return all, total, nil
}
