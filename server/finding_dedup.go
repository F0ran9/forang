package server

// finding_dedup.go — 漏洞中台重复发现治理：
//   AI 在同一任务里常对同一漏洞多次 report_finding（实测任务 292 有 4 条同
//   RCE）。查重按「任务 + 漏洞类 + 主机路径特征」分组标记疑似重复（非破坏性，
//   人工确认后合并）；合并把证据子表/证据文本迁到主条目，重复条目置
//   status=duplicate（状态机已有该值），报告与统计即自动去重。
//
//   GET  /api/exploration/findings/duplicates  疑似重复分组
//   POST /api/exploration/findings/merge       合并 {primary_id, duplicate_ids}

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

var reURLHost = regexp.MustCompile(`(?i)https?://([A-Za-z0-9.\-]+(?::\d+)?)(/[A-Za-z0-9_\-./%]{0,80})?`)

// dedupKey 计算疑似重复的分组键：漏洞类 + 主机 + 首个 URL 路径段。
// 提不出主机时退化用归一化标题前缀。键相同 ≠ 一定重复 —— 只做「疑似」标记，
// 合并永远由人确认。
func dedupKey(f *db.DBFinding) string {
	class := strings.ToLower(strings.TrimSpace(f.VulnClass))
	text := f.Name + " " + f.Summary + " " + f.Evidence
	m := reURLHost.FindStringSubmatch(text)
	if m != nil {
		path := ""
		if len(m) > 2 {
			path = strings.TrimRight(strings.SplitN(m[2], "?", 2)[0], "/")
		}
		return class + "|" + strings.ToLower(m[1]) + "|" + path
	}
	norm := strings.ToLower(f.Name)
	norm = strings.Join(strings.Fields(norm), " ")
	if len(norm) > 48 {
		norm = norm[:48]
	}
	return class + "||" + norm
}

// dedupActionable 只对未收口的发现查重（已判重复/误报/修复等不再进组）。
func dedupActionable(status string) bool {
	switch status {
	case "", db.FindingPending, db.FindingInProgress, db.FindingConfirmed:
		return true
	}
	return false
}

var dedupSevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// findingDuplicates GET：返回疑似重复组（每组成员按严重度/时间排，组内 >=2 条）。
func (s *Server) findingDuplicates(w http.ResponseWriter, r *http.Request) {
	fs, err := s.m.pg.ListFindingsForExport(db.FindingFilter{}, nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	groups := map[string][]*db.DBFinding{}
	order := []string{}
	for _, f := range fs {
		if !dedupActionable(f.Status) {
			continue
		}
		k := dedupKey(f)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}
	out := []map[string]any{}
	for _, k := range order {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		sort.Slice(g, func(i, j int) bool {
			if dedupSevOrder[g[i].Severity] != dedupSevOrder[g[j].Severity] {
				return dedupSevOrder[g[i].Severity] < dedupSevOrder[g[j].Severity]
			}
			return g[i].CreatedAt.Before(g[j].CreatedAt)
		})
		ids := make([]int64, len(g))
		members := make([]map[string]any, len(g))
		for i, f := range g {
			ids[i] = f.ID
			// DBFinding 无小写 json tag，显式给前端轻量字段
			members[i] = map[string]any{
				"id": f.ID, "task_id": f.TaskID, "vulnclass": f.VulnClass,
				"name": f.Name, "severity": f.Severity, "summary": f.Summary,
				"status": f.Status, "created_at": f.CreatedAt.Format("01-02 15:04"),
			}
		}
		out = append(out, map[string]any{
			"key":      k,
			"count":    len(g),
			"members":  members,
			"member_ids": ids,
			// 主条目建议：最严重里最早的（合并目标是它）
			"suggested_primary": g[0].ID,
		})
	}
	// 组间排序：组内条数多、严重级高的在前
	sort.Slice(out, func(i, j int) bool {
		if out[i]["count"] != out[j]["count"] {
			return out[i]["count"].(int) > out[j]["count"].(int)
		}
		return out[i]["key"].(string) < out[j]["key"].(string)
	})
	writeJSON(w, 200, map[string]any{"data": out})
}

// mergeFindings POST：把重复条目并进主条目——证据子表迁移、证据文本追加、
// 重复条目置 status=duplicate。主条目 evidence_version+1 触发报告重新生成。
func (s *Server) mergeFindings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PrimaryID    int64   `json:"primary_id"`
		DuplicateIDs []int64 `json:"duplicate_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.PrimaryID <= 0 || len(b.DuplicateIDs) == 0 {
		writeErr(w, 400, "primary_id 与 duplicate_ids 必填")
		return
	}
	pg := s.m.pg
	primary, err := pg.GetFinding(b.PrimaryID)
	if err != nil || primary == nil {
		writeErr(w, 404, "主条目不存在")
		return
	}
	merged, skipped := []string{}, []string{}
	for _, id := range b.DuplicateIDs {
		if id == b.PrimaryID {
			continue
		}
		dup, err := pg.GetFinding(id)
		if err != nil || dup == nil {
			skipped = append(skipped, fmt.Sprintf("#%d 不存在", id))
			continue
		}
		// 1) 证据子表迁移（截图/命令输出随主条目进报告）
		evs, err := s.ListFindingEvidence(id)
		if err == nil {
			for _, e := range evs {
				_ = s.AppendFindingEvidence(b.PrimaryID, e)
			}
		}
		// 2) 证据文本追加（去重：主条目已含则跳过）
		if dup.Evidence != "" && !strings.Contains(primary.Evidence, truncateStr(dup.Evidence, 120)) {
			if _, err := pg.Exec(`UPDATE findings SET evidence = evidence || $1 WHERE id=$2`,
				"\n\n--- 合并自重复发现 #"+fmt.Sprint(id)+" ---\n"+dup.Evidence, b.PrimaryID); err != nil {
				skipped = append(skipped, fmt.Sprintf("#%d 证据追加失败", id))
				continue
			}
		}
		// 3) 重复条目置 duplicate，摘要在备注里保留出处
		if _, err := pg.Exec(`UPDATE findings SET status=$1, summary = summary || $2 WHERE id=$3`,
			db.FindingDuplicate, fmt.Sprintf("（合并至 #%d）", b.PrimaryID), id); err != nil {
			skipped = append(skipped, fmt.Sprintf("#%d 状态更新失败", id))
			continue
		}
		merged = append(merged, fmt.Sprintf("#%d", id))
	}
	if len(merged) > 0 {
		_, _ = pg.Exec(`UPDATE findings SET evidence_version = evidence_version + 1 WHERE id=$1`, b.PrimaryID)
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"merged": merged, "skipped": skipped,
		"message": fmt.Sprintf("已合并 %d 条到 #%d（重复条目置为「重复」）", len(merged), b.PrimaryID),
		"at":      time.Now().Format("2006-01-02 15:04:05"),
	}})
}
