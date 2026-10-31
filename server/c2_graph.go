package server

// c2_graph.go — C2 攻击链路图 + AI 驱动（参考 oktos GoalManagement + FORANG 探索图）：
//   节点=beacon/cmd/asset/cred/lateral/ai_insight，边=executed/discovered/moved/escalated
//   GET  /api/tools/c2/graph?session_id=     图数据（nodes+edges 树结构）
//   POST /api/tools/c2/graph/node            添加节点（AI 或手动）
//   POST /api/tools/c2/graph/edge            添加边
//   DELETE /api/tools/c2/graph/{session_id}  清图
//   POST /api/tools/c2/ai                    AI 驱动：自然语言 → 规划 → 执行 → 建节点
//   GET  /api/tools/c2/ai/suggestions        AI 建议下一步（基于图上下文）

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ensureC2GraphTables 幂等建表（在 schema.sql 之外兜底）。
func (s *Server) ensureC2GraphTables() {
	_, _ = s.m.PG().Exec(`CREATE TABLE IF NOT EXISTS c2_graph_nodes (
		id BIGSERIAL PRIMARY KEY,
		session_id TEXT NOT NULL DEFAULT '',
		parent_id BIGINT,
		node_type TEXT NOT NULL DEFAULT 'cmd',
		label TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'done',
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	_, _ = s.m.PG().Exec(`CREATE TABLE IF NOT EXISTS c2_graph_edges (
		id BIGSERIAL PRIMARY KEY,
		session_id TEXT NOT NULL DEFAULT '',
		from_node BIGINT NOT NULL,
		to_node BIGINT NOT NULL,
		edge_type TEXT NOT NULL DEFAULT 'executed'
	)`)
}

// C2GraphNode 图节点。
type C2GraphNode struct {
	ID        int64           `json:"id"`
	SessionID string          `json:"session_id"`
	ParentID  *int64          `json:"parent_id"`
	Type      string          `json:"node_type"`
	Label     string          `json:"label"`
	Detail    string          `json:"detail"`
	Status    string          `json:"status"`
	CreatedAt string          `json:"created_at"`
	Children  []*C2GraphNode  `json:"children,omitempty"`
}

// GET /api/tools/c2/graph?session_id= — 图数据（树结构 + 平铺边）。
func (s *Server) c2GraphGet(w http.ResponseWriter, r *http.Request) {
	s.ensureC2GraphTables()
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	// 读全部节点
	rows, err := s.m.PG().Query(`SELECT id, session_id, parent_id, node_type, label, detail, status, created_at
		FROM c2_graph_nodes WHERE session_id=$1 ORDER BY id`, sid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	nodeMap := map[int64]*C2GraphNode{}
	var roots []*C2GraphNode
	for rows.Next() {
		n := &C2GraphNode{}
		var pid sql.NullInt64
		var ts sql.NullTime
		if err := rows.Scan(&n.ID, &n.SessionID, &pid, &n.Type, &n.Label, &n.Detail, &n.Status, &ts); err != nil {
			continue
		}
		if pid.Valid {
			v := pid.Int64
			n.ParentID = &v
		}
		if ts.Valid {
			n.CreatedAt = ts.Time.Format("15:04:05")
		}
		nodeMap[n.ID] = n
		if n.ParentID == nil {
			roots = append(roots, n)
		}
	}
	// 组装树
	for _, n := range nodeMap {
		if n.ParentID != nil {
			if p, ok := nodeMap[*n.ParentID]; ok {
				p.Children = append(p.Children, n)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"data": roots})
}

// POST /api/tools/c2/graph/node — 添加节点（返回 id）。
func (s *Server) c2GraphNodeAdd(w http.ResponseWriter, r *http.Request) {
	s.ensureC2GraphTables()
	var b struct {
		SessionID string `json:"session_id"`
		ParentID  *int64 `json:"parent_id"`
		Type      string `json:"node_type"`
		Label     string `json:"label"`
		Detail    string `json:"detail"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	if b.Type == "" {
		b.Type = "cmd"
	}
	if b.Status == "" {
		b.Status = "done"
	}
	var id int64
	err := s.m.PG().QueryRow(`INSERT INTO c2_graph_nodes (session_id, parent_id, node_type, label, detail, status)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		b.SessionID, b.ParentID, b.Type, truncateStr(b.Label, 200), truncateStr(b.Detail, 4000), b.Status).Scan(&id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"id": id}})
}

// POST /api/tools/c2/graph/edge — 添加边。
func (s *Server) c2GraphEdgeAdd(w http.ResponseWriter, r *http.Request) {
	s.ensureC2GraphTables()
	var b struct {
		SessionID string `json:"session_id"`
		FromNode  int64  `json:"from_node"`
		ToNode    int64  `json:"to_node"`
		EdgeType  string `json:"edge_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if b.EdgeType == "" {
		b.EdgeType = "executed"
	}
	_, err := s.m.PG().Exec(`INSERT INTO c2_graph_edges (session_id, from_node, to_node, edge_type)
		VALUES ($1,$2,$3,$4)`, b.SessionID, b.FromNode, b.ToNode, b.EdgeType)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/tools/c2/graph/{session_id} — 清图。
func (s *Server) c2GraphClear(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("session_id")
	if sid == "" {
		writeErr(w, 400, "bad session_id")
		return
	}
	_, _ = s.m.PG().Exec("DELETE FROM c2_graph_edges WHERE session_id=$1", sid)
	_, _ = s.m.PG().Exec("DELETE FROM c2_graph_nodes WHERE session_id=$1", sid)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- AI 驱动 ----

// c2AISystemPrompt AI 驱动 C2 的系统提示词。
const c2AISystemPrompt = `你是 C2 后渗透 AI 指挥官。根据当前攻击链路图上下文和用户指令，规划下一步行动。

规则：
1. 输出严格的 JSON 数组，每个元素是一条要执行的命令及其图节点信息：
[{"cmd":"要执行的命令","label":"简短标签","type":"cmd|asset|cred|lateral|ai_insight","reason":"为什么执行这条"}]
2. 最多 3 条命令（保守执行，不要一次全跑）
3. 基于已有图节点（避免重复执行同样的侦察）
4. 标签用中文，命令用英文
5. 如果用户问的是分析性问题（不是要执行命令），输出空数组 []

只输出 JSON，不要代码围栏、不要解释文本。`

// POST /api/tools/c2/ai — AI 驱动：自然语言指令 → 规划 → 执行 → 建图节点。
func (s *Server) c2AIDrive(w http.ResponseWriter, r *http.Request) {
	s.ensureC2GraphTables()
	var b struct {
		SessionID string `json:"session_id"`
		Instruction string `json:"instruction"` // 自然语言指令
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" || b.Instruction == "" {
		writeErr(w, 400, "session_id 与 instruction 必填")
		return
	}

	// AI 规划（注入知识库经验 + 图上下文）
	plan, err := s.c2AIPlanWithKB(b.SessionID, b.Instruction)
	if err != nil {
		writeErr(w, 502, "AI 规划失败: "+err.Error())
		return
	}

	// 3) 执行并建节点
	type planItem struct {
		Cmd    string `json:"cmd"`
		Label  string `json:"label"`
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	var items []planItem
	if err := json.Unmarshal([]byte(plan), &items); err != nil {
		// AI 输出不是 JSON——原样返回（分析性问题）
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ai_reply": plan, "executed": 0}})
		return
	}

	// 找根节点（beacon 节点）或创建
	rootID := s.c2GetOrCreateRoot(b.SessionID)

	type execResult struct {
		NodeID  int64  `json:"node_id"`
		Cmd     string `json:"cmd"`
		Label   string `json:"label"`
		Output  string `json:"output"`
		Reason  string `json:"reason"`
		OK      bool   `json:"ok"`
	}
	results := []execResult{}

	for _, item := range items {
		if item.Cmd == "" {
			continue
		}
		// 建节点（pending）
		var nodeID int64
		s.m.PG().QueryRow(`INSERT INTO c2_graph_nodes (session_id, parent_id, node_type, label, detail, status)
			VALUES ($1,$2,$3,$4,'','running') RETURNING id`,
			b.SessionID, &rootID, item.Type, item.Label).Scan(&nodeID)

		// 执行
		output, err := s.c2ExecAndWait(r, b.SessionID, item.Cmd)

		// 更新节点
		status := "done"
		out := truncateStr(output, 4000)
		if err != nil {
			status = "failed"
			out = err.Error()
		}
		_, _ = s.m.PG().Exec("UPDATE c2_graph_nodes SET detail=$1, status=$2 WHERE id=$3",
			out, status, nodeID)

		results = append(results, execResult{NodeID: nodeID, Cmd: item.Cmd, Label: item.Label, Output: out, Reason: item.Reason, OK: err == nil})
		s.c2Audit(b.SessionID, "", "ai_exec", fmt.Sprintf("%s → %s", item.Label, item.Cmd))
		// AI 分析输出 → 自动识别安全问题 → 提交漏洞中台
		go s.c2AnalyzeAndReport(context.Background(), b.SessionID, "", item.Cmd, out)
	}

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"plan": items, "executed": len(results), "results": results,
	}})
}

// c2GraphContext 获取图上下文摘要（已有节点列表，供 AI 决策）。
func (s *Server) c2GraphContext(sessionID string) string {
	rows, err := s.m.PG().Query(`SELECT node_type, label, status, COALESCE(detail,'')
		FROM c2_graph_nodes WHERE session_id=$1 ORDER BY id DESC LIMIT 20`, sessionID)
	if err != nil {
		return "（空图）"
	}
	defer rows.Close()
	var sb strings.Builder
	sb.WriteString("已有攻击链路节点（最新 20 条）：\n")
	for rows.Next() {
		var t, l, st, d string
		if rows.Scan(&t, &l, &st, &d) == nil {
			sb.WriteString(fmt.Sprintf("- [%s/%s] %s: %s\n", t, st, l, truncateStr(d, 100)))
		}
	}
	if sb.Len() < 30 {
		sb.WriteString("（尚无节点——初始阶段）")
	}
	return sb.String()
}

// c2AIPlan 调 LLM 规划命令。
func (s *Server) c2AIPlan(graphCtx, instruction string) (string, error) {
	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, ok := s.providerForProfile(profileID)
	if !ok {
		return "", fmt.Errorf("LLM 不可用")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	userPrompt := fmt.Sprintf("当前图上下文：\n%s\n\n用户指令：%s\n\n请规划要执行的命令：", graphCtx, instruction)
	return streamCollectText(ctx, prov, c2AISystemPrompt, userPrompt)
}



// c2GetOrCreateRoot 获取或创建 beacon 根节点。
func (s *Server) c2GetOrCreateRoot(sessionID string) int64 {
	var id int64
	err := s.m.PG().QueryRow(`SELECT id FROM c2_graph_nodes WHERE session_id=$1 AND node_type='beacon' LIMIT 1`, sessionID).Scan(&id)
	if err == nil {
		return id
	}
	s.m.PG().QueryRow(`INSERT INTO c2_graph_nodes (session_id, node_type, label, detail, status)
		VALUES ($1,'beacon','Beacon 会话','初始接入点','done') RETURNING id`, sessionID).Scan(&id)
	return id
}

// GET /api/tools/c2/ai/suggestions?session_id= — AI 建议下一步。
func (s *Server) c2AISuggest(w http.ResponseWriter, r *http.Request) {
	s.ensureC2GraphTables()
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	ctxText := s.c2GraphContext(sid)
	prompt := fmt.Sprintf("%s\n\n请建议 3 条最有价值的下一步命令（格式同规则）：", ctxText)
	result, err := s.c2AIPlan(ctxText, prompt)
	if err != nil {
		writeErr(w, 502, "AI 失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"suggestions": result}})
}
