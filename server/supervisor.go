package server

// supervisor.go — LLM 监督员（升级版，对齐全链哨兵 v2.1 监督模式设计）。
// 相比初版的升级（哨兵 supervisor.ts/supervisor-prompt.ts/supervisor-digest.ts，MIT）：
//   1. 滚动状态：每任务维护 {phase, tested[], excluded[]}，模型的建议(episode)由代码
//      合并进状态——"已排除/已测过"跨批次持久，不会悄悄消失；
//   2. digest：工具结果只给 head/tail 摘录 + 短哈希，先脱敏（Bearer/token/authorization/
//      URL 凭据），大输出不进监督上下文；
//   3. 策略：操作员可选 steady/validation/offensive/stealth/guarded，指导语注入 prompt；
//   4. 阶段：recon→enum→vuln_mapping→exploitation→post→report，模型判当前阶段。
// 落地方式不变：观察活动流→节流→LLM→写 worker=supervisor 活动 + NotifyHint 注入 planner。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
)

// ---------- 配置 ----------

type SupervisorConfig struct {
	Enabled     bool   `json:"enabled"`
	ProfileID   int64  `json:"profile_id"`
	IntervalSec int    `json:"interval_sec"`
	MinActions  int    `json:"min_actions"`
	MaxEvents   int    `json:"max_events"`
	Strategy    string `json:"strategy"` // steady/validation/offensive/stealth/guarded
}

func defaultSupervisorConfig() SupervisorConfig {
	return SupervisorConfig{Enabled: false, ProfileID: 0, IntervalSec: 120, MinActions: 8, MaxEvents: 40, Strategy: "steady"}
}

var supervisorStrategies = map[string]string{
	"steady":     "稳健交付：优先确认授权边界和环境影响；建议以可复现、低影响步骤为主；发现越界、生产写入、破坏性动作立即指出。",
	"validation": "漏洞验证：围绕已发现漏洞做可复现验证，区分误报；建议补 PoC、对照请求、最小影响证明；避免无目的换目标。",
	"offensive":  "红队推进：关注下一跳、权限提升、横向和可利用路径；仍必须遵守授权与安全规则，不得建议越界或破坏性动作。",
	"stealth":    "低噪声：避免高频爆破、批量请求和明显扫描；建议被动信息、低速、小样本验证。",
	"guarded":    "避危险接口：不允许测试或建议测试会修改系统运行、业务数据/配置的接口，也不允许测试密码重置/账号接管/文件删除等不可逆动作；发现只记录风险并建议人工确认，改用只读或可回滚验证；主 Agent 正在调用这类接口时立即要求停止。",
}

func (c *SupervisorConfig) clamp() {
	if c.IntervalSec < 30 {
		c.IntervalSec = 30
	}
	if c.IntervalSec > 3600 {
		c.IntervalSec = 3600
	}
	if c.MinActions < 3 {
		c.MinActions = 3
	}
	if c.MinActions > 100 {
		c.MinActions = 100
	}
	if c.MaxEvents < 10 {
		c.MaxEvents = 10
	}
	if c.MaxEvents > 120 {
		c.MaxEvents = 120
	}
	if _, ok := supervisorStrategies[c.Strategy]; !ok {
		c.Strategy = "steady"
	}
	if c.ProfileID < 0 {
		c.ProfileID = 0
	}
}

// ---------- 任务状态 ----------

type supervisorTask struct {
	events    []db.Activity
	lastRun   time.Time
	sinceLast int
	running   bool
	// 滚动状态（哨兵 episode-merge 语义：由代码合并，模型不整体改写历史）
	phase    string   // recon/enum/vuln_mapping/exploitation/post/report
	tested   []string // 已测试结论（并集去重，上限 20）
	excluded []string // 已排除项（并集去重，上限 20）
}

type Supervisor struct {
	m     *Manager
	eng   *Engine
	srv   *Server
	mu    sync.Mutex
	cfg   SupervisorConfig
	tasks map[string]*supervisorTask
	order []string
}

const supervisorMaxTrackedTasks = 32

func NewSupervisor(m *Manager, eng *Engine) *Supervisor {
	sv := &Supervisor{m: m, eng: eng, tasks: map[string]*supervisorTask{}}
	sv.cfg = sv.loadConfig()
	return sv
}

func (sv *Supervisor) loadConfig() SupervisorConfig {
	cfg := defaultSupervisorConfig()
	if sv.m.pg == nil {
		return cfg
	}
	if v, ok, err := sv.m.pg.GetSetting("supervisor.enabled"); err == nil && ok {
		cfg.Enabled = v == "true" || v == "1"
	}
	if v, ok, err := sv.m.pg.GetSetting("supervisor.profile_id"); err == nil && ok {
		var id int64
		if _, err := fmt.Sscanf(v, "%d", &id); err == nil {
			cfg.ProfileID = id
		}
	}
	loadInt := func(key string, dst *int) {
		if v, ok, err := sv.m.pg.GetSetting(key); err == nil && ok {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				*dst = n
			}
		}
	}
	loadInt("supervisor.interval_sec", &cfg.IntervalSec)
	loadInt("supervisor.min_actions", &cfg.MinActions)
	loadInt("supervisor.max_events", &cfg.MaxEvents)
	if v, ok, _ := sv.m.pg.GetSetting("supervisor.strategy"); ok {
		cfg.Strategy = v
	}
	cfg.clamp()
	return cfg
}

func (sv *Supervisor) GetConfig() SupervisorConfig {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	return sv.cfg
}

func (sv *Supervisor) SetConfig(cfg SupervisorConfig) error {
	cfg.clamp()
	sv.mu.Lock()
	sv.cfg = cfg
	sv.mu.Unlock()
	if sv.m.pg == nil {
		return fmt.Errorf("数据库不可用，配置未持久化")
	}
	w := func(key, val string) {
		if err := sv.m.pg.SetSetting(key, val); err != nil {
			log.Printf("[supervisor] 写设置 %s 失败: %v", key, err)
		}
	}
	w("supervisor.enabled", boolStr(cfg.Enabled))
	w("supervisor.profile_id", fmt.Sprintf("%d", cfg.ProfileID))
	w("supervisor.interval_sec", fmt.Sprintf("%d", cfg.IntervalSec))
	w("supervisor.min_actions", fmt.Sprintf("%d", cfg.MinActions))
	w("supervisor.max_events", fmt.Sprintf("%d", cfg.MaxEvents))
	w("supervisor.strategy", cfg.Strategy)
	return nil
}

// ---------- 观察 ----------

func (sv *Supervisor) Observe(t *Task, r db.Activity) {
	if r.Kind != "tool_use" && r.Kind != "tool_result" && r.Kind != "text" {
		return
	}
	sv.mu.Lock()
	cfg := sv.cfg
	if !cfg.Enabled {
		sv.mu.Unlock()
		return
	}
	e, ok := sv.tasks[t.ID]
	if !ok {
		e = &supervisorTask{}
		sv.tasks[t.ID] = e
		sv.order = append(sv.order, t.ID)
		if len(sv.order) > supervisorMaxTrackedTasks {
			for _, old := range sv.order[:len(sv.order)-supervisorMaxTrackedTasks] {
				delete(sv.tasks, old)
			}
			sv.order = sv.order[len(sv.order)-supervisorMaxTrackedTasks:]
		}
	}
	e.events = append(e.events, r)
	if len(e.events) > cfg.MaxEvents {
		e.events = e.events[len(e.events)-cfg.MaxEvents:]
	}
	if r.Kind == "tool_result" {
		e.sinceLast++
	}
	due := !e.running && e.sinceLast >= cfg.MinActions &&
		time.Since(e.lastRun) >= time.Duration(cfg.IntervalSec)*time.Second
	if due {
		e.running = true
		e.sinceLast = 0
		e.lastRun = time.Now()
		events := make([]db.Activity, len(e.events))
		copy(events, e.events)
		state := *e
		sv.mu.Unlock()
		go sv.analyze(t.ID, events, state, cfg)
		return
	}
	sv.mu.Unlock()
}

// ---------- digest（哨兵 supervisor-digest：脱敏 + head/tail + 短哈希） ----------

var supervisorSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`(?i)((?:authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s"',;]+)`),
	regexp.MustCompile(`(?i)\b(https?://)([^/\s:@]+):([^@\s/]+)@`),
}

func supervisorRedact(s string) string {
	for _, re := range supervisorSecretPatterns {
		if re.NumSubexp() > 0 {
			s = re.ReplaceAllString(s, "${1}[REDACTED]")
		} else {
			s = re.ReplaceAllString(s, "[REDACTED]")
		}
	}
	return s
}

func supervisorDigestSummary(s string) string {
	s = supervisorRedact(strings.TrimSpace(s))
	r := []rune(s)
	const head, tail = 600, 400
	if len(r) <= head+tail+50 {
		return s
	}
	h := sha256.Sum256([]byte(s))
	return string(r[:head]) + "\n…[中间省略 sha256:" + hex.EncodeToString(h[:])[:10] + "]…\n" + string(r[len(r)-tail:])
}

// ---------- 分析 ----------

type supervisorEpisode struct {
	Phase       string   `json:"phase"`
	Assessment  string   `json:"assessment"`
	Avoid       []string `json:"avoid"`
	Next        []string `json:"next"`
	Excluded    []string `json:"excluded"`
	Tested      []string `json:"tested"`
}

const supervisorSystemPrompt = `你是授权渗透测试的监督观察员。你不执行任何工具，也不向操作员发指令；你只根据调用记录和结果摘要，判断这个 Agent 刚才在做什么、有没有进展、下一步该换什么策略。

【输入】
- 目标/当前阶段/滚动状态（已测过的结论、已排除的方向——这些由系统维护，你只返回增量）
- 最近一批工具调用（工具名 + 参数摘要 + 结果 digest：结果可能被脱敏/截断，这是有意为之）

【任务】
1. 判断当前阶段（recon/enum/vuln_mapping/exploitation/post/report 六选一）
2. 判断是否：空转、重复测试同一目标/接口、陷入无产出死胡同、偏离授权范围
3. 给出增量结论：
   - avoid：指出重复/无效动作及原因（如「已对 /api/login 连测 3 次同一 payload」）
   - next：具体可执行的下一步（换攻击面/换接口/换 payload/深入线索）
   - excluded：本轮可明确排除的方向（模型只报增量，系统负责并集）
   - tested：本轮新确认已测试有效的结论
4. 滚动状态里的 excluded/tested 是已确认的事实：如果主 Agent 正在重做已排除的事，在 avoid 里点名制止
5. 进展健康、方向正确时：avoid/next/excluded/tested 全部给空数组，assessment 照常一句话

【纪律】
- 只依据 digest 判断，digest 截断的部分不要脑补
- 每个建议必须指向输入里出现过的具体目标/接口/动作，不写泛泛的「加强信息收集」
- 不建议任何越权范围外或破坏性动作

【输出】
严格输出一个 JSON 对象（不要 markdown 代码块、不要多余文字）：
{"phase":"...","assessment":"一句话判断","avoid":["..."],"next":["..."],"excluded":["..."],"tested":["..."]}`

func (sv *Supervisor) analyze(taskID string, events []db.Activity, state supervisorTask, cfg SupervisorConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[supervisor] task %s analyze panic: %v\n%s", taskID, r, debug.Stack())
		}
	}()
	defer func() {
		sv.mu.Lock()
		if e, ok := sv.tasks[taskID]; ok {
			e.running = false
		}
		sv.mu.Unlock()
	}()
	t, ok := sv.m.Task(taskID)
	if !ok || sv.eng == nil || sv.srv == nil {
		return
	}
	profileID := cfg.ProfileID
	if profileID == 0 {
		if sv.m.pg == nil {
			return
		}
		if p, err := sv.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, pok := sv.srv.providerForProfile(profileID)
	if !pok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ctx = llmrec.WithWorker(ctx, supervisorLaneV2)
	text, err := streamCollectText(ctx, prov, supervisorSystemPrompt, renderSupervisorInput(events, state, cfg))
	if err != nil {
		log.Printf("[supervisor] task %s: LLM 失败: %v", taskID, err)
		return
	}
	ep, perr := parseSupervisorEpisode(text)
	if perr != nil {
		log.Printf("[supervisor] task %s: 解析失败: %v", taskID, perr)
		return
	}
	// episode 由代码合并进滚动状态（哨兵语义：模型不改写历史，只报增量）
	sv.mu.Lock()
	if e, ok := sv.tasks[taskID]; ok {
		if ep.Phase != "" {
			e.phase = ep.Phase
		}
		e.tested = mergeCap(e.tested, ep.Tested, 20)
		e.excluded = mergeCap(e.excluded, ep.Excluded, 20)
	}
	sv.mu.Unlock()

	if len(ep.Avoid) == 0 && len(ep.Next) == 0 {
		log.Printf("[supervisor] task %s: %s（无干预建议）", taskID, ep.Assessment)
		return
	}
	note := renderSupervisorNote(ep)
	sv.eng.emitActivity(t, db.Activity{Worker: "supervisor", Kind: "text", Summary: note, Detail: note})
	var hints []string
	for _, a := range ep.Avoid {
		hints = append(hints, "[监督] 不要重复："+a)
	}
	for _, n := range ep.Next {
		hints = append(hints, "[监督] 建议下一步："+n)
	}
	for _, ex := range ep.Excluded {
		hints = append(hints, "[监督] 已排除："+ex)
	}
	if len(hints) > 0 {
		t.NotifyHint(hints)
	}
	log.Printf("[supervisor] task %s: 注入 %d 条建议 (phase=%s): %s", taskID, len(hints), ep.Phase, ep.Assessment)
}

const supervisorLaneV2 = "supervisor"

func mergeCap(base, add []string, cap int) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, base...), add...) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) > cap {
		out = out[len(out)-cap:]
	}
	return out
}

func renderSupervisorInput(events []db.Activity, state supervisorTask, cfg SupervisorConfig) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "策略：%s\n阶段：%s\n", cfg.Strategy, orDefault(state.phase, "unknown"))
	if guidance, ok := supervisorStrategies[cfg.Strategy]; ok {
		fmt.Fprintf(&sb, "策略要求：%s\n", guidance)
	}
	if len(state.tested) > 0 {
		sb.WriteString("已测过的结论（不要建议重做）：\n- " + strings.Join(state.tested, "\n- ") + "\n")
	}
	if len(state.excluded) > 0 {
		sb.WriteString("已排除的方向（主 Agent 重做时要点名制止）：\n- " + strings.Join(state.excluded, "\n- ") + "\n")
	}
	sb.WriteString("\n最近动作（从旧到新，结果已脱敏/截断）：\n")
	for i, r := range events {
		fmt.Fprintf(&sb, "%d. [%s/%s] %s\n", i+1, r.Worker, r.Kind,
			supervisorDigestSummary(r.Tool+": "+strings.ReplaceAll(r.Summary, "\n", " ")))
	}
	return sb.String()
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func renderSupervisorNote(ep supervisorEpisode) string {
	var sb strings.Builder
	sb.WriteString("🧭 监督建议（非操作员指令，仅供参考调整方向）\n")
	fmt.Fprintf(&sb, "阶段：%s · 判断：%s\n", orDefault(ep.Phase, "-"), ep.Assessment)
	for _, list := range []struct{ title string; items []string }{
		{"不要重复", ep.Avoid}, {"建议下一步", ep.Next}, {"已排除", ep.Excluded},
	} {
		if len(list.items) > 0 {
			sb.WriteString(list.title + "：\n")
			for _, s := range list.items {
				sb.WriteString("- " + s + "\n")
			}
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func parseSupervisorEpisode(text string) (supervisorEpisode, error) {
	var ep supervisorEpisode
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	if err := json.Unmarshal([]byte(s), &ep); err != nil {
		return ep, err
	}
	if strings.TrimSpace(ep.Assessment) == "" && len(ep.Avoid) == 0 && len(ep.Next) == 0 {
		return ep, fmt.Errorf("内容为空")
	}
	switch ep.Phase {
	case "recon", "enum", "vuln_mapping", "exploitation", "post", "report":
	default:
		ep.Phase = ""
	}
	return ep, nil
}

// ---------- HTTP ----------

type supervisorConfigPayload struct {
	SupervisorConfig
	Profiles  []supervisorProfileOpt `json:"profiles"`
	Strategies map[string]string      `json:"strategies"`
}

type supervisorProfileOpt struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (s *Server) supervisorGetConfig(w http.ResponseWriter, r *http.Request) {
	payload := supervisorConfigPayload{SupervisorConfig: s.supervisor.GetConfig(), Strategies: supervisorStrategies}
	if s.m.pg != nil {
		if ps, err := s.m.pg.ListProfiles(); err == nil {
			for _, p := range ps {
				payload.Profiles = append(payload.Profiles, supervisorProfileOpt{ID: p.ID, Name: p.Name})
			}
		}
	}
	writeJSON(w, 200, payload)
}

func (s *Server) supervisorSetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg SupervisorConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求体无效: " + err.Error()})
		return
	}
	if err := s.supervisor.SetConfig(cfg); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, s.supervisor.GetConfig())
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
