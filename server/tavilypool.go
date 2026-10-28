package server

// tavilypool.go — Tavily 多 Key 号池（移植自哨兵 websearch 号池思想，适配 ARTEX 的
// 单 key SDK 边界）：池在选择层生效——每次取 key 时按 /usage 剩余额度选最优，
// 60s 缓存，坏 key（401/403）自动跳出本轮选择；SDK 内部的单次调用无法中途换 key
// （这是与哨兵的差异，文档如实记录）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type tavilyPoolKey struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

type tavilyPoolUsage struct {
	at        time.Time
	remaining float64 // -1 = 探测失败
	limit     float64 // -1 = 无上限
	dead      bool    // 401/403 等不可重试错误
}

func (s *Server) loadTavilyPool() []tavilyPoolKey {
	var pool []tavilyPoolKey
	if s.m.pg == nil {
		return nil
	}
	if v, ok, _ := s.m.pg.GetSetting("tavily_pool"); ok && v != "" {
		_ = json.Unmarshal([]byte(v), &pool)
	}
	return pool
}

func (s *Server) saveTavilyPool(pool []tavilyPoolKey) error {
	b, _ := json.Marshal(pool)
	return s.m.pg.SetSetting("tavily_pool", string(b))
}

// pickTavilyKey 余额最高优先（哨兵 pickKey 语义）；缓存 60s；失败 key 标 dead 跳出。
func (s *Server) pickTavilyKey() string {
	pool := s.loadTavilyPool()
	var usable []tavilyPoolKey
	for _, k := range pool {
		if k.Enabled && k.Key != "" {
			usable = append(usable, k)
		}
	}
	if len(usable) == 0 {
		return ""
	}
	s.tavilyMu.Lock()
	defer s.tavilyMu.Unlock()
	if s.tavilyUsage == nil {
		s.tavilyUsage = map[string]*tavilyPoolUsage{}
	}
	if time.Since(s.tavilyUsageAt) > 60*time.Second {
		s.refreshTavilyUsageLocked(usable)
	}
	type cand struct {
		key  string
		rem  float64
	}
	var cands []cand
	for _, k := range usable {
		u, ok := s.tavilyUsage[k.ID]
		if ok && u.dead {
			continue
		}
		rem := 1e18 // 无缓存按最大优先（新 key 未探测）
		if ok {
			rem = u.remaining
		}
		cands = append(cands, cand{k.Key, rem})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].rem > cands[j].rem })
	return cands[0].key
}

// refreshTavilyUsageLocked 并行探测各 key 的 /usage（8s 超时）。
func (s *Server) refreshTavilyUsageLocked(usable []tavilyPoolKey) {
	s.tavilyUsageAt = time.Now()
	var wg sync.WaitGroup
	for _, k := range usable {
		wg.Add(1)
		go func(id, key string) {
			defer wg.Done()
			u := s.probeTavilyUsage(key)
			s.tavilyMu.Lock()
			s.tavilyUsage[id] = u
			s.tavilyMu.Unlock()
		}(k.ID, k.Key)
	}
	wg.Wait()
}

func (s *Server) probeTavilyUsage(key string) *tavilyPoolUsage {
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.tavily.com/usage", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return &tavilyPoolUsage{at: time.Now(), remaining: -1}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &tavilyPoolUsage{at: time.Now(), remaining: -1, dead: true}
	}
	var raw struct {
		Key struct {
			Usage float64 `json:"usage"`
			Limit *float64 `json:"limit"`
		} `json:"key"`
		Account struct {
			PlanUsage float64 `json:"plan_usage"`
			PlanLimit *float64 `json:"plan_limit"`
		} `json:"account"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return &tavilyPoolUsage{at: time.Now(), remaining: -1}
	}
	rem := raw.Key.Limit
	if rem == nil {
		rem = raw.Account.PlanLimit
	}
	used := raw.Key.Usage
	if rem == nil {
		return &tavilyPoolUsage{at: time.Now(), remaining: 1e17, limit: -1}
	}
	return &tavilyPoolUsage{at: time.Now(), remaining: *rem - used, limit: *rem}
}

// ---------- API ----------

func (s *Server) registerTavilyPoolRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/websearch/pool", s.tavilyPoolGet)
	mux.HandleFunc("PUT /api/websearch/pool", s.tavilyPoolSet)
	mux.HandleFunc("POST /api/websearch/pool/test", s.tavilyPoolTest)
}

func (s *Server) tavilyPoolGet(w http.ResponseWriter, r *http.Request) {
	pool := s.loadTavilyPool()
	s.tavilyMu.Lock()
	defer s.tavilyMu.Unlock()
	out := []map[string]any{}
	for _, k := range pool {
		tail := ""
		if len(k.Key) >= 4 {
			tail = k.Key[len(k.Key)-4:]
		}
		item := map[string]any{"id": k.ID, "label": k.Label, "enabled": k.Enabled,
			"has_key": k.Key != "", "key_tail": tail}
		if u, ok := s.tavilyUsage[k.ID]; ok {
			item["usage"] = map[string]any{"remaining": u.remaining, "limit": u.limit, "dead": u.dead, "at": u.at}
		}
		out = append(out, item)
	}
	writeJSON(w, 200, map[string]any{"keys": out})
}

func (s *Server) tavilyPoolSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Keys []tavilyPoolKey `json:"keys"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求体无效")
		return
	}
	if len(body.Keys) > 20 {
		writeErr(w, 400, "号池最多 20 个 Key")
		return
	}
	for i := range body.Keys {
		if body.Keys[i].ID == "" {
			body.Keys[i].ID = fmt.Sprintf("tvk-%d", time.Now().UnixNano()%1e6+int64(i))
		}
	}
	if err := s.saveTavilyPool(body.Keys); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.tavilyMu.Lock()
	s.tavilyUsageAt = time.Time{} // 立即重探测
	s.tavilyMu.Unlock()
	s.tavilyPoolGet(w, r)
}

func (s *Server) tavilyPoolTest(w http.ResponseWriter, r *http.Request) {
	var body struct{ ID, Key string }
	_ = decode(r, &body)
	key := body.Key
	if key == "" {
		for _, k := range s.loadTavilyPool() {
			if k.ID == body.ID {
				key = k.Key
			}
		}
	}
	if key == "" {
		writeErr(w, 400, "key 必填（或 id 对应的 Key 已保存）")
		return
	}
	u := s.probeTavilyUsage(key)
	writeJSON(w, 200, map[string]any{"ok": !u.dead && u.remaining >= 0,
		"remaining": u.remaining, "limit": u.limit})
}
