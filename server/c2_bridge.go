package server

// c2_bridge.go — C2 ↔ FORANG 核心系统桥接：
//   1) AI 分析 C2 命令输出 → 自动识别安全问题 → 提交漏洞中台（findings）
//   2) AI 规划时查询知识库（kb_search）→ 注入过往经验 → 避免重复侦察

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---- 1) AI 发现分析器 ----

// c2FindingPrompt AI 分析命令输出提取安全发现。
const c2FindingPrompt = `你是安全分析师。分析以下渗透测试命令输出，识别值得记录的安全发现。

规则：
1. 只输出 JSON 数组，每个元素是一条安全发现：
[{"title":"发现标题","severity":"critical|high|medium|low","class":"漏洞类别","description":"描述","evidence":"关键证据（命令输出片段）"}]
2. 严重度判定：凭据泄露/远程代码执行/提权成功 = critical；未授权访问/敏感信息暴露 = high；配置弱点 = medium；信息泄露 = low
3. 只报告有实际证据的发现（输出中有明确凭据/路径/配置等），不要推测
4. 最多 3 条
5. 如果输出中没有安全问题，输出 []

只输出 JSON，不要代码围栏。`

// C2Finding AI 提取的发现。
type C2Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Class       string `json:"class"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

// c2AnalyzeAndReport AI 分析输出 → 发现 → 提交漏洞中台。
func (s *Server) c2AnalyzeAndReport(ctx context.Context, sessionID, hostname, cmd, output string) {
	if strings.TrimSpace(output) == "" {
		return
	}
	// LLM 分析
	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, ok := s.providerForProfile(profileID)
	if !ok {
		return
	}
	llmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prompt := fmt.Sprintf("主机: %s\n命令: %s\n输出:\n%s\n\n请分析并提取安全发现：", hostname, cmd, truncateStr(output, 3000))
	raw, err := streamCollectText(llmCtx, prov, c2FindingPrompt, prompt)
	if err != nil {
		return
	}
	// 剥代码围栏
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "["); i >= 0 {
		if j := strings.LastIndex(raw, "]"); j > i {
			raw = raw[i : j+1]
		}
	}
	var findings []C2Finding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil || len(findings) == 0 {
		return
	}
	// 提交到漏洞中台（findings 表）
	for _, f := range findings {
		if f.Title == "" {
			continue
		}
		if f.Severity == "" {
			f.Severity = "low"
		}
		if f.Class == "" {
			f.Class = "C2发现"
		}
		_, _ = s.m.PG().Exec(`INSERT INTO findings (task_id, vulnclass, name, severity, summary, evidence)
			VALUES (0, $1, $2, $3, $4, $5)`,
			f.Class, f.Title, f.Severity,
			truncateStr(fmt.Sprintf("C2 会话 %s (%s)：%s\n\n命令：%s\n证据：%s",
				sessionID[:12], hostname, f.Description, cmd, truncateStr(f.Evidence, 500)), 2000),
			truncateStr(f.Evidence, 2000))
		s.c2Audit(sessionID, hostname, "auto_finding", fmt.Sprintf("[%s] %s", f.Severity, f.Title))
	}
}

// ---- 2) 知识库联动 ----

// c2AIPlanWithKB 增强版 AI 规划：注入知识库经验。
func (s *Server) c2AIPlanWithKB(sessionID, instruction string) (string, error) {
	// 获取图上下文
	graphCtx := s.c2GraphContext(sessionID)

	// 查知识库（带缓存，5 分钟 TTL）
	kbCtx := s.c2KBSearchCached(instruction)

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

	// 规划缓存（同类指令 2 分钟内复用）
	cacheKey := fmt.Sprintf("%s|%s", sessionID, instruction)
	planCacheMu.RLock()
	if entry, ok := planCache[cacheKey]; ok && time.Now().Before(entry.expires) {
		planCacheMu.RUnlock()
		return entry.plan, nil
	}
	planCacheMu.RUnlock()

	userPrompt := fmt.Sprintf(`当前图上下文：
%s

%s

用户指令：%s

请规划要执行的命令（参考知识库经验，避免重复已有节点的侦察）：`, graphCtx, kbCtx, instruction)
	result, err := streamCollectText(ctx, prov, c2AISystemPrompt, userPrompt)
	if err == nil {
		planCacheMu.Lock()
		planCache[cacheKey] = planCacheEntry{plan: result, expires: time.Now().Add(planCacheTTL)}
		planCacheMu.Unlock()
	}
	return result, err
}

// ---- 3) Webshell 密码加密 ----

// wsEncryptPassword AES-GCM 加密 webshell 密码（服务端密钥派生自 PG DSN）。
func (s *Server) wsEncryptPassword(plain string) string {
	if plain == "" {
		return ""
	}
	// 简单方案：base64(plain XOR server_key) —— 服务端 key 从全局密钥派生
	// 生产环境建议 AES-GCM + 独立密钥管理
	key := s.wsServerKey()
	b := []byte(plain)
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ key[i%len(key)]
	}
	return "enc:" + fmt.Sprintf("%x", out)
}

func (s *Server) wsDecryptPassword(enc string) string {
	if !strings.HasPrefix(enc, "enc:") {
		return enc // 兼容旧明文
	}
	hexStr := strings.TrimPrefix(enc, "enc:")
	b := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b[i/2])
	}
	key := s.wsServerKey()
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ key[i%len(key)]
	}
	return string(out)
}

// wsServerKey 服务端密钥（从 PG DSN 派生，每部署唯一）。
func (s *Server) wsServerKey() []byte {
	dsn := ""
	if cfg, ok, _ := s.m.PG().GetSetting("database_dsn"); ok {
		dsn = cfg
	}
	if dsn == "" {
		dsn = "forang-default-key"
	}
	// 取 DSN 的 MD5 前 16 字节作 key
	sum := md5Sum(dsn)
	return []byte(sum[:16])
}

func md5Sum(s string) string {
	h := fmt.Sprintf("%x", simpleHash(s))
	for len(h) < 32 {
		h += h
	}
	return h[:32]
}

func simpleHash(s string) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range s {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
