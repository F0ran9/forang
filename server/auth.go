package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	// authNotBeforeKey: 改密时写入的 unix 秒。iat 早于它的 token 一律拒绝——
	// JWT 本身无状态、改密本不吊销旧会话，这是最小成本的有状态吊销控制。
	authNotBeforeKey = "auth.token_not_before"
	jwtTTL           = 7 * 24 * time.Hour
	keyChars         = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// signJWT issues a 7-day HS256 token for user ARTEX.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "FORANG",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWTToken parses and validates an HS256 token, returning the parsed
// token (claims included) on success.
func verifyJWTToken(tokenStr string, key []byte) (*jwt.Token, bool) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	return t, err == nil && t.Valid
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	_, ok := verifyJWTToken(tokenStr, key)
	return ok
}

// extractToken reads the JWT from Authorization: Bearer header, forang_token
// cookie, or ?token= query param. The query fallback exists ONLY for SSE:
// native EventSource cannot send headers. It is restricted to GET requests on
// */stream and */event endpoints — letting a URL-embedded token authenticate
// arbitrary API calls means every access log, browser history entry and
// Referer header carrying the URL leaks full API access (自测漏洞 #3).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("forang_token"); err == nil && c.Value != "" {
		return c.Value
	}
	// 1958 收尾：SSE 不再接受 ?token=（长效 JWT 进日志/历史）。EventSource 的两条
	// 合法通道：①同源 forang_token cookie；②一次性 ?ticket=（sse-ticket，见上）。
	return ""
}

// ---- SSE 一次性票据（自测 1958）----
// POST /api/auth/sse-ticket（需 JWT）→ {ticket, expires_in}；GET <sse>?ticket=…
// 票据 60 秒有效、单次使用，仅限 /stream|/events 结尾的 GET。

var (
	sseTicketMu    sync.Mutex
	sseTicketLive  = map[string]time.Time{}
	sseTicketTTL   = 60 * time.Second
	sseTicketSweep = 5 * time.Minute
)

func issueSSETicket() (string, int) {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	tk := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	sseTicketMu.Lock()
	defer sseTicketMu.Unlock()
	// 顺手清理过期项（签发频率低，无需独立协程）
	if len(sseTicketLive) > 512 {
		for k, exp := range sseTicketLive {
			if now.After(exp) {
				delete(sseTicketLive, k)
			}
		}
	}
	sseTicketLive[tk] = now.Add(sseTicketTTL)
	return tk, int(sseTicketTTL / time.Second)
}

func consumeSSETicket(tk string) bool {
	sseTicketMu.Lock()
	defer sseTicketMu.Unlock()
	exp, ok := sseTicketLive[tk]
	if !ok {
		return false
	}
	delete(sseTicketLive, tk) // 一次性
	return time.Now().Before(exp)
}

func isSSEPath(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		(strings.HasSuffix(r.URL.Path, "/stream") || strings.HasSuffix(r.URL.Path, "/events"))
}

// sseTicketIssue POST /api/auth/sse-ticket — 给 EventSource 换一次性短票据。
func (s *Server) sseTicketIssue(w http.ResponseWriter, r *http.Request) {
	tk, ttl := issueSSETicket()
	writeJSON(w, 200, map[string]any{"ticket": tk, "expires_in": ttl})
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// 载荷直链下载免鉴权：文件名本身是一次性秘密（生成才知道）+ 10min TTL，
		// window.location.href 无法携带 Authorization 头（浏览器导航请求）
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" ||
			strings.HasPrefix(p, "/api/tools/c2/download/") ||
			strings.HasPrefix(p, "/api/tools/c2/classic/page") ||
			strings.HasPrefix(p, "/api/tools/c2/classic/static/") ||
			strings.HasPrefix(p, "/api/tools/c2/classic/stream") {
			h.ServeHTTP(w, r)
			return
		}
		// SSE 票据（自测 1958 修复）：EventSource 无法带 Authorization 头，原方案把
		// 长效 JWT 拼进 ?token= 进日志/历史。现改 ?ticket= 一次性 60s 票据——泄露面
		// 从"长效全权限"缩到"60 秒单次 SSE"。带 Authorization 的普通请求不受影响。
		if tk := r.URL.Query().Get("ticket"); tk != "" && isSSEPath(r) {
			if consumeSSETicket(tk) {
				h.ServeHTTP(w, r)
				return
			}
			writeErr(w, 401, "ticket 无效或已使用")
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		t, ok := verifyJWTToken(tok, s.jwtKey)
		if !ok {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		if s.tokenRejected(t) {
			writeErr(w, 401, "token 已失效（密码修改会吊销旧会话），请重新登录")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// tokenRejected reports whether the token predates the latest password change
// (auth.token_not_before). The setting is cached briefly so the per-request
// auth path does not hit the DB on every /api call.
func (s *Server) tokenRejected(t *jwt.Token) bool {
	nb := s.tokenNotBefore()
	if nb == 0 {
		return false
	}
	if cl, ok := t.Claims.(jwt.MapClaims); ok {
		if v, ok := cl["iat"].(float64); ok {
			return int64(v) < nb
		}
	}
	return false
}

func (s *Server) tokenNotBefore() int64 {
	s.nbMu.Lock()
	defer s.nbMu.Unlock()
	if s.nbLoaded && time.Since(s.nbAt) < 60*time.Second {
		return s.nbVal
	}
	s.nbVal, s.nbLoaded, s.nbAt = 0, true, time.Now()
	if s.m.pg != nil {
		if v, ok, err := s.m.pg.GetSetting(authNotBeforeKey); err == nil && ok {
			var n int64
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
				s.nbVal = n
			}
		}
	}
	return s.nbVal
}

func (s *Server) invalidateNotBefore() {
	s.nbMu.Lock()
	s.nbLoaded = false
	s.nbMu.Unlock()
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.jwtKey) {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	// 吊销旧会话：not_before=now 使所有已签发 token（iat<now）失效。写设置失败
	// 不阻塞改密本身（改密成功是主目标），但会回退到「旧会话仍有效」的旧行为。
	if err := pg.SetSetting(authNotBeforeKey, fmt.Sprintf("%d", time.Now().Unix())); err != nil {
		log.Printf("[auth] 写 %s 失败（旧会话未被吊销）: %v", authNotBeforeKey, err)
	}
	s.invalidateNotBefore()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
// 连续失败按 IP|用户名 限速（见 loginlimit.go），达到阈值后拒绝并告知等待时长。
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	key := loginKey(r, req.Username)
	if ok, wait := s.logins.allow(key); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		writeErr(w, 429, fmt.Sprintf("登录尝试过于频繁，请约 %d 分钟后再试", int(wait.Minutes())+1))
		return
	}
	if req.Username != "FORANG" {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		s.logins.record(key)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	if s.consentEnforced() {
		writeErr(w, 403, "consent_required")
		return
	}
	s.logins.reset(key)
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
