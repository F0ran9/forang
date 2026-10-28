package server

// gate.go — 隐身入口（移植自哨兵 gate.ts，MIT）：控制台一旦暴露公网/大网，测绘
// 引擎（FOFA 等）抓取首页就能指纹入库。gate 的职责不是鉴权（那是 JWT 的事），
// 而是让陌生人「不知道这里有个控制台」：
//   - 启用后，除 /api/health 外，无有效 cookie 的一切请求（含登录页/API/SSE）
//     一律返回裸 404——无重定向、无登录页、无指纹；
//   - 每次启用生成随机 token（或操作员指定），访问 /<token> 种下 HMAC cookie
//     并跳转 /，之后一切正常；
//   - cookie 是 token 的 HMAC（域分隔），服务器零状态；轮换 token 即全量失效。
// 默认关闭（内网部署无此威胁）；设置页开关/查看/轮换 token。

import (
	"time"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"strings"
)

const (
	gateCookieName = "artex-gate"
	gateHMACLabel  = "artex-gate-v1"
	gateTokenLen   = 12 // 72 bits，URL 安全字符
)

// gateEnabled / gateToken 存 settings；enabled 默认 false。
func (s *Server) gateConfig() (enabled bool, token string) {
	// 5s 缓存：gate 中间件对每个请求都会读，不能次次打 DB（审计修复：每请求 2 次 DB 读）。
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	if time.Since(s.gateCacheAt) < 5*time.Second {
		return s.gateCacheEnabled, s.gateCacheToken
	}
	enabled, token = false, ""
	if s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting("gate.enabled"); ok {
			enabled = v == "true" || v == "1"
		}
		if v, ok, _ := s.m.pg.GetSetting("gate.token"); ok {
			token = v
		}
	}
	s.gateCacheAt, s.gateCacheEnabled, s.gateCacheToken = time.Now(), enabled, token
	return enabled, token
}

// invalidateGateCache 供开关/轮换后立即生效（否则最多等 5s）。
func (s *Server) invalidateGateCache() {
	s.gateMu.Lock()
	s.gateCacheAt = time.Time{}
	s.gateMu.Unlock()
}

func (s *Server) setGateEnabled(on bool) (string, error) {
	_, token := s.gateConfig()
	if on && token == "" {
		token = newGateToken()
		if err := s.m.pg.SetSetting("gate.token", token); err != nil {
			return "", err
		}
	}
	if err := s.m.pg.SetSetting("gate.enabled", boolStr(on)); err != nil {
		return "", err
	}
	s.invalidateGateCache()
	return token, nil
}

func (s *Server) rotateGateToken() (string, error) {
	token := newGateToken()
	if err := s.m.pg.SetSetting("gate.token", token); err != nil {
		return "", err
	}
	s.invalidateGateCache()
	return token, nil
}

func newGateToken() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, gateTokenLen)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(63))
		if err != nil {
			b[i] = chars[i%len(chars)]
			continue
		}
		b[i] = chars[int(n.Int64())%len(chars)]
	}
	return string(b)
}

// gateCookieValue: HMAC-SHA256(serverKey, label|token) 的 hex。
// cookie 不携带 token 本身；轮换 token 后旧 cookie 全部失效。
func (s *Server) gateCookieValue(token string) string {
	mac := hmac.New(sha256.New, s.jwtKey)
	mac.Write([]byte(gateHMACLabel + "|" + token))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) gateCookieValid(r *http.Request, token string) bool {
	c, err := r.Cookie(gateCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	want := s.gateCookieValue(token)
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

// gateMiddleware 包装整个 root handler。见文件头注释的语义。
func (s *Server) gateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enabled, token := s.gateConfig()
		if !enabled || token == "" || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		if s.gateCookieValid(r, token) {
			next.ServeHTTP(w, r)
			return
		}
		// 入口路径：种 cookie 后跳转。常量时间比较（与 cookie 校验同标准）防逐字符探测。
		if subtle.ConstantTimeCompare([]byte(strings.Trim(r.URL.Path, "/")), []byte(token)) == 1 {
			http.SetCookie(w, &http.Cookie{
				Name:     gateCookieName,
				Value:    s.gateCookieValue(token),
				Path:     "/",
				MaxAge:   30 * 24 * 3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		// 其余一律裸 404：不带登录页、不带重定向、不带 Server 头指纹。
		http.NotFound(w, r)
	})
}

// ---------- HTTP（这些路由本身在 gate 后面：能调到它们说明已过 gate 或 gate 关闭） ----------

func (s *Server) registerGateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/gate", s.gateGet)
	mux.HandleFunc("PUT /api/gate", s.gateSet)
}

func (s *Server) gateGet(w http.ResponseWriter, r *http.Request) {
	enabled, token := s.gateConfig()
	writeJSON(w, 200, map[string]any{"enabled": enabled, "token": token})
}

func (s *Server) gateSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
		Rotate  bool  `json:"rotate"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求体无效")
		return
	}
	enabled, token := s.gateConfig()
	switch {
	case body.Rotate:
		t, err := s.rotateGateToken()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		token = t
		enabled = true
		log.Printf("[gate] token 已轮换（旧 cookie 全部失效）")
	case body.Enabled != nil:
		t, err := s.setGateEnabled(*body.Enabled)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		enabled, token = *body.Enabled, t
		if enabled {
			log.Printf("[gate] 隐身入口已启用")
		} else {
			log.Printf("[gate] 隐身入口已关闭")
		}
	}
	writeJSON(w, 200, map[string]any{"enabled": enabled, "token": token})
}

