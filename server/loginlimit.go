package server

// loginlimit.go — 登录限速（递增锁定）。
//
// 背景：平台可能被映射到公网（内网穿透/隧道），密码爆破从"内网无人管"变成
// 真实威胁；原实现是 15 分钟滑动窗口内 5 次失败后拒绝到窗口过期，攻击者只要
// 拖慢节奏就能长期试。现在改为**阶梯式锁定**：
//
//	第 1 轮 5 次失败 → 锁 5 分钟
//	第 2 轮 5 次失败 → 锁 30 分钟
//	第 3 轮及以后   → 锁 1 小时
//
// 成功登录清零；1 小时无失败则本轮失败计数归零（锁定等级保留，避免"歇会儿再来"清档）。
//
// 两个维度同时计数：
//   - IP 维度：挡住单机爆破；
//   - 账号维度：即使客户端伪造 X-Forwarded-For / CF-Connecting-IP，
//     账号维度的计数依旧会触发锁定，避免"换头即绕过"。
//
// IP 取值：只有来自回环（本机 nginx 反代）的请求才信任代理头，其它来源一律用
// TCP 对端地址，防止外部直接伪造。

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	loginFailLimit = 5 // 每轮允许的失败次数，达到即进入下一档锁定
	// 失败计数在无新失败时的自然衰减时间
	loginFailIdleReset = time.Hour
)

// loginLockSteps 锁定阶梯：第 1 轮 5 分钟、第 2 轮 30 分钟、第 3 轮起 1 小时。
var loginLockSteps = []time.Duration{5 * time.Minute, 30 * time.Minute, time.Hour}

type loginState struct {
	fails    int       // 当前轮内的失败次数
	level    int       // 已触发的锁定轮数（0 表示从未锁定）
	until    time.Time // 锁定解除时间
	lastFail time.Time
}

type loginLimiter struct {
	mu sync.Mutex
	m  map[string]*loginState
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{m: map[string]*loginState{}} }

// clientIP 返回用于限速的客户端 IP。
// 仅当 TCP 对端是回环（nginx 反代）时才信任代理头，否则用 TCP 对端地址。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "127.0.0.1" || host == "::1" || host == "::ffff:127.0.0.1" {
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
	}
	return host
}

// loginKeys 返回本次登录要计入的两个 key：IP 维度与账号维度。
func loginKeys(r *http.Request, username string) (string, string) {
	return "ip|" + clientIP(r), "acct|" + strings.ToLower(strings.TrimSpace(username))
}

// allow 判断是否放行；被锁时返回剩余等待时间。
func (l *loginLimiter) allow(keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		st := l.m[k]
		if st == nil {
			continue
		}
		if st.until.After(now) {
			if d := st.until.Sub(now); d > wait {
				wait = d
			}
		}
	}
	if wait > 0 {
		return false, wait
	}
	return true, 0
}

// record 记一次失败；达到阈值则按阶梯锁定。
func (l *loginLimiter) record(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		st := l.m[k]
		if st == nil {
			st = &loginState{}
			l.m[k] = st
		}
		if !st.lastFail.IsZero() && now.Sub(st.lastFail) > loginFailIdleReset {
			st.fails = 0
		}
		st.fails++
		st.lastFail = now
		if st.fails >= loginFailLimit {
			idx := st.level
			if idx >= len(loginLockSteps) {
				idx = len(loginLockSteps) - 1
			}
			st.until = now.Add(loginLockSteps[idx])
			st.level++
			st.fails = 0
		}
	}
	// 兜底清理：仅在 key 数量失控时触发一次
	if len(l.m) > 4096 {
		for k, v := range l.m {
			if v.until.Before(now) && now.Sub(v.lastFail) > loginFailIdleReset {
				delete(l.m, k)
			}
		}
	}
}

// remaining 返回本轮还剩几次可尝试（取两个维度里更严格的）。
func (l *loginLimiter) remaining(keys ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	best := loginFailLimit
	for _, k := range keys {
		st := l.m[k]
		if st == nil {
			continue
		}
		if left := loginFailLimit - st.fails; left < best {
			best = left
		}
	}
	if best < 0 {
		best = 0
	}
	return best
}

// reset 成功登录后清零（两个维度一起清）。
func (l *loginLimiter) reset(keys ...string) {
	l.mu.Lock()
	for _, k := range keys {
		delete(l.m, k)
	}
	l.mu.Unlock()
}
