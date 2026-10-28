package server

// loginlimit.go — 登录限速。修复自测发现的「登录接口无限流」(medium)：
// 100 次/0.06s 的密码爆破此前毫无阻力。维度取 IP|用户名——平台是单用户 ARTEX，
// 换用户名打不到 bcrypt（用户名不匹配直接 401），真实攻击面就是同 IP 对 ARTEX
// 的密码爆破。滑动窗口内连续失败达阈值后拒绝，成功登录即清零。

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	loginFailLimit  = 5              // 窗口内允许的连续失败次数
	loginFailWindow = 15 * time.Minute
)

type loginLimiter struct {
	mu   sync.Mutex
	fail map[string][]time.Time // key -> 窗口内的失败时间戳
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{fail: map[string][]time.Time{}} }

// loginKey 用远端 IP + 提交的用户名。刻意不信任 X-Forwarded-For：平台直连暴露，
// 该头可伪造，按它限速等于按攻击者心情限速。
func loginKey(r *http.Request, username string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host + "|" + username
}

func (l *loginLimiter) prune(key string, now time.Time) []time.Time {
	ts := l.fail[key]
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < loginFailWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fail, key)
		return nil
	}
	l.fail[key] = keep
	return keep
}

// allow reports whether a login attempt for key may proceed. 拒绝时返回需要等待
// 的剩余时间（到最早一次失败出窗为止）。
func (l *loginLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	ts := l.prune(key, now)
	if len(ts) < loginFailLimit {
		return true, 0
	}
	wait := loginFailWindow - now.Sub(ts[0])
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// record logs one failed attempt.
func (l *loginLimiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.fail[key] = append(l.prune(key, now), now)
	// 全表兜底清理：只在不同 key 数量失控时触发一次，避免常驻后台协程。
	if len(l.fail) > 4096 {
		for k, v := range l.fail {
			kept := v[:0]
			for _, t := range v {
				if now.Sub(t) < loginFailWindow {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(l.fail, k)
			} else {
				l.fail[k] = kept
			}
		}
	}
}

// reset clears the counter after a successful login.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.fail, key)
	l.mu.Unlock()
}
