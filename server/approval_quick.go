package server

// approval_quick.go — 审批快捷操作：飞书/企微推送里的免登录一键批准/拒绝链接。
//
// 安全设计（对照白盒审计的教训，这里从设计期就收紧）：
//   - 令牌用 HMAC(服务器 jwtKey, "approval:{pendingID}:{expires}") 派生，
//     不引入新密钥；泄露面=单条审批的单次决定权，10 分钟过期。
//   - 单次使用：用过的令牌进内存黑名单（进程生命周期内）；重启清空可接受
//     （令牌 10 分钟短时效，重启后旧链接自然过期）。
//   - pending 状态前置校验：已决策的 pending 任何令牌都返回 409 页面。
//   - 决策只能 allow/deny 两种，链接由服务端拼，用户不可构造中间态。
//
// 体验：手机飞书点链接 → 浏览器打开 → 显示结果页（成功绿页/失败红页）。
// 比「跳登录→找审批页→找按钮」少三步。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
)

const approvalQuickTTL = 10 * time.Minute

var (
	quickMu      sync.Mutex
	quickUsed    = map[string]time.Time{} // 已用令牌 → 使用时间（用于懒清理）
	quickUsedMax = 4096
)

// approvalQuickToken 为 pending 生成一次性审批令牌（expiresUnix 为过期 Unix 秒）。
func (s *Server) approvalQuickToken(pendingID int64, expiresUnix int64) string {
	mac := hmac.New(sha256.New, s.jwtKey)
	fmt.Fprintf(mac, "approval:%d:%d", pendingID, expiresUnix)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// approvalQuickVerify 校验令牌与有效期；通过即记入已用（单次语义）。
func (s *Server) approvalQuickVerify(pendingID int64, expiresUnix int64, token string) bool {
	if time.Now().Unix() > expiresUnix {
		return false
	}
	if !hmac.Equal([]byte(s.approvalQuickToken(pendingID, expiresUnix)), []byte(token)) {
		return false
	}
	key := fmt.Sprintf("%d:%d:%s", pendingID, expiresUnix, token)
	quickMu.Lock()
	defer quickMu.Unlock()
	if _, used := quickUsed[key]; used {
		return false
	}
	// 懒清理：超上限时丢掉过期项（按签发时间近似——用 map 大小触发即可）
	if len(quickUsed) >= quickUsedMax {
		quickUsed = map[string]time.Time{}
	}
	quickUsed[key] = time.Now()
	return true
}

// serveApprovalQuick GET /approval-quick?pid=..&exp=..&d=allow|deny&t=..
// 返回极简 HTML 结果页（手机浏览器直开）。
func (s *Server) serveApprovalQuick(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pid, err1 := strconv.ParseInt(q.Get("pid"), 10, 64)
	exp, err2 := strconv.ParseInt(q.Get("exp"), 10, 64)
	decision := q.Get("d")
	token := q.Get("t")
	if err1 != nil || err2 != nil || (decision != "allow" && decision != "deny") || token == "" {
		s.approvalQuickPage(w, 400, "链接无效", "参数缺失或格式错误")
		return
	}
	if !s.approvalQuickVerify(pid, exp, token) {
		s.approvalQuickPage(w, 401, "链接已失效", "令牌过期或已被使用；请到平台「审批与审计」页处理")
		return
	}
	if err := s.m.interceptor.Decide(pid, decision == "allow", nil); err != nil {
		// 常见场景：同一链接被点过两次（第一次成功，第二次走到这里）。
		if errors.Is(err, intercept.ErrAlreadyDecided) {
			s.approvalQuickPage(w, 409, "已处理过", "该审批此前已有决定（本链接一次性）。如需改判请到平台「审批与审计」页。")
			return
		}
		s.approvalQuickPage(w, 409, "处理失败", err.Error())
		return
	}
	label := "已批准"
	if decision == "deny" {
		label = "已拒绝"
	}
	w.Header().Set("Cache-Control", "no-store")
	s.approvalQuickPage(w, 200, label, fmt.Sprintf("审批 #%d 处理完成，任务将继续执行。", pid))
}

// approvalQuickPage 渲染结果页（内联样式，无外部依赖）。
func (s *Server) approvalQuickPage(w http.ResponseWriter, code int, title, detail string) {
	ok := code == 200
	bg, fg := "#0b3d2b", "#00ff88"
	if !ok {
		bg, fg = "#431216", "#ff7a90"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>审批 - %s</title></head>
<body style="margin:0;font-family:system-ui;background:%s;color:%s;display:flex;align-items:center;justify-content:center;min-height:100vh">
<div style="text-align:center;padding:32px">
<div style="font-size:56px;margin-bottom:12px">%s</div>
<div style="font-size:24px;font-weight:700">%s</div>
<div style="opacity:.75;margin-top:8px;font-size:14px">%s</div>
</div></body></html>`, title, bg, fg, map[bool]string{true: "✅", false: "⚠️"}[ok], title, detail)
}

// notifyPublicBaseURL 读取推送回链基址（settings notify_public_base_url）。
func (s *Server) notifyPublicBaseURL() string {
	if s.m == nil || s.m.pg == nil {
		return ""
	}
	v, ok, err := s.m.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}
