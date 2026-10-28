package server

// consent.go — 授权承诺（移植自哨兵 consent.ts，MIT）：攻击性安全工具的合规留痕。
// 语义：登录成功≠可用；当前承诺文案（含版本号）的哈希必须已被该账号确认过，
// 否则登录返回 403 consent_required，前端展示文案并要求勾选 → POST /api/auth/consent
// 记录 {user, hash, at} → 重试登录。改文案（升 shape 版本）后所有账号需重新确认。
// 哈希同时覆盖中英文？哨兵是双语文案都算通过；FORANG 单语文案，哈希直接 sha256(text)。

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// ConsentShape 文案版本：改文案必须升这个号，否则旧确认记录仍视为有效。
const consentShape = 1

const consentTextZh = `FORANG 是攻击性安全测试平台。我承诺：仅对我已获得书面授权的目标使用本平台进行渗透测试与漏洞验证；不利用本平台对任何未经授权的系统实施入侵、扫描、口令破解或其他攻击行为；我已知晓《网络安全法》第二十七条、《刑法》第二百八十五条、第二百八十六条、第二百八十七条之二的相关规定，因违规使用造成的一切后果由我本人承担。`

func consentHash() string {
	h := sha256.Sum256([]byte(string(rune('0'+consentShape)) + "|" + consentTextZh))
	return hex.EncodeToString(h[:])
}

func (s *Server) consentRecordKey() string { return "consent.accepted." + consentHash() }

// consentAcceptedFor: settings 记录 "consent.accepted.<hash>" = "<user>|<RFC3339>"。
// 同哈希被任意账号确认后即对本机有效（哨兵语义：承诺绑定这台部署；换文案重确认）。
// 单用户平台（FORANG）这样最简；记录里仍写明是谁在何时确认的。
func (s *Server) consentAccepted() (user, at string, ok bool) {
	if s.m.pg == nil {
		return "", "", false
	}
	v, found, _ := s.m.pg.GetSetting(s.consentRecordKey())
	if !found || v == "" {
		return "", "", false
	}
	parts := split2(v, "|")
	return parts[0], parts[1], true
}

func split2(s, sep string) [2]string {
	var out [2]string
	for i := 0; i < len(s); i++ {
		if string(s[i]) == sep {
			out[0], out[1] = s[:i], s[i+1:]
			return out
		}
	}
	out[0] = s
	return out
}

// GET /api/auth/consent — 前端登录页拉取文案与确认状态（免鉴权）。
func (s *Server) authConsentGet(w http.ResponseWriter, r *http.Request) {
	user, at, ok := s.consentAccepted()
	writeJSON(w, 200, map[string]any{
		"shape":    consentShape,
		"hash":     consentHash(),
		"text":     consentTextZh,
		"accepted": ok,
		"accepted_by": user,
		"accepted_at": at,
	})
}

// POST /api/auth/consent — 记录确认（不需要 JWT：登录前的动作；能打到本机即视为
// 部署者本人/受信内网，与哨兵一致——承诺的价值在留痕，不在拦截）。
func (s *Server) authConsentPost(w http.ResponseWriter, r *http.Request) {
	var body struct{ Acknowledged bool `json:"acknowledged"` }
	if err := decode(r, &body); err != nil || !body.Acknowledged {
		writeErr(w, 400, "需要 acknowledged=true")
		return
	}
	user := "FORANG"
	if s.m.pg == nil {
		writeErr(w, 503, "数据源暂时不可用")
		return
	}
	rec := user + "|" + time.Now().Format(time.RFC3339)
	if err := s.m.pg.SetSetting(s.consentRecordKey(), rec); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// consentEnforced 登录前的闸门（authLogin 调用）。
func (s *Server) consentEnforced() bool {
	_, _, ok := s.consentAccepted()
	return !ok
}
