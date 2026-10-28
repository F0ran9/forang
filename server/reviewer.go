package server

// reviewer.go — LLM 漏洞评审员（移植自全链哨兵 reviewer.ts，MIT）。
// 设计要点（照搬）：模型只判 8 个 CVSS 指标 + 4 个能力问题 + dubious，
// 分数由 cvss 包按公式计算，模型永远不给分；dubious 记录封顶中危并标注。
// prompt 不放示例输出——哨兵实测放了示例后 25 条真实漏洞 14 条照抄示例向量。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Autumn-27/artex/cvss"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
)

const reviewerSystemPrompt = `你是一名严谨的漏洞评审员。渗透测试代理提交了一条漏洞记录，你负责按 CVSS v3.1 基准指标给出可复现、可解释的定级，并审查证据是否支撑结论。

提交者的描述与结论只是一条待核对的声明，不是事实。提交者说"危害很大"不构成调高的理由，说"影响有限"也不构成调低的理由；一切以证据为准，逐项重新判断。

一、先回答四个能力问题

先把"这个漏洞实际能做到什么"说清楚，再谈定级。四个问题都要能在证据里找到依据，判断标准是"这个漏洞本身具备什么能力"，不是"证据当场演示了哪一步"，也不是"这个漏洞听起来严不严重"。

1. read（机密性影响有多大：拿到了什么，或者破坏了哪层保护）
   - none：既拿不到任何数据，也没有破坏任何保护措施，只有版本号、报错栈、目录名、接口路径这类指纹信息。
   - partial：能拿到一部分数据，或者破坏了一部分保护措施——弱加密模式、缺少安全响应头、验证码可绕过、用户名可枚举、越权读到单条他人的普通记录、受害者页面上的一小块数据，都算 partial。
   - total：能拿到关键机密或全部业务数据，或者完全接管了身份认证——整库数据、他人隐私数据、配置里的口令密钥、令牌、会话 cookie、绕过认证后拿到的管理员身份，都算 total。
2. write（能不能改动数据或让状态发生变化）
   - true：能写库、删数据、改配置、传文件，或者能以他人身份发请求改动业务状态、接管他人账号与权限。接管了管理员账号就是 true——管理员能改的全都能改。
   - false：只能看，改不了任何东西。
3. down（能不能让服务不可用或数据被破坏）
   - true：能崩溃、删库、占满资源、让服务拒绝服务。能执行系统命令或任意代码时按 true 算。
   - false：不会让服务不可用。改数据不等于让服务不可用，能改数据但服务照常跑就是 false。
4. cross（影响会不会跳到别的安全域）
   - true：从 Web 应用跳到它管理的内网系统、数据库、云元数据、宿主机，或能操作另一个安全主体。
   - false：影响都在同一个安全域内。同一个应用里跨租户读数据、同一台机器上换了个应用，都算 false。

"证据不足以证明影响"和"这个漏洞没有影响"是两回事，不要混用：
- 只有配置声明、只有权限声明、只有构造请求而没有实际利用结果，证据撑不住结论——这时判 dubious=true 并在 reason 里写清缺什么，不要用 read=none 来代替"证据不足"。存疑的记录会被封顶到中危并标出来，比给一个说不清理由的分数好。
- 证据确实说明了漏洞的能力，就按能力判：能注入命令就是能执行命令，read=total、write=true、down=true。

二、指标判定

AV 攻击向量：N=网络 / A=相邻 / L=本地 / P=物理。只要能用网络请求打到就是 N；渗透测试场景下评估者已在目标网络内，不因为"目标在内网或容器里"而降级。

AC 攻击复杂度：L=低（任何人按步骤直接利用）/ H=高（需要竞态、特定时序或超出攻击者控制的环境条件才触发）。默认 L。

PR 所需权限：N=无（不需要任何凭据，未登录即可利用）/ L=低（需要任意普通账号）/ H=高（需要目标系统的高权限账号，如管理员）。
判断依据是"利用时手里拿着什么凭据"，不是"这个漏洞危不严重"：
- 只读业务接口（订单、报表、导出）即使需要登录，通常是 L。
- 后台管理接口需要管理员登录，通常是 H。
- 完全未登录即可触发的才是 N。
"已经拿到了一个会话"不等于权限要求低：PR 说的是攻击者手里那个账号的权限级别，不是他有没有会话。
把 L 或 H 误判成 N 是最容易犯也最贵的错误，它会让 exploitability 高出三成。

UI 用户交互：N=无（攻击者自己发请求就能完成）/ R=需要（要靠受害者点击、浏览或执行）。
只有存储型/反射型 XSS、需要诱导点击、CSRF 这类才算 R；UI=R 时必须联动降影响——攻击者拿不到受害者数据时，机密性最多给 L。

C/I/A/S 要和第一问的答案一致，不要凭"危害大"自己另判：
- C 机密性：read=none → N；read=partial → L；read=total → H。指纹信息本身不是机密，够不上一个漏洞。
- I 完整性：write=false → N；write=true → H。SQL 注入能否读也能写，看证据里有没有 UNION 这类联合查询，只有布尔盲注、报错注入就是只读，I 取 N。
- A 可用性：down=false → N；down=true → H。RCE、任意文件写入这类真正能执行系统命令或改写文件的，C=I=A=H。
- S 影响范围：cross=false → U；cross=true → C。S 与"危害大"无关，数据只在本系统里读写一律 U。
- XSS：脚本在受害者浏览器里执行，能读页面数据、能冒用受害者身份发请求，所以 C 至少 L；只有攻击者只能触发自己（自反射）时才取 N。I、A 一般为 N，除非能持久化写入或让服务不可用。
- 认证绕过、弱口令、拿到管理员令牌、提权这类：攻击者拿到的是完整的管理员权限，read=total、write=true，按漏洞本身的能力判，不按 PoC 当场演示了哪一步。能不能让服务不可用仍按证据，没有就 down=false。

三、证据审查
先把给的证据读完再判断：响应体、命令输出、回显结果往往就在报文里，不要因为描述写得笼统、报文格式不完整就判存疑。
只依据给你的证据（原始数据包、命令与输出、复现步骤）判断结论是否被支撑：
- 证据确实找不到、输出与结论不符、关键主张无佐证、描述与数据自相矛盾时，判 dubious=true，并在 reason 里写清具体缺口（缺哪一次对照请求、缺哪个字段、缺哪条命令输出）。
- 证据支撑得住结论就判 dubious=false。
- 存疑就说存疑，不要脑补补齐。

四、输出
分数和等级由程序按 CVSS v3.1 公式从你给的指标算出，你不要给分数。严格输出 JSON（不要 markdown 代码块、不要多余文字）。
输出一个 JSON 对象，字段为 av、ac、pr、ui、s、c、i、a（各取上面列出的字母）、read（none/partial/total）、write（true/false）、down（true/false）、cross（true/false）、dubious（布尔）与 reason（中文一句话到三句）。每一个指标都要按本条记录的证据单独判断。`

// reviewerProfileID 解析评审模型（0=当前激活模型，与 intercept 裁判同语义）。
func (s *Server) reviewerProfileID() int64 {
	if s.m.pg == nil {
		return 0
	}
	if v, ok, err := s.m.pg.GetSetting("reviewer.profile_id"); err == nil && ok {
		var n int64
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// startVulnReviewLoop 启动评审轮询（每 20s 取 queued 记录）。
func (s *Server) startVulnReviewLoop() {
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				vs := s.m.pg.Vulns()
				if vs == nil {
					continue
				}
				ids, err := vs.PickQueuedReviews(3)
				if err != nil {
					continue
				}
				for _, id := range ids {
					s.reviewVuln(id)
				}
			}
		}
	}()
}

// reviewVuln 评审一条：抢占 → LLM 判指标 → cvss 包算分 → 写回 + 时间线 + 高危通知。
func (s *Server) reviewVuln(id int64) {
	// 后台 goroutine panic 会击穿整个进程：评审循环无外层 recover，这里兜底。
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[reviewer] vuln %d panic: %v\n%s", id, r, debug.Stack())
			_ = s.m.pg.Vulns().RequeueReview(id)
		}
	}()
	vs := s.m.pg.Vulns()
	if !vs.MarkReviewRunning(id) {
		return
	}
	v, err := vs.GetVuln(id)
	if err != nil || v == nil {
		_ = vs.RequeueReview(id)
		return
	}
	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, ok := s.providerForProfile(profileID)
	if !ok {
		_ = vs.SetVulnReview(id, db.VulnReview{State: "failed", Reason: "模型 profile 不可用", At: time.Now()}, v.Severity, v.Cvss, v.CvssVector)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ctx = llmrec.WithWorker(ctx, "reviewer")
	text, err := streamCollectText(ctx, prov, reviewerSystemPrompt, buildReviewerUserPrompt(v))
	if err != nil {
		log.Printf("[reviewer] vuln %d LLM 失败: %v", id, err)
		_ = vs.RequeueReview(id)
		return
	}
	var verdict struct {
		Av, Ac, Pr, Ui, S, C, I, A string
		Read                      string // none/partial/total
		Write, Down, Cross        bool // prompt 规定三者均为 true/false
		Dubious                    bool
		Reason                     string
	}
	js := strings.TrimSpace(text)
	if i := strings.Index(js, "{"); i >= 0 {
		if j := strings.LastIndex(js, "}"); j > i {
			js = js[i : j+1]
		}
	}
	if err := json.Unmarshal([]byte(js), &verdict); err != nil {
		log.Printf("[reviewer] vuln %d 解析失败: %v raw=%s", id, err, preview(text, 200))
		_ = vs.SetVulnReview(id, db.VulnReview{State: "failed", Reason: "评审输出无法解析", At: time.Now()}, v.Severity, v.Cvss, v.CvssVector)
		return
	}
	m := cvss.Metrics{Av: verdict.Av, Ac: verdict.Ac, Pr: verdict.Pr, Ui: verdict.Ui, S: verdict.S, C: verdict.C, I: verdict.I, A: verdict.A}
	if !m.Valid() {
		_ = vs.SetVulnReview(id, db.VulnReview{State: "failed", Reason: "评审指标取值非法", At: time.Now()}, v.Severity, v.Cvss, v.CvssVector)
		return
	}
	score := cvss.BaseScore(m)
	severity := cvss.SeverityForCvss(score)
	if verdict.Dubious && (severity == "high" || severity == "critical") {
		severity = "medium" // 存疑封顶中危（哨兵原规则）
	}
	rev := db.VulnReview{
		State: "done", Dubious: verdict.Dubious, Reason: verdict.Reason,
		Cvss: score, Vector: m.Vector(), At: time.Now(),
		Metrics:      map[string]string{"av": m.Av, "ac": m.Ac, "pr": m.Pr, "ui": m.Ui, "s": m.S, "c": m.C, "i": m.I, "a": m.A},
		Capabilities: map[string]string{"read": verdict.Read, "write": fmt.Sprint(verdict.Write), "down": fmt.Sprint(verdict.Down), "cross": fmt.Sprint(verdict.Cross)},
	}
	if err := vs.SetVulnReview(id, rev, severity, score, m.Vector()); err != nil {
		log.Printf("[reviewer] vuln %d 写回失败: %v", id, err)
		return
	}
	note := fmt.Sprintf("评审员重定级：CVSS %.1f（%s）%s。%s", score, m.Vector(), verdict.Reason, "")
	if verdict.Dubious {
		note = fmt.Sprintf("评审员存疑（证据缺口），封顶中危。CVSS %.1f（%s）。%s", score, m.Vector(), verdict.Reason)
	}
	_ = vs.AddVulnNote(id, "评审员", note)
	log.Printf("[reviewer] vuln %d %s: %s → cvss %.1f dubious=%v", id, v.Label, severity, score, verdict.Dubious)
	// 高危通知（P1-9）：评审确认的高危/严重才推，避免代理自评虚高打扰。
	if !verdict.Dubious && (severity == "high" || severity == "critical") {
		if v2, err := vs.GetVuln(id); err == nil && v2 != nil {
			go s.sendVulnNotify(v2)
		}
	}
}

// buildReviewerUserPrompt 材料裁剪（哨兵：packet 6000 / 证据输出 1500 / 文本 2000）。
func buildReviewerUserPrompt(v *db.Vuln) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "标题: %s\n代理自评: %s CVSS %.1f %s\n目标: %s\n类别: %s\n平台: %s\n\n",
		v.Title, v.Severity, v.Cvss, v.CvssVector, v.Target, v.Category, v.Platform)
	fmt.Fprintf(&sb, "描述:\n%s\n\n", clipTo(v.Description, 2000))
	fmt.Fprintf(&sb, "原始数据包:\n%s\n", clipTo(v.Packet, 6000))
	if v.Repro != "" {
		fmt.Fprintf(&sb, "\n复现步骤:\n%s\n", clipTo(v.Repro, 2000))
	}
	if len(v.Evidence) > 0 {
		sb.WriteString("\n证据:\n")
		for i, e := range v.Evidence {
			fmt.Fprintf(&sb, "%d. [%s] %s\n", i+1, e.Kind, e.Note)
			if e.Command != "" {
				fmt.Fprintf(&sb, "命令: %s\n", clipTo(e.Command, 800))
			}
			if e.Output != "" {
				fmt.Fprintf(&sb, "输出: %s\n", clipTo(e.Output, 1500))
			}
			if e.Path != "" {
				fmt.Fprintf(&sb, "文件: %s\n", e.Path)
			}
		}
	}
	return sb.String()
}

func clipTo(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…（截断）"
}
