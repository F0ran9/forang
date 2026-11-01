package agent

// tools_action.go — 攻击动作入图：webshell / C2 / 自动升级等工具执行时，自动把
// 动作写成探索图的一等节点（db.KindAction），连到产生它的意图
// （intent --yields--> action）。探索链路图由此从「推理链」升级为
// 「推理 + 攻击动作」的全景链路：每一步拿权限/执行命令都有据可查。
//
// 约定 payload：{action, summary, target?, op?, result?, cmd?, ...}
//   action  = webshell_gen / webshell_exec / auto_escalate / c2_exec / c2_beacon
//   summary = 一句话（图卡片与播报板直接显示）
//   result  = ok / fail（供前端着色）

import (
	"github.com/Autumn-27/artex/db"
)

// recordAction 写一个攻击动作节点并连到当前意图（ownerNode）。
// 无探索图上下文（对话模式 / ownerNode 未设，如 planner 侧调用）时静默跳过；
// 记录失败也不影响工具本身的成败——动作入图是旁路记账，不是工具语义的一部分。
func (t *ToolSet) recordAction(action, summary string, extra map[string]any) {
	if t.ts == nil || t.ownerNode <= 0 {
		return
	}
	payload := map[string]any{
		"action":  action,
		"summary": summary,
	}
	for k, v := range extra {
		if v != nil {
			payload[k] = v
		}
	}
	id, err := t.ts.AddNode(db.KindAction, payload, 0, "done", t.worker, nil)
	if err != nil {
		return
	}
	_ = t.ts.Link(t.ownerNode, db.RelYields, id) // intent -> action
}
