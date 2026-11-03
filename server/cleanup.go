package server

// cleanup.go — 「清理痕迹」按钮：为指定任务一键派生清理任务。
//   清理任务继承原任务图谱（能读到本次部署过的 webshell/上传/payload 事实），
//   到被测目标上清除测试数据；其删除操作由 guard 改道 AI 裁判——裁判放行即执行，
//   裁判 ask/deny/失败转人工审批（人只兜底）。原任务的删除防线保持不变。
//
//   POST /api/tasks/{id}/cleanup → 派生清理任务并立即启动。

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

const cleanupTaskPrefix = "痕迹清理：#"

// cleanupTaskGoal 清理任务目标模板。
func cleanupTaskGoal(originID int64, target string) string {
	return fmt.Sprintf(`清理渗透任务 #%d 在被测目标上留下的全部测试痕迹。目标：%s。

执行步骤：
1) 阅读继承的源任务图谱：列出所有 action 节点与事实——本次部署过的 webshell URL、上传过的文件、
   注入过的存储型 XSS payload（留言/评论/个人资料里的测试语句）、创建过的测试账号，形成清理清单；
2) 对清单逐项到目标上核实仍存在（GET 访问列表页/详情页，检索 payload 特征：script 标签、
   alert(/prompt(/onerror=、测试标记文字）；
3) 通过应用自身接口逐项删除（删除接口/编辑置空/下线内容）。本任务是平台清理模式：删除操作会先经
   AI 裁判审批，裁判放行即执行；若进入人工审批队列，等待操作员批准即可，不要绕过；
4) webshell 文件若仍在线：经 webshell_exec 执行自删除（删除自身文件）；
5) 无法经接口清除的（如无删除端点的留言），record_fact 记录精确位置与内容供站点管理员手动清理；
6) 完成后 record_fact 汇总：已清除 N 项 / 待人工 M 项（含位置清单）。
红线（逐条硬性执行）：
- 只删「内容指纹精确匹配」的条目：先取列表，仅对内容包含源任务图谱里记录的本次 payload 原文
  （script 语句/标记文字/文件名）的条目执行删除，按条目 ID 逐个删；
- 禁止按范围/批量/通配删除（禁止 delete-all、按日期段、按用户全量）；
- 列表里找不到指纹匹配的条目 = 不是我们留的，一律不动；
- 拿不准是不是本次测试数据 → 不删，record_fact 记录待人工；
- 上传的 webshell：只删源任务图谱里记录的具体文件路径。`, originID, target)
}

// spawnCleanupTask 派生并启动清理任务；已存在则返回已有任务 id。
func (s *Server) spawnCleanupTask(originID int64, target string) (string, error) {
	name := fmt.Sprintf("%s%d", cleanupTaskPrefix, originID)
	var existing string
	_ = s.m.PG().QueryRow(`SELECT id::text FROM tasks WHERE name=$1 ORDER BY id DESC LIMIT 1`, name).Scan(&existing)
	if existing != "" {
		return existing, nil // 幂等：重复点按钮不重复建任务
	}
	t, err := s.m.CreateTaskWithOptions(target, cleanupTaskGoal(originID, target),
		db.TaskCreateOptions{Name: name, SourceTaskIDs: []int64{originID}})
	if err != nil {
		return "", err
	}
	if _, err := s.m.PG().Exec(
		`UPDATE tasks SET cleanup_mode=true WHERE id=$1`, parseI64(t.ID)); err != nil {
		return "", err
	}
	s.launchTask(t, cleanupTaskGoal(originID, target), false)
	log.Printf("[cleanup] 任务 #%d → 清理任务 #%s 已启动", originID, t.ID)
	return t.ID, nil
}

// cleanupNow POST /api/tasks/{id}/cleanup —— 「清理痕迹」按钮后端。
func (s *Server) cleanupNow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := s.m.Task(id)
	if !ok || t == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	target := t.Description
	if target == "" {
		writeErr(w, 400, "该任务没有可清理的目标地址")
		return
	}
	cid, err := s.spawnCleanupTask(parseI64(id), target)
	if err != nil {
		writeErr(w, 500, "创建清理任务失败: "+err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"cleanup_task_id": cid, "message": "清理任务已创建并开始执行"})
}

// parseI64 小助手。
func parseI64(s string) int64 {
	var n int64
	fmt.Sscan(s, &n)
	return n
}
