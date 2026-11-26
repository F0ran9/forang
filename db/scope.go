package db

import "strings"

// scope.go — 任务授权范围（给 AI 裁判用的结构化事实）。
//
// 裁判此前只看到单条命令，不知道"这是客户授权的渗透测试、目标清单在册"，
// 于是把对目标主机的认证探测判成"向生产邮件服务发送认证请求"（线上 #1634，
// 实际是 A3 允许的口令测试）。这里把任务目标与在册资产作为**平台事实**
// 提供给裁判——只读 DB，不接受模型生成的内容。

// TaskScope 返回任务的人类目标描述、在册目标主机（去重、限量）与总数。
// hostLimit<=0 时默认 12。
func (d *DB) TaskScope(taskID int64, hostLimit int) (goal string, hosts []string, total int, err error) {
	if hostLimit <= 0 {
		hostLimit = 12
	}
	if e := d.QueryRow(`SELECT COALESCE(goal, '') FROM tasks WHERE id = $1`, taskID).Scan(&goal); e != nil {
		err = e
		return
	}
	rows, qerr := d.Query(`
		SELECT DISTINCT COALESCE(NULLIF(domain, ''), NULLIF(ip, '')) AS host
		FROM assets
		WHERE $1 = ANY(task_ids)
		  AND (domain <> '' OR ip <> '')
		  AND COALESCE(NULLIF(domain, ''), NULLIF(ip, '')) IS NOT NULL
		ORDER BY 1
		LIMIT $2`, taskID, hostLimit)
	if qerr != nil {
		err = qerr
		return
	}
	defer rows.Close()
	for rows.Next() {
		var h *string
		if rows.Scan(&h) == nil && h != nil && *h != "" {
			hosts = append(hosts, *h)
		}
	}
	if cerr := rows.Err(); cerr != nil {
		err = cerr
		return
	}
	_ = d.QueryRow(`
		SELECT COUNT(DISTINCT COALESCE(NULLIF(domain, ''), NULLIF(ip, '')))
		FROM assets
		WHERE $1 = ANY(task_ids)
		  AND (domain <> '' OR ip <> '')
		  AND COALESCE(NULLIF(domain, ''), NULLIF(ip, '')) IS NOT NULL`, taskID).Scan(&total)
	return
}

// TaskScopeHasHost 判断某个主机（IP 或域名）是否登记在本任务范围内。
// 供裁判按"本次命令实际打的目标"做精确归属，避免只给前 N 个资产时
// 把范围里的其它目标误判成"不在册"（线上 #2628）。
func (d *DB) TaskScopeHasHost(taskID int64, host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || taskID <= 0 {
		return false
	}
	var ok bool
	_ = d.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM assets
			WHERE $1 = ANY(task_ids)
			  AND (ip = $2 OR domain = $2 OR root_domain = $2 OR bound_domains = $2)
		)`, taskID, host).Scan(&ok)
	return ok
}
