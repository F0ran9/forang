package server

// finding_upgrade.go — 漏洞中枢合并批次：findings 表升级为唯一漏洞中心。
// schema 末尾 ALTER 批次已为 findings 加 CVSS/评审/原始包/复现/修复建议/平台列。
// 证据子表方法在 finding_evidence.go。

import (
	"encoding/json"

	"github.com/Autumn-27/artex/db"
)

// FindingUpgrade 一条 finding 的升级字段集。
type FindingUpgrade struct {
	Cvss        float64        `json:"cvss"`
	CvssVector  string         `json:"cvss_vector"`
	Packet      string         `json:"packet"`
	Repro       string         `json:"repro"`
	Remediation string         `json:"remediation"`
	Review      *db.FindingReview `json:"review,omitempty"`
}

// GetFindingUpgrade 读取升级字段。
func (s *Server) GetFindingUpgrade(findingID int64) (*FindingUpgrade, error) {
	var u FindingUpgrade
	var review []byte
	err := s.m.pg.QueryRow(
		`SELECT cvss, cvss_vector, COALESCE(packet,''), COALESCE(repro,''), COALESCE(remediation,''), COALESCE(review,'{}'::jsonb)
FROM findings WHERE id=$1`, findingID,
	).Scan(&u.Cvss, &u.CvssVector, &u.Packet, &u.Repro, &u.Remediation, &review)
	if err != nil {
		return nil, err
	}
	if len(review) > 0 && string(review) != "{}" {
		u.Review = &db.FindingReview{}
		_ = json.Unmarshal(review, u.Review)
	}
	return &u, nil
}

// SetFindingUpgrade 写回升级字段（评审员：score/vector 由 cvss 包算好后传入）。
func (s *Server) SetFindingUpgrade(findingID int64, u FindingUpgrade) error {
	b, _ := json.Marshal(u.Review)
	_, err := s.m.pg.Exec(
		`UPDATE findings SET cvss=$2, cvss_vector=$3, packet=$4, repro=$5, remediation=$6, review=$7 WHERE id=$1`,
		findingID, u.Cvss, u.CvssVector, u.Packet, u.Repro, u.Remediation, string(b))
	return err
}

// QueueFindingReview 标记待评审。
func (s *Server) QueueFindingReview(findingID int64) error {
	_, err := s.m.pg.Exec(
		`UPDATE findings SET review=jsonb_set(COALESCE(review,'{}'::jsonb), '{state}', '"queued"') WHERE id=$1`,
		findingID)
	return err
}

// PickQueuedFindingReviews 取待评审 id 列表。
func (s *Server) PickQueuedFindingReviews(limit int) ([]int64, error) {
	rows, err := s.m.pg.Query(
		`SELECT id FROM findings WHERE review->>'state'='queued' ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// MarkFindingReviewRunning 抢占 queued→running（防并发双评）。
func (s *Server) MarkFindingReviewRunning(id int64) bool {
	ct, err := s.m.pg.Exec(
		`UPDATE findings SET review=jsonb_set(COALESCE(review,'{}'::jsonb), '{state}', '"running"')
WHERE id=$1 AND review->>'state'='queued'`, id)
	if err != nil {
		return false
	}
	n, _ := ct.RowsAffected()
	return n == 1
}

// FinishFindingReview 写回评审结论（severity/score 由 cvss 包计算后传入）。
func (s *Server) FinishFindingReview(id int64, rev db.FindingReview, severity string, score float64, vector string) error {
	b, _ := json.Marshal(rev)
	_, err := s.m.pg.Exec(
		`UPDATE findings SET severity=$2, cvss=$3, cvss_vector=$4, review=$5 WHERE id=$1`,
		id, severity, score, vector, string(b))
	return err
}
