package server

// finding_evidence.go — findings 证据子表（kind: command/file/screenshot）。
// 表结构见 db/schema.sql 的 finding_evidence；随 findings 级联删除。

import (
	"github.com/Autumn-27/artex/db"
)

// FindingEvidence 一条发现证据。
type FindingEvidence = db.FindingEvidence

// ListFindingEvidence 取某条发现的全部证据（按 seq 升序）。
func (s *Server) ListFindingEvidence(findingID int64) ([]db.FindingEvidence, error) {
	rows, err := s.m.pg.Query(
		`SELECT kind, command, output, path, note FROM finding_evidence WHERE finding_id=$1 ORDER BY seq`,
		findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []db.FindingEvidence
	for rows.Next() {
		var e db.FindingEvidence
		if err := rows.Scan(&e.Kind, &e.Command, &e.Output, &e.Path, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// AppendFindingEvidence 追加一条证据（seq 自动递增）。
func (s *Server) AppendFindingEvidence(findingID int64, e db.FindingEvidence) error {
	_, err := s.m.pg.Exec(
		`INSERT INTO finding_evidence (finding_id, seq, kind, command, output, path, note)
SELECT $1, COALESCE(MAX(seq)+1, 0), $2, $3, $4, $5, $6 FROM finding_evidence WHERE finding_id=$1`,
		findingID, e.Kind, e.Command, e.Output, e.Path, e.Note)
	return err
}
