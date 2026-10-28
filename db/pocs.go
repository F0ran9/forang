package db

import (
	"database/sql"
	"strings"
	"time"
)

// PocStore 持久化 POC 库（nuclei 模板 + 指纹匹配关键字 + 验证结论）。
type PocStore struct{ db *DB }

// Pocs returns the POC store.
func (d *DB) Pocs() *PocStore { return &PocStore{db: d} }

// Pocs returns the POC store bound to this asset store's DB.
func (s *AssetStore) Pocs() *PocStore { return &PocStore{db: s.db} }

// Poc is one stored nuclei template with match metadata.
type Poc struct {
	ID         int64     `json:"id"`
	Title      string    `json:"title"`
	Component  string    `json:"component"`
	CVE        string    `json:"cve"`
	Severity   string    `json:"severity"`
	Template   string    `json:"template"`
	Source     string    `json:"source"`
	Verified   bool      `json:"verified"`
	LastTarget string    `json:"last_target"`
	LastResult string    `json:"last_result"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PocTargetMatchInput is one asset for batch matching.
type PocTargetMatchInput struct {
	Target    string `json:"target"`
	Component string `json:"component"`
}

// PocMatch is one (target, poc) candidate pair.
type PocMatch struct {
	Target string `json:"target"`
	Poc    Poc    `json:"poc"`
	Reason string `json:"reason"`
}

const pocCols = `id, title, component, cve, severity, template, source, verified, last_target, last_result, created_at, updated_at`

func scanPoc(row interface{ Scan(...any) error }) (*Poc, error) {
	var p Poc
	if err := row.Scan(&p.ID, &p.Title, &p.Component, &p.CVE, &p.Severity, &p.Template,
		&p.Source, &p.Verified, &p.LastTarget, &p.LastResult, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreatePoc inserts a POC.
func (s *PocStore) CreatePoc(title, component, cve, severity, template, source string) (*Poc, error) {
	row := s.db.QueryRow(`
		INSERT INTO pocs (title, component, cve, severity, template, source)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+pocCols,
		title, component, cve, severity, template, source)
	return scanPoc(row)
}

// UpdatePoc modifies an existing POC.
func (s *PocStore) UpdatePoc(id int64, title, component, cve, severity, template string) (*Poc, error) {
	row := s.db.QueryRow(`
		UPDATE pocs SET title=$2, component=$3, cve=$4, severity=$5, template=$6
		WHERE id=$1 RETURNING `+pocCols,
		id, title, component, cve, severity, template)
	p, err := scanPoc(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// DeletePoc removes one POC.
func (s *PocStore) DeletePoc(id int64) error {
	_, err := s.db.Exec(`DELETE FROM pocs WHERE id=$1`, id)
	return err
}

// GetPoc fetches one POC.
func (s *PocStore) GetPoc(id int64) (*Poc, error) {
	row := s.db.QueryRow(`SELECT `+pocCols+` FROM pocs WHERE id=$1`, id)
	p, err := scanPoc(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// ListPocs lists all POCs, verified first.
func (s *PocStore) ListPocs() ([]Poc, error) {
	rows, err := s.db.Query(`SELECT ` + pocCols + ` FROM pocs ORDER BY verified DESC, updated_at DESC LIMIT 2000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Poc
	for rows.Next() {
		p, err := scanPoc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// MatchPocs returns candidate POCs whose component keywords hit the asset's
// component string (case-insensitive substring, comma-separated keywords).
func (s *PocStore) MatchPocs(in []PocTargetMatchInput) ([]PocMatch, error) {
	pocs, err := s.ListPocs()
	if err != nil {
		return nil, err
	}
	if len(pocs) == 0 || len(in) == 0 {
		return []PocMatch{}, nil
	}
	var out []PocMatch
	for _, item := range in {
		comp := strings.ToLower(item.Component)
		if comp == "" {
			continue
		}
		for _, p := range pocs {
			for _, kw := range strings.Split(p.Component, ",") {
				kw = strings.ToLower(strings.TrimSpace(kw))
				if kw == "" {
					continue
				}
				if strings.Contains(comp, kw) {
					out = append(out, PocMatch{Target: item.Target, Poc: p, Reason: kw})
					break
				}
			}
		}
	}
	if out == nil {
		out = []PocMatch{}
	}
	return out, nil
}

// RecordPocVerifyResult stores the outcome of one verification run.
func (s *PocStore) RecordVerifyResult(id int64, target, result string, matched bool) error {
	_, err := s.db.Exec(`
		UPDATE pocs SET verified=CASE WHEN $3 THEN TRUE ELSE verified END,
		               last_target=$2, last_result=$4 WHERE id=$1`,
		id, target, matched, result)
	return err
}

// UpsertByTemplate 按模板 id 去重 upsert（订阅同步用）。返回 (added, updated)。
// template_id 部分唯一索引（idx_pocs_template_id）支撑：O(logN) 取代旧 LIKE 全表扫
// （旧实现每次同步对全表做 N 次扫描，9387 模板即 O(N²)）。内容未变不重写。
func (s *PocStore) UpsertByTemplate(id, title, component, severity, template, source string) (added, updated int, err error) {
	ct, err := s.db.Exec(`INSERT INTO pocs (title, component, cve, severity, template, source, template_id)
VALUES ($1,$2,'',$3,$4,$5,$6)
ON CONFLICT (template_id) WHERE template_id <> ''
DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity,
  template=EXCLUDED.template, source=EXCLUDED.source, updated_at=now()
  WHERE pocs.template <> EXCLUDED.template`,
		title, component, severity, template, source, id)
	if err != nil {
		return 0, 0, err
	}
	n, _ := ct.RowsAffected()
	if n == 1 {
		return 1, 0, nil
	}
	return 0, 1, nil // 冲突路径（含无变化被 WHERE 挡掉，误差 ±1 可接受）
}

// PocUpsertRow 订阅导入的一行。
type PocUpsertRow struct {
	TemplateID, Title, Component, Severity, Template, Source string
}

// BulkUpsertTx 整轮导入放进单个事务（此前逐条 autocommit，1.4 万条是同步分钟级主因）。
// 任一条失败整体回滚——导入是幂等 upsert，重来无副作用。
func (s *PocStore) BulkUpsertTx(rows []PocUpsertRow) (added, updated int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	for _, r := range rows {
		ct, err := tx.Exec(`INSERT INTO pocs (title, component, cve, severity, template, source, template_id)
VALUES ($1,$2,'',$3,$4,$5,$6)
ON CONFLICT (template_id) WHERE template_id <> ''
DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity,
  template=EXCLUDED.template, source=EXCLUDED.source, updated_at=now()
  WHERE pocs.template <> EXCLUDED.template`,
			r.Title, r.Component, r.Severity, r.Template, r.Source, r.TemplateID)
		if err != nil {
			return 0, 0, err
		}
		if n, _ := ct.RowsAffected(); n == 1 {
			added++
		} else {
			updated++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return added, updated, nil
}
