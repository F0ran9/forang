package db

// vulns.go — 漏洞中枢存储（移植自全链哨兵 vuln hub 的三表结构）。
// 状态机：pending（代理提交，待操作员复核）→ confirmed / false_positive / fixed；
// 每次状态变更写一条 vuln_notes 时间线；LLM 评审结果落在 review JSONB。

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// VulnStore 持久化漏洞中枢。
type VulnStore struct{ db *DB }

// Vulns returns the vuln-hub store.
func (d *DB) Vulns() *VulnStore { return &VulnStore{db: d} }

// Vulns returns the vuln-hub store bound to this asset store's DB.
func (s *AssetStore) Vulns() *VulnStore { return &VulnStore{db: s.db} }

// VulnEvidence 一条证据：命令+输出，或工作目录内文件。
type VulnEvidence struct {
	Kind    string `json:"kind"` // command / file
	Command string `json:"command,omitempty"`
	Output  string `json:"output,omitempty"`
	Path    string `json:"path,omitempty"`
	Note    string `json:"note,omitempty"`
}

// VulnNote 处理时间线一行。
type VulnNote struct {
	At         time.Time `json:"at"`
	Author     string    `json:"author"`
	Text       string    `json:"text"`
	StatusFrom string    `json:"status_from,omitempty"`
	StatusTo   string    `json:"status_to,omitempty"`
}

// VulnReview LLM 评审员结论。State: queued/running/done/failed。
type VulnReview struct {
	State        string            `json:"state"`
	Metrics      map[string]string `json:"metrics,omitempty"`      // av/ac/pr/ui/s/c/i/a
	Capabilities map[string]string `json:"capabilities,omitempty"` // read/write/down/cross
	Dubious      bool              `json:"dubious"`
	Reason       string            `json:"reason,omitempty"`
	Cvss         float64           `json:"cvss,omitempty"`
	Vector       string            `json:"vector,omitempty"`
	At           time.Time         `json:"at,omitempty"`
}

// Vuln 一条漏洞记录。
type Vuln struct {
	ID         int64          `json:"id"`
	Label      string         `json:"label"`
	Number     int            `json:"number"`
	TaskID     int64          `json:"task_id"`
	Source     string         `json:"source"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`
	Cvss       float64        `json:"cvss"`
	CvssVector string         `json:"cvss_vector"`
	Status     string         `json:"status"`
	Target     string         `json:"target"`
	Category   string         `json:"category"`
	Platform   string         `json:"platform"`
	AppPackage string         `json:"app_package,omitempty"`
	AppVersion string         `json:"app_version,omitempty"`
	Description string        `json:"description"`
	Packet     string         `json:"packet"`
	Repro      string         `json:"repro,omitempty"`
	Remediation string        `json:"remediation,omitempty"`
	Refs       []string       `json:"refs,omitempty"`
	Evidence   []VulnEvidence `json:"evidence,omitempty"`
	Notes      []VulnNote     `json:"notes,omitempty"`
	Review     *VulnReview   `json:"review,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// VulnCreate 提交入参。
type VulnCreate struct {
	TaskID      int64
	Source      string
	Title, Severity string
	Cvss        float64
	CvssVector  string
	Target, Category string
	Platform, AppPackage, AppVersion string
	Description, Packet string
	Repro, Remediation string
	Refs        []string
	Evidence    []VulnEvidence
}

// VulnFilters 列表过滤。
type VulnFilters struct {
	TaskID   int64
	Status   string
	Severity string
	Target   string // 子串
	Search   string // id/label/title/category/description 子串
}

const vulnCols = `id, label, number, task_id, source, title, severity, cvss, cvss_vector, status, target,
category, platform, app_package, app_version, description, packet, repro, remediation, refs, review, created_at, updated_at`

// VulnSeverityRank 排序用：数值越大越严重。
func VulnSeverityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// CreateVuln 落一条记录（review 初始 queued），证据随行写入。
func (s *VulnStore) CreateVuln(v VulnCreate) (*Vuln, error) {
	var number int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(number),0)+1 FROM vulns WHERE task_id=$1`, v.TaskID).Scan(&number); err != nil {
		return nil, err
	}
	label := "VULN-" + pad4(number)
	refs, _ := json.Marshal(v.Refs)
	if refs == nil {
		refs = []byte("[]")
	}
	rev, _ := json.Marshal(VulnReview{State: "queued"})
	var id int64
	err := s.db.QueryRow(`
INSERT INTO vulns (label, number, task_id, source, title, severity, cvss, cvss_vector, status,
 target, category, platform, app_package, app_version, description, packet, repro, remediation, refs, review)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING id`,
		label, number, v.TaskID, v.Source, v.Title, v.Severity, v.Cvss, v.CvssVector,
		v.Target, v.Category, plat(v.Platform), v.AppPackage, v.AppVersion,
		v.Description, v.Packet, v.Repro, v.Remediation, string(refs), string(rev)).Scan(&id)
	if err != nil {
		return nil, err
	}
	for i, e := range v.Evidence {
		if _, err := s.db.Exec(`INSERT INTO vuln_evidence (vuln_id, seq, kind, command, output, path, note) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, i, e.Kind, e.Command, e.Output, e.Path, e.Note); err != nil {
			return nil, err
		}
	}
	return s.GetVuln(id)
}

func plat(p string) string {
	if p == "android" {
		return "android"
	}
	return "web"
}

func pad4(n int) string {
	s := "000" + itoa(int64(n))
	return s[len(s)-4:]
}

// GetVuln 取完整记录（含证据与时间线）。
func (s *VulnStore) GetVuln(id int64) (*Vuln, error) {
	row := s.db.QueryRow(`SELECT `+vulnCols+` FROM vulns WHERE id=$1`, id)
	v, err := scanVuln(row)
	if err != nil {
		return nil, err
	}
	ev, err := s.db.Query(`SELECT kind, command, output, path, note FROM vuln_evidence WHERE vuln_id=$1 ORDER BY seq`, id)
	if err == nil {
		defer ev.Close()
		for ev.Next() {
			var e VulnEvidence
			if ev.Scan(&e.Kind, &e.Command, &e.Output, &e.Path, &e.Note) == nil {
				v.Evidence = append(v.Evidence, e)
			}
		}
	}
	nt, err := s.db.Query(`SELECT at, author, text, status_from, status_to FROM vuln_notes WHERE vuln_id=$1 ORDER BY seq`, id)
	if err == nil {
		defer nt.Close()
		for nt.Next() {
			var n VulnNote
			if nt.Scan(&n.At, &n.Author, &n.Text, &n.StatusFrom, &n.StatusTo) == nil {
				v.Notes = append(v.Notes, n)
			}
		}
	}
	return v, nil
}

func scanVuln(row interface{ Scan(...any) error }) (*Vuln, error) {
	var v Vuln
	var refs string
	var rev sql.NullString
	err := row.Scan(&v.ID, &v.Label, &v.Number, &v.TaskID, &v.Source, &v.Title, &v.Severity, &v.Cvss, &v.CvssVector,
		&v.Status, &v.Target, &v.Category, &v.Platform, &v.AppPackage, &v.AppVersion,
		&v.Description, &v.Packet, &v.Repro, &v.Remediation, &refs, &rev, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(refs), &v.Refs)
	if rev.Valid && rev.String != "" {
		var r VulnReview
		if json.Unmarshal([]byte(rev.String), &r) == nil {
			v.Review = &r
		}
	}
	return &v, nil
}

// ListVulns 按过滤条件列记录（不带 packet/证据/时间线，报告页再取详情）。
func (s *VulnStore) ListVulns(f VulnFilters) ([]*Vuln, error) {
	q := `SELECT ` + strings.Replace(vulnCols, "packet, ", "'' AS packet, ", 1) + `
FROM vulns WHERE 1=1`
	var args []any
	if f.TaskID != 0 {
		args = append(args, f.TaskID)
		q += ` AND task_id=$` + itoa(int64(len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		q += ` AND status=$` + itoa(int64(len(args)))
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		q += ` AND severity=$` + itoa(int64(len(args)))
	}
	if f.Target != "" {
		args = append(args, "%"+f.Target+"%")
		q += ` AND target ILIKE $` + itoa(int64(len(args)))
	}
	if f.Search != "" {
		args = append(args, "%"+f.Search+"%")
		q += ` AND (label ILIKE $` + itoa(int64(len(args))) + ` OR title ILIKE $` + itoa(int64(len(args))) +
			` OR category ILIKE $` + itoa(int64(len(args))) + ` OR description ILIKE $` + itoa(int64(len(args))) + `)`
	}
	q += ` ORDER BY cvss DESC, id DESC LIMIT 500`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Vuln
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// PickQueuedReviews 取待评审记录 id（评审循环轮询用）。
func (s *VulnStore) PickQueuedReviews(limit int) ([]int64, error) {
	rows, err := s.db.Query(`SELECT id FROM vulns WHERE review->>'state'='queued' ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

// SetVulnReview 写回评审结论（分数/向量/等级由调用方算好传入）。
func (s *VulnStore) SetVulnReview(id int64, rev VulnReview, severity string, cvss float64, vector string) error {
	b, _ := json.Marshal(rev)
	_, err := s.db.Exec(`UPDATE vulns SET review=$2, severity=$3, cvss=$4, cvss_vector=$5 WHERE id=$1`,
		id, string(b), severity, cvss, vector)
	return err
}

// MarkReviewRunning 抢占 queued→running（多实例防重复评审）。
func (s *VulnStore) MarkReviewRunning(id int64) bool {
	tag, _ := json.Marshal(map[string]string{"state": "running"})
	ct, err := s.db.Exec("UPDATE vulns SET review=$2 WHERE id=$1 AND review->>'state'='queued'", id, string(tag))
	if err != nil {
		return false
	}
	n, _ := ct.RowsAffected()
	return n == 1
}

// RequeueReview 置回 queued（手动重评/失败重试）。
func (s *VulnStore) RequeueReview(id int64) error {
	tag, _ := json.Marshal(map[string]string{"state": "queued"})
	_, err := s.db.Exec(`UPDATE vulns SET review=$2 WHERE id=$1`, id, string(tag))
	return err
}

// PatchVulnStatus 状态迁移 + 时间线。
func (s *VulnStore) PatchVulnStatus(id int64, status, author, text string) error {
	var from string
	if err := s.db.QueryRow(`SELECT status FROM vulns WHERE id=$1`, id).Scan(&from); err != nil {
		return err
	}
	if from == status {
		return nil
	}
	if _, err := s.db.Exec(`UPDATE vulns SET status=$2 WHERE id=$1`, id, status); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO vuln_notes (vuln_id, seq, author, text, status_from, status_to)
SELECT $1, COALESCE(MAX(seq),0)+1, $2, $3, $4, $5 FROM vuln_notes WHERE vuln_id=$1`,
		id, author, text, from, status)
	return err
}

// AddVulnNote 追加时间线（不改状态）。
func (s *VulnStore) AddVulnNote(id int64, author, text string) error {
	_, err := s.db.Exec(`INSERT INTO vuln_notes (vuln_id, seq, author, text)
SELECT $1, COALESCE(MAX(seq),0)+1, $2, $3 FROM vuln_notes WHERE vuln_id=$1`, id, author, text)
	return err
}
