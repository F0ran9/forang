package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// CarrierStore persists multi-carrier targets / artifacts / normalized
// backend-API endpoints (三端载体：Web / 微信小程序 / APP)。
type CarrierStore struct{ db *DB }

// Carriers returns the carrier store.
func (d *DB) Carriers() *CarrierStore { return &CarrierStore{db: d} }

// Carriers returns the carrier store bound to this asset store's DB,
// so call sites that only hold an *AssetStore can still reach carriers.
func (s *AssetStore) Carriers() *CarrierStore { return &CarrierStore{db: s.db} }

// CarrierTarget is one test target (site / mini-program / app package).
type CarrierTarget struct {
	ID         int64          `json:"id"`
	Carrier    string         `json:"carrier"`
	Name       string         `json:"name"`
	Identifier string         `json:"identifier"`
	Version    string         `json:"version"`
	Notes      string         `json:"notes"`
	Summary    json.RawMessage `json:"summary"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// CarrierArtifact is one uploaded+parsed artifact.
type CarrierArtifact struct {
	ID         int64           `json:"id"`
	TargetID   int64           `json:"target_id"`
	Kind       string          `json:"kind"`
	Filename   string          `json:"filename"`
	SHA256     string          `json:"sha256"`
	Size       int64           `json:"size"`
	StoredPath string          `json:"stored_path"`
	Status     string          `json:"status"`
	ParseError string          `json:"parse_error"`
	Analysis   json.RawMessage `json:"analysis"`
	CreatedAt  time.Time       `json:"created_at"`
}

// CarrierEndpoint is one normalized backend API call.
type CarrierEndpoint struct {
	ID             int64           `json:"id"`
	TargetID       int64           `json:"target_id"`
	Carrier        string          `json:"carrier"`
	Method         string          `json:"method"`
	Scheme         string          `json:"scheme"`
	Host           string          `json:"host"`
	Path           string          `json:"path"`
	QueryKeys      json.RawMessage `json:"query_keys"`
	BodyKeys       json.RawMessage `json:"body_keys"`
	AuthHeaders    json.RawMessage `json:"auth_headers"`
	ContentType    string          `json:"content_type"`
	SampleRequest  string          `json:"sample_request"`
	SampleResponse string          `json:"sample_response"`
	HitCount       int             `json:"hit_count"`
	FirstSeen      time.Time       `json:"first_seen"`
	LastSeen       time.Time       `json:"last_seen"`
}

// CreateCarrierTarget inserts a new target.
func (s *CarrierStore) CreateTarget(carrier, name, identifier, version, notes string) (*CarrierTarget, error) {
	row := s.db.QueryRow(`
		INSERT INTO carrier_targets (carrier, name, identifier, version, notes)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, carrier, name, identifier, version, notes, summary, created_at, updated_at`,
		carrier, name, identifier, version, notes)
	return scanCarrierTarget(row)
}

const carrierTargetCols = `id, carrier, name, identifier, version, notes, summary, created_at, updated_at`

func scanCarrierTarget(row *sql.Row) (*CarrierTarget, error) {
	var t CarrierTarget
	if err := row.Scan(&t.ID, &t.Carrier, &t.Name, &t.Identifier, &t.Version, &t.Notes, &t.Summary, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// ListCarrierTargets returns targets, newest first (optionally filtered by carrier).
func (s *CarrierStore) ListTargets(carrier string) ([]CarrierTarget, error) {
	q := `SELECT ` + carrierTargetCols + ` FROM carrier_targets`
	args := []any{}
	if carrier != "" {
		q += ` WHERE carrier = $1`
		args = append(args, carrier)
	}
	q += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CarrierTarget
	for rows.Next() {
		var t CarrierTarget
		if err := rows.Scan(&t.ID, &t.Carrier, &t.Name, &t.Identifier, &t.Version, &t.Notes, &t.Summary, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetCarrierTarget fetches one target.
func (s *CarrierStore) GetTarget(id int64) (*CarrierTarget, error) {
	row := s.db.QueryRow(`SELECT `+carrierTargetCols+` FROM carrier_targets WHERE id=$1`, id)
	t, err := scanCarrierTarget(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// DeleteCarrierTarget removes a target (artifacts/endpoints cascade).
func (s *CarrierStore) DeleteTarget(id int64) error {
	_, err := s.db.Exec(`DELETE FROM carrier_targets WHERE id=$1`, id)
	return err
}

// CreateCarrierArtifact records an uploaded artifact (status=pending).
func (s *CarrierStore) CreateArtifact(targetID int64, kind, filename, sha256, storedPath string, size int64) (*CarrierArtifact, error) {
	row := s.db.QueryRow(`
		INSERT INTO carrier_artifacts (target_id, kind, filename, sha256, stored_path, size)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, target_id, kind, filename, sha256, size, stored_path, status, parse_error, analysis, created_at`,
		targetID, kind, filename, sha256, storedPath, size)
	var a CarrierArtifact
	err := row.Scan(&a.ID, &a.TargetID, &a.Kind, &a.Filename, &a.SHA256, &a.Size, &a.StoredPath, &a.Status, &a.ParseError, &a.Analysis, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// FindArtifactBySHA returns an existing artifact with the same digest for this target.
func (s *CarrierStore) FindArtifactBySHA(targetID int64, sha string) (*CarrierArtifact, error) {
	row := s.db.QueryRow(`
		SELECT id, target_id, kind, filename, sha256, size, stored_path, status, parse_error, analysis, created_at
		FROM carrier_artifacts WHERE target_id=$1 AND sha256=$2 LIMIT 1`, targetID, sha)
	var a CarrierArtifact
	err := row.Scan(&a.ID, &a.TargetID, &a.Kind, &a.Filename, &a.SHA256, &a.Size, &a.StoredPath, &a.Status, &a.ParseError, &a.Analysis, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// GetCarrierArtifact fetches one artifact.
func (s *CarrierStore) GetArtifact(id int64) (*CarrierArtifact, error) {
	row := s.db.QueryRow(`
		SELECT id, target_id, kind, filename, sha256, size, stored_path, status, parse_error, analysis, created_at
		FROM carrier_artifacts WHERE id=$1`, id)
	var a CarrierArtifact
	err := row.Scan(&a.ID, &a.TargetID, &a.Kind, &a.Filename, &a.SHA256, &a.Size, &a.StoredPath, &a.Status, &a.ParseError, &a.Analysis, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// ListCarrierArtifacts lists artifacts of one target.
func (s *CarrierStore) ListArtifacts(targetID int64) ([]CarrierArtifact, error) {
	rows, err := s.db.Query(`
		SELECT id, target_id, kind, filename, sha256, size, stored_path, status, parse_error, analysis, created_at
		FROM carrier_artifacts WHERE target_id=$1 ORDER BY id DESC`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CarrierArtifact
	for rows.Next() {
		var a CarrierArtifact
		if err := rows.Scan(&a.ID, &a.TargetID, &a.Kind, &a.Filename, &a.SHA256, &a.Size, &a.StoredPath, &a.Status, &a.ParseError, &a.Analysis, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteCarrierArtifact removes one artifact row (caller unlinks the file).
func (s *CarrierStore) DeleteArtifact(id int64) error {
	_, err := s.db.Exec(`DELETE FROM carrier_artifacts WHERE id=$1`, id)
	return err
}

// FinishArtifact marks parse success/failure and stores the analysis payload.
func (s *CarrierStore) FinishArtifact(id int64, status, parseErr string, analysis json.RawMessage) error {
	_, err := s.db.Exec(`
		UPDATE carrier_artifacts SET status=$2, parse_error=$3, analysis=$4 WHERE id=$1`,
		id, status, parseErr, analysis)
	return err
}

// UpsertCarrierEndpoints merges parsed endpoints into the unified API table.
func (s *CarrierStore) UpsertEndpoints(ctx context.Context, targetID int64, carrier string, eps []CarrierEndpoint) (int64, error) {
	var inserted int64
	for i := range eps {
		e := &eps[i]
		e.Carrier = carrier
		qk, bk, ah := jsonRawOrDefault(e.QueryKeys, "[]"), jsonRawOrDefault(e.BodyKeys, "[]"), jsonRawOrDefault(e.AuthHeaders, "[]")
		tag, err := s.db.ExecContext(ctx, `
			INSERT INTO carrier_endpoints
				(target_id, carrier, method, scheme, host, path, query_keys, body_keys, auth_headers,
				 content_type, sample_request, sample_response, hit_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (target_id, method, host, path) DO UPDATE SET
				hit_count = carrier_endpoints.hit_count + EXCLUDED.hit_count,
				last_seen = now(),
				content_type = CASE WHEN carrier_endpoints.content_type = '' THEN EXCLUDED.content_type ELSE carrier_endpoints.content_type END,
				sample_request = CASE WHEN carrier_endpoints.sample_request = '' THEN EXCLUDED.sample_request ELSE carrier_endpoints.sample_request END,
				sample_response = CASE WHEN carrier_endpoints.sample_response = '' THEN EXCLUDED.sample_response ELSE carrier_endpoints.sample_response END`,
			targetID, e.Carrier, e.Method, e.Scheme, e.Host, e.Path, qk, bk, ah,
			e.ContentType, e.SampleRequest, e.SampleResponse, maxInt(e.HitCount, 1))
		if err != nil {
			return inserted, err
		}
		if n, _ := tag.RowsAffected(); n > 0 {
			inserted++
		}
	}
	return inserted, nil
}

func jsonRawOrDefault(raw json.RawMessage, def string) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(def)
	}
	return raw
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ListCarrierEndpoints lists endpoints of one target.
func (s *CarrierStore) ListEndpoints(targetID int64) ([]CarrierEndpoint, error) {
	rows, err := s.db.Query(`
		SELECT id, target_id, carrier, method, scheme, host, path, query_keys, body_keys, auth_headers,
		       content_type, sample_request, sample_response, hit_count, first_seen, last_seen
		FROM carrier_endpoints WHERE target_id=$1 ORDER BY host, path, method LIMIT 5000`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CarrierEndpoint
	for rows.Next() {
		var e CarrierEndpoint
		if err := rows.Scan(&e.ID, &e.TargetID, &e.Carrier, &e.Method, &e.Scheme, &e.Host, &e.Path,
			&e.QueryKeys, &e.BodyKeys, &e.AuthHeaders, &e.ContentType, &e.SampleRequest, &e.SampleResponse,
			&e.HitCount, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListEndpointsByProject lists endpoints across every target (agent 全局视图).
func (s *CarrierStore) ListAllEndpoints(carrier string, limit int) ([]CarrierEndpoint, error) {
	if limit <= 0 || limit > 2000 {
		limit = 300
	}
	q := `
		SELECT id, target_id, carrier, method, scheme, host, path, query_keys, body_keys, auth_headers,
		       content_type, sample_request, sample_response, hit_count, first_seen, last_seen
		FROM carrier_endpoints`
	args := []any{}
	if carrier != "" {
		q += ` WHERE carrier=$1`
		args = append(args, carrier)
	}
	q += ` ORDER BY last_seen DESC LIMIT ` + itoa(int64(limit))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CarrierEndpoint
	for rows.Next() {
		var e CarrierEndpoint
		if err := rows.Scan(&e.ID, &e.TargetID, &e.Carrier, &e.Method, &e.Scheme, &e.Host, &e.Path,
			&e.QueryKeys, &e.BodyKeys, &e.AuthHeaders, &e.ContentType, &e.SampleRequest, &e.SampleResponse,
			&e.HitCount, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}



// RecomputeTargetSummary rebuilds summary JSONB from all parsed artifacts.
func (s *CarrierStore) RecomputeSummary(ctx context.Context, targetID int64) error {
	arts, err := s.ListArtifacts(targetID)
	if err != nil {
		return err
	}
	domains := map[string]bool{}
	secrets := 0
	endpoints, _ := s.ListEndpoints(targetID)
	identity := map[string]string{}
	risks := map[string]bool{}
	for _, a := range arts {
		if a.Status != "parsed" {
			continue
		}
		var an struct {
			Domains   []string `json:"domains"`
			Secrets   []any    `json:"secrets"`
			RiskHints []string `json:"risk_hints"`
			AppID     string   `json:"appid"`
			Package   string   `json:"package"`
			BundleID  string   `json:"bundle_id"`
			Version   string   `json:"versionName"`
		}
		if json.Unmarshal(a.Analysis, &an) != nil {
			continue
		}
		for _, d := range an.Domains {
			domains[d] = true
		}
		secrets += len(an.Secrets)
		for _, r := range an.RiskHints {
			risks[r] = true
		}
		if an.AppID != "" {
			identity["appid"] = an.AppID
		}
		if an.Package != "" {
			identity["package"] = an.Package
		}
		if an.BundleID != "" {
			identity["bundle_id"] = an.BundleID
		}
		if an.Version != "" {
			identity["versionName"] = an.Version
		}
	}
	dl := make([]string, 0, len(domains))
	for d := range domains {
		dl = append(dl, d)
	}
	rl := make([]string, 0, len(risks))
	for r := range risks {
		rl = append(rl, r)
	}
	sortStrings(dl)
	sortStrings(rl)
	if len(dl) > 100 {
		dl = dl[:100]
	}
	if len(rl) > 20 {
		rl = rl[:20]
	}
	summary, _ := json.Marshal(map[string]any{
		"endpoints": len(endpoints),
		"domains":   dl,
		"secrets":   secrets,
		"risks":     rl,
		"identity":  identity,
	})
	_, err = s.db.ExecContext(ctx, `UPDATE carrier_targets SET summary=$2 WHERE id=$1`, targetID, summary)
	return err
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
