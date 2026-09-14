set -euo pipefail
mkdir -p internal/vulndb internal/feeds internal/vuln contrib/systemd contrib
cat > internal/model/model.go <<'EOF_internal_model_model_go'
package model

import "time"

type TLSInfo struct {
	Version    string   `json:"version,omitempty"`
	Cipher     string   `json:"cipher,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	ALPN       string   `json:"alpn,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
}

type ThreatIntel struct {
	Source     string `json:"source"`
	ObjectID   string `json:"object_id,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
	Labels     string `json:"labels,omitempty"`
	FirstSeen  string `json:"first_seen,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
}

type Finding struct {
	Target         string        `json:"target,omitempty"`
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Severity       string        `json:"severity"`
	Port           int           `json:"port,omitempty"`
	Protocol       string        `json:"protocol,omitempty"`
	Description    string        `json:"description"`
	Evidence       string        `json:"evidence,omitempty"`
	Remediation    string        `json:"remediation,omitempty"`
	CVSSScore      float64       `json:"cvss_score,omitempty"`
	CVSSVector     string        `json:"cvss_vector,omitempty"`
	EPSSScore      float64       `json:"epss_score,omitempty"`
	EPSSPercentile float64       `json:"epss_percentile,omitempty"`
	KEV            bool          `json:"kev,omitempty"`
	RiskScore      float64       `json:"risk_score,omitempty"`
	ThreatIntel    []ThreatIntel `json:"threat_intel,omitempty"`
	References     []string      `json:"references,omitempty"`
}

type Service struct {
	Target     string            `json:"target,omitempty"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Name       string            `json:"name,omitempty"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	Confidence int               `json:"confidence,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	TLS        *TLSInfo          `json:"tls,omitempty"`
	Findings   []Finding         `json:"findings,omitempty"`
}

type Report struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Target      string    `json:"target_spec"`
	Targets     []string  `json:"targets"`
	LiveTargets []string  `json:"live_targets"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	Hosts       int       `json:"hosts_scanned"`
	Scanned     int       `json:"ports_scanned"`
	Services    []Service `json:"services"`
	Findings    []Finding `json:"findings"`
}
EOF_internal_model_model_go

cat > internal/vulndb/db.go <<'EOF_internal_vulndb_db_go'
package vulndb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

type CVERecord struct {
	ID          string
	Published   string
	Modified    string
	Status      string
	Title       string
	Description string
	Severity    string
	CVSSScore   float64
	CVSSVector  string
	CWE         string
	Source      string
	Products    []AffectedProduct
	References  []Reference
}

type AffectedProduct struct {
	Vendor         string
	Product        string
	ProductNorm    string
	VersionStart   string
	StartInclusive bool
	VersionEnd     string
	EndInclusive   bool
	ExactVersion   string
	VersionType    string
	Source         string
	CPE            string
}

type Reference struct {
	URL    string
	Source string
}

type KEVRecord struct {
	CVEID            string
	VendorProject    string
	Product          string
	Vulnerability    string
	DateAdded        string
	DueDate          string
	KnownRansomware  string
	RequiredAction   string
	ShortDescription string
	Notes            string
	CWE              string
}

type EPSSRecord struct {
	CVEID      string
	Score      float64
	Percentile float64
	Date       string
}

type IntelRecord struct {
	CVEID      string
	Source     string
	ObjectID   string
	Confidence int
	Labels     string
	FirstSeen  string
	LastSeen   string
	Raw        string
}

type FeedState struct {
	Name       string
	LastUpdate string
	Status     string
	Records    int
	Cursor     string
	ETag       string
	Message    string
}

type Candidate struct {
	CVEID          string
	Title          string
	Description    string
	Severity       string
	CVSSScore      float64
	CVSSVector     string
	CWE            string
	EPSSScore      float64
	EPSSPercentile float64
	KEV            bool
	KEVDateAdded   string
	KEVRansomware  string
	KEVAction      string
	VersionStart   string
	StartInclusive bool
	VersionEnd     string
	EndInclusive   bool
	ExactVersion   string
	VersionType    string
	Source         string
}

type CVEDetail struct {
	Candidate
	Published  string
	Modified   string
	Status     string
	Products   []AffectedProduct
	References []string
	Intel      []IntelRecord
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".absl", "recon.db")
	}
	return filepath.Join(home, ".absl", "recon.db")
}

func DefaultFeedDir() string {
	return filepath.Join(filepath.Dir(DefaultPath()), "feeds")
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	store := &Store{db: db, path: path}
	if err := store.Init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func OpenExisting(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("vulnerability database does not exist: %s", path)
		}
		return nil, err
	}
	return Open(path)
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string { return s.path }

func (s *Store) Init(ctx context.Context) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
	}
	for _, q := range pragmas {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}

	schema := []string{
		`CREATE TABLE IF NOT EXISTS cves (
			id TEXT PRIMARY KEY,
			published TEXT,
			modified TEXT,
			status TEXT,
			title TEXT,
			description TEXT,
			severity TEXT,
			cvss_score REAL DEFAULT 0,
			cvss_vector TEXT,
			cwe TEXT,
			source TEXT,
			epss_score REAL DEFAULT 0,
			epss_percentile REAL DEFAULT 0,
			epss_date TEXT,
			kev INTEGER DEFAULT 0,
			kev_date_added TEXT,
			kev_due_date TEXT,
			kev_ransomware TEXT,
			kev_action TEXT,
			updated_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS affected_products (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id TEXT NOT NULL,
			vendor TEXT,
			product TEXT,
			product_norm TEXT NOT NULL,
			version_start TEXT,
			start_inclusive INTEGER DEFAULT 1,
			version_end TEXT,
			end_inclusive INTEGER DEFAULT 0,
			exact_version TEXT,
			version_type TEXT,
			source TEXT NOT NULL,
			cpe TEXT,
			FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_affected_product_norm ON affected_products(product_norm);`,
		`CREATE INDEX IF NOT EXISTS idx_affected_cve ON affected_products(cve_id);`,
		`CREATE TABLE IF NOT EXISTS cve_references (
			cve_id TEXT NOT NULL,
			url TEXT NOT NULL,
			source TEXT NOT NULL,
			PRIMARY KEY(cve_id, url, source),
			FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS threat_intel (
			cve_id TEXT NOT NULL,
			source TEXT NOT NULL,
			object_id TEXT NOT NULL,
			confidence INTEGER DEFAULT 0,
			labels TEXT,
			first_seen TEXT,
			last_seen TEXT,
			raw TEXT,
			PRIMARY KEY(cve_id, source, object_id),
			FOREIGN KEY(cve_id) REFERENCES cves(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_intel_cve ON threat_intel(cve_id);`,
		`CREATE TABLE IF NOT EXISTS feed_state (
			name TEXT PRIMARY KEY,
			last_update TEXT,
			status TEXT,
			records INTEGER DEFAULT 0,
			cursor TEXT,
			etag TEXT,
			message TEXT
		);`,
	}
	for _, q := range schema {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertCVEs(ctx context.Context, records []CVERecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, r := range records {
		if strings.TrimSpace(r.ID) == "" {
			continue
		}
		now := time.Now().UTC().Format(time.RFC3339)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO cves(
				id,published,modified,status,title,description,severity,cvss_score,cvss_vector,cwe,source,updated_at
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				published=CASE WHEN excluded.published<>'' THEN excluded.published ELSE cves.published END,
				modified=CASE WHEN excluded.modified<>'' THEN excluded.modified ELSE cves.modified END,
				status=CASE WHEN excluded.status<>'' THEN excluded.status ELSE cves.status END,
				title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE cves.title END,
				description=CASE WHEN excluded.description<>'' THEN excluded.description ELSE cves.description END,
				severity=CASE WHEN excluded.severity<>'' THEN excluded.severity ELSE cves.severity END,
				cvss_score=CASE WHEN excluded.cvss_score>0 THEN excluded.cvss_score ELSE cves.cvss_score END,
				cvss_vector=CASE WHEN excluded.cvss_vector<>'' THEN excluded.cvss_vector ELSE cves.cvss_vector END,
				cwe=CASE WHEN excluded.cwe<>'' THEN excluded.cwe ELSE cves.cwe END,
				source=CASE WHEN excluded.source<>'' THEN excluded.source ELSE cves.source END,
				updated_at=excluded.updated_at`,
			r.ID, r.Published, r.Modified, r.Status, r.Title, r.Description,
			strings.ToLower(r.Severity), r.CVSSScore, r.CVSSVector, r.CWE, r.Source, now,
		)
		if err != nil {
			return err
		}

		if r.Source != "" {
			if _, err = tx.ExecContext(ctx, `DELETE FROM affected_products WHERE cve_id=? AND source=?`, r.ID, r.Source); err != nil {
				return err
			}
		}
		for _, p := range r.Products {
			norm := p.ProductNorm
			if norm == "" {
				norm = NormalizeVendorProduct(p.Vendor, p.Product)
			}
			if norm == "" {
				continue
			}
			source := p.Source
			if source == "" {
				source = r.Source
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO affected_products(
					cve_id,vendor,product,product_norm,version_start,start_inclusive,
					version_end,end_inclusive,exact_version,version_type,source,cpe
				) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
				r.ID, p.Vendor, p.Product, norm, p.VersionStart, boolInt(p.StartInclusive),
				p.VersionEnd, boolInt(p.EndInclusive), p.ExactVersion, p.VersionType, source, p.CPE,
			)
			if err != nil {
				return err
			}
		}
		for _, ref := range r.References {
			if strings.TrimSpace(ref.URL) == "" {
				continue
			}
			source := ref.Source
			if source == "" {
				source = r.Source
			}
			_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO cve_references(cve_id,url,source) VALUES(?,?,?)`, r.ID, ref.URL, source)
			if err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) ReplaceKEV(ctx context.Context, records []KEVRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE cves SET kev=0, kev_date_added='', kev_due_date='', kev_ransomware='', kev_action=''`); err != nil {
		return err
	}
	for _, r := range records {
		if r.CVEID == "" {
			continue
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO cves(id,title,description,cwe,kev,kev_date_added,kev_due_date,kev_ransomware,kev_action,source,updated_at)
			VALUES(?,?,?,?,1,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				title=CASE WHEN cves.title='' OR cves.title IS NULL THEN excluded.title ELSE cves.title END,
				description=CASE WHEN cves.description='' OR cves.description IS NULL THEN excluded.description ELSE cves.description END,
				cwe=CASE WHEN cves.cwe='' OR cves.cwe IS NULL THEN excluded.cwe ELSE cves.cwe END,
				kev=1,
				kev_date_added=excluded.kev_date_added,
				kev_due_date=excluded.kev_due_date,
				kev_ransomware=excluded.kev_ransomware,
				kev_action=excluded.kev_action,
				updated_at=excluded.updated_at`,
			r.CVEID, r.Vulnerability, r.ShortDescription, r.CWE, r.DateAdded, r.DueDate,
			r.KnownRansomware, r.RequiredAction, "cisa-kev", time.Now().UTC().Format(time.RFC3339),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpsertEPSS(ctx context.Context, records []EPSSRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cves(id,epss_score,epss_percentile,epss_date,source,updated_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			epss_score=excluded.epss_score,
			epss_percentile=excluded.epss_percentile,
			epss_date=excluded.epss_date,
			updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range records {
		if _, err = stmt.ExecContext(ctx, r.CVEID, r.Score, r.Percentile, r.Date, "first-epss", now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpsertIntel(ctx context.Context, records []IntelRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range records {
		if r.CVEID == "" || r.Source == "" || r.ObjectID == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO cves(id,source,updated_at) VALUES(?,?,?)`, r.CVEID, r.Source, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO threat_intel(cve_id,source,object_id,confidence,labels,first_seen,last_seen,raw)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(cve_id,source,object_id) DO UPDATE SET
				confidence=excluded.confidence,
				labels=excluded.labels,
				first_seen=excluded.first_seen,
				last_seen=excluded.last_seen,
				raw=excluded.raw`,
			r.CVEID, r.Source, r.ObjectID, r.Confidence, r.Labels, r.FirstSeen, r.LastSeen, r.Raw,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetFeedState(ctx context.Context, state FeedState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO feed_state(name,last_update,status,records,cursor,etag,message)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			last_update=excluded.last_update,
			status=excluded.status,
			records=excluded.records,
			cursor=excluded.cursor,
			etag=excluded.etag,
			message=excluded.message`,
		state.Name, state.LastUpdate, state.Status, state.Records, state.Cursor, state.ETag, state.Message,
	)
	return err
}

func (s *Store) FeedState(ctx context.Context, name string) (FeedState, error) {
	var st FeedState
	err := s.db.QueryRowContext(ctx, `SELECT name,last_update,status,records,cursor,etag,message FROM feed_state WHERE name=?`, name).Scan(
		&st.Name, &st.LastUpdate, &st.Status, &st.Records, &st.Cursor, &st.ETag, &st.Message,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return FeedState{}, nil
	}
	return st, err
}

func (s *Store) FeedStates(ctx context.Context) ([]FeedState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,last_update,status,records,cursor,etag,message FROM feed_state ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedState
	for rows.Next() {
		var st FeedState
		if err := rows.Scan(&st.Name, &st.LastUpdate, &st.Status, &st.Records, &st.Cursor, &st.ETag, &st.Message); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) CountCVEs(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cves`).Scan(&n)
	return n, err
}

func (s *Store) Candidates(ctx context.Context, productNorm string) ([]Candidate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id,COALESCE(c.title,''),COALESCE(c.description,''),COALESCE(c.severity,''),
			COALESCE(c.cvss_score,0),COALESCE(c.cvss_vector,''),COALESCE(c.cwe,''),
			COALESCE(c.epss_score,0),COALESCE(c.epss_percentile,0),COALESCE(c.kev,0),
			COALESCE(c.kev_date_added,''),COALESCE(c.kev_ransomware,''),COALESCE(c.kev_action,''),
			COALESCE(ap.version_start,''),COALESCE(ap.start_inclusive,1),COALESCE(ap.version_end,''),
			COALESCE(ap.end_inclusive,0),COALESCE(ap.exact_version,''),COALESCE(ap.version_type,''),COALESCE(ap.source,'')
		FROM affected_products ap
		JOIN cves c ON c.id=ap.cve_id
		WHERE ap.product_norm=? AND UPPER(COALESCE(c.status,''))<>'REJECTED'`, productNorm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Candidate
	for rows.Next() {
		var c Candidate
		var kev, startInc, endInc int
		if err := rows.Scan(
			&c.CVEID, &c.Title, &c.Description, &c.Severity, &c.CVSSScore, &c.CVSSVector, &c.CWE,
			&c.EPSSScore, &c.EPSSPercentile, &kev, &c.KEVDateAdded, &c.KEVRansomware, &c.KEVAction,
			&c.VersionStart, &startInc, &c.VersionEnd, &endInc, &c.ExactVersion, &c.VersionType, &c.Source,
		); err != nil {
			return nil, err
		}
		c.KEV = kev != 0
		c.StartInclusive = startInc != 0
		c.EndInclusive = endInc != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) References(ctx context.Context, cveID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url FROM cve_references WHERE cve_id=? ORDER BY url LIMIT 50`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

func (s *Store) Intel(ctx context.Context, cveID string) ([]IntelRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id,source,object_id,confidence,labels,first_seen,last_seen,raw FROM threat_intel WHERE cve_id=? ORDER BY confidence DESC,source`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntelRecord
	for rows.Next() {
		var r IntelRecord
		if err := rows.Scan(&r.CVEID, &r.Source, &r.ObjectID, &r.Confidence, &r.Labels, &r.FirstSeen, &r.LastSeen, &r.Raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Search(ctx context.Context, query string, limit int) ([]CVEDetail, error) {
	if limit <= 0 {
		limit = 20
	}
	pattern := "%" + strings.TrimSpace(query) + "%"
	rows, err := s.db.QueryContext(ctx, `
		SELECT id,COALESCE(title,''),COALESCE(description,''),COALESCE(severity,''),COALESCE(cvss_score,0),
			COALESCE(cvss_vector,''),COALESCE(cwe,''),COALESCE(epss_score,0),COALESCE(epss_percentile,0),
			COALESCE(kev,0),COALESCE(kev_date_added,''),COALESCE(kev_ransomware,''),COALESCE(kev_action,''),
			COALESCE(published,''),COALESCE(modified,''),COALESCE(status,'')
		FROM cves
		WHERE id LIKE ? COLLATE NOCASE OR title LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE
		ORDER BY CASE WHEN id=? COLLATE NOCASE THEN 0 ELSE 1 END,id
		LIMIT ?`, pattern, pattern, pattern, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CVEDetail
	for rows.Next() {
		var d CVEDetail
		var kev int
		if err := rows.Scan(
			&d.CVEID, &d.Title, &d.Description, &d.Severity, &d.CVSSScore, &d.CVSSVector, &d.CWE,
			&d.EPSSScore, &d.EPSSPercentile, &kev, &d.KEVDateAdded, &d.KEVRansomware, &d.KEVAction,
			&d.Published, &d.Modified, &d.Status,
		); err != nil {
			return nil, err
		}
		d.KEV = kev != 0
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		products, err := s.productsForCVE(ctx, out[i].CVEID)
		if err != nil {
			return nil, err
		}
		refs, err := s.References(ctx, out[i].CVEID)
		if err != nil {
			return nil, err
		}
		intel, err := s.Intel(ctx, out[i].CVEID)
		if err != nil {
			return nil, err
		}
		out[i].Products = products
		out[i].References = refs
		out[i].Intel = intel
	}
	return out, nil
}

func (s *Store) productsForCVE(ctx context.Context, cveID string) ([]AffectedProduct, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT vendor,product,product_norm,version_start,start_inclusive,version_end,end_inclusive,
			exact_version,version_type,source,cpe
		FROM affected_products WHERE cve_id=? ORDER BY product_norm,source`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AffectedProduct
	for rows.Next() {
		var p AffectedProduct
		var si, ei int
		if err := rows.Scan(&p.Vendor, &p.Product, &p.ProductNorm, &p.VersionStart, &si, &p.VersionEnd, &ei, &p.ExactVersion, &p.VersionType, &p.Source, &p.CPE); err != nil {
			return nil, err
		}
		p.StartInclusive = si != 0
		p.EndInclusive = ei != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

func NormalizeProduct(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	n := b.String()
	aliases := map[string]string{
		"apachehttpserver":            "apache",
		"apachehttpd":                 "apache",
		"httpd":                       "apache",
		"openssh":                     "openssh",
		"nginx":                       "nginx",
		"microsoftiis":                "iis",
		"internetinformationservices": "iis",
		"postgres":                    "postgresql",
	}
	if v, ok := aliases[n]; ok {
		return v
	}
	return n
}

func NormalizeVendorProduct(vendor, product string) string {
	v := NormalizeProduct(vendor)
	p := NormalizeProduct(product)
	if (v == "apache" || v == "apachesoftwarefoundation") && (p == "httpserver" || p == "apache") {
		return "apache"
	}
	if (v == "openbsd" || v == "openssh") && p == "openssh" {
		return "openssh"
	}
	if p != "" {
		return p
	}
	return v
}

func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA optimize;`)
	return err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func UniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
EOF_internal_vulndb_db_go

cat > internal/feeds/feeds.go <<'EOF_internal_feeds_feeds_go'
package feeds

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

type Options struct {
	CacheDir           string
	NVDAPIKey          string
	NVDFull            bool
	OpenCTIURL         string
	OpenCTIToken       string
	OpenCTICollection  string
	OpenCTIInsecureTLS bool
	WatchMode          bool
	Log                func(format string, args ...any)
}

type Result struct {
	Provider string
	Records  int
	Skipped  bool
	Message  string
	Duration time.Duration
}

type Provider interface {
	Name() string
	Sync(context.Context, *vulndb.Store, Options) (Result, error)
}

type Manager struct {
	Providers []Provider
}

func DefaultManager() Manager {
	return Manager{
		Providers: []Provider{
			CVEProvider{},
			KEVProvider{},
			EPSSProvider{},
			NVDProvider{},
			OpenCTIProvider{},
		},
	}
}

func (m Manager) Sync(
	ctx context.Context,
	store *vulndb.Store,
	opts Options,
	only []string,
) ([]Result, error) {
	if opts.CacheDir == "" {
		opts.CacheDir = filepath.Join(filepath.Dir(store.Path()), "feeds")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		return nil, err
	}
	filter := map[string]bool{}
	for _, name := range only {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			filter[name] = true
		}
	}
	var results []Result
	var errs []error
	for _, provider := range m.Providers {
		if len(filter) > 0 && !filter[provider.Name()] {
			continue
		}
		if opts.Log != nil {
			opts.Log("[%s] sync started", provider.Name())
		}
		started := time.Now()
		res, err := provider.Sync(ctx, store, opts)
		res.Provider = provider.Name()
		res.Duration = time.Since(started)
		results = append(results, res)
		if err != nil {
			_ = store.SetFeedState(ctx, vulndb.FeedState{
				Name:       provider.Name(),
				LastUpdate: time.Now().UTC().Format(time.RFC3339),
				Status:     "error",
				Records:    res.Records,
				Message:    err.Error(),
			})
			errs = append(errs, fmt.Errorf("%s: %w", provider.Name(), err))
			if opts.Log != nil {
				opts.Log("[%s] ERROR: %v", provider.Name(), err)
			}
			continue
		}
		if opts.Log != nil {
			if res.Skipped {
				opts.Log("[%s] skipped: %s", provider.Name(), res.Message)
			} else {
				opts.Log("[%s] %d records in %s", provider.Name(), res.Records, res.Duration.Round(time.Millisecond))
			}
		}
	}
	_ = store.Vacuum(ctx)
	return results, errors.Join(errs...)
}

func parseOnly(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func ParseOnly(value string) []string { return parseOnly(value) }

func httpClient(insecure bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func newRequest(ctx context.Context, method, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ABSL-Recon/0.7 (+https://github.com/abyssalsec/absl-recon)")
	return req, nil
}

func stateAge(state vulndb.FeedState) time.Duration {
	if state.LastUpdate == "" {
		return 1<<63 - 1
	}
	t, err := time.Parse(time.RFC3339, state.LastUpdate)
	if err != nil {
		return 1<<63 - 1
	}
	return time.Since(t)
}
EOF_internal_feeds_feeds_go

cat > internal/feeds/cve.go <<'EOF_internal_feeds_cve_go'
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

const cveRepoURL = "https://github.com/CVEProject/cvelistV5.git"

type CVEProvider struct{}

func (CVEProvider) Name() string { return "cve" }

func (CVEProvider) Sync(ctx context.Context, store *vulndb.Store, opts Options) (Result, error) {
	repoDir := filepath.Join(opts.CacheDir, "cvelistV5")
	first := false
	var oldHead string

	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		if !os.IsNotExist(err) {
			return Result{}, err
		}
		first = true
		_ = os.RemoveAll(repoDir)
		if _, err := exec.LookPath("git"); err != nil {
			return Result{}, fmt.Errorf("git is required for CVE List V5 sync: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(repoDir), 0o755); err != nil {
			return Result{}, err
		}
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--single-branch", cveRepoURL, repoDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			return Result{}, fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	} else {
		var err error
		oldHead, err = gitOutput(ctx, repoDir, "rev-parse", "HEAD")
		if err != nil {
			return Result{}, err
		}
		cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "pull", "--ff-only")
		if output, err := cmd.CombinedOutput(); err != nil {
			return Result{}, fmt.Errorf("git pull failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}

	newHead, err := gitOutput(ctx, repoDir, "rev-parse", "HEAD")
	if err != nil {
		return Result{}, err
	}

	var files []string
	if first {
		err = filepath.Walk(filepath.Join(repoDir, "cves"), func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".json") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return Result{}, err
		}
	} else if oldHead != newHead {
		changed, err := gitOutput(ctx, repoDir, "diff", "--name-only", oldHead, newHead, "--", "cves")
		if err != nil {
			return Result{}, err
		}
		for _, rel := range strings.Split(changed, "\n") {
			rel = strings.TrimSpace(rel)
			if rel == "" || !strings.HasSuffix(strings.ToLower(rel), ".json") {
				continue
			}
			path := filepath.Join(repoDir, filepath.FromSlash(rel))
			if _, err := os.Stat(path); err == nil {
				files = append(files, path)
			}
		}
	}

	sort.Strings(files)
	if len(files) == 0 {
		count, _ := store.CountCVEs(ctx)
		_ = store.SetFeedState(ctx, vulndb.FeedState{
			Name:       "cve",
			LastUpdate: time.Now().UTC().Format(time.RFC3339),
			Status:     "ok",
			Records:    count,
			Cursor:     newHead,
			Message:    "no CVE List changes",
		})
		return Result{Records: 0, Message: "no changes"}, nil
	}

	const batchSize = 500
	batch := make([]vulndb.CVERecord, 0, batchSize)
	imported := 0
	for _, path := range files {
		record, err := parseCVEV5(path)
		if err != nil {
			return Result{Records: imported}, err
		}
		batch = append(batch, record)
		if len(batch) >= batchSize {
			if err := store.UpsertCVEs(ctx, batch); err != nil {
				return Result{Records: imported}, err
			}
			imported += len(batch)
			batch = batch[:0]
			if opts.Log != nil && first && imported%10000 == 0 {
				opts.Log("[cve] imported %d/%d", imported, len(files))
			}
		}
	}
	if len(batch) > 0 {
		if err := store.UpsertCVEs(ctx, batch); err != nil {
			return Result{Records: imported}, err
		}
		imported += len(batch)
	}
	count, _ := store.CountCVEs(ctx)
	if err := store.SetFeedState(ctx, vulndb.FeedState{
		Name:       "cve",
		LastUpdate: time.Now().UTC().Format(time.RFC3339),
		Status:     "ok",
		Records:    count,
		Cursor:     newHead,
		Message:    fmt.Sprintf("imported %d changed records", imported),
	}); err != nil {
		return Result{Records: imported}, err
	}
	return Result{Records: imported, Message: fmt.Sprintf("database contains %d CVEs", count)}, nil
}

func gitOutput(ctx context.Context, repoDir string, args ...string) (string, error) {
	full := append([]string{"-C", repoDir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

type cveV5Record struct {
	Metadata struct {
		CVEID         string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cveV5CNA `json:"cna"`
	} `json:"containers"`
}

type cveV5CNA struct {
	Title        string `json:"title"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Affected []struct {
		Vendor        string `json:"vendor"`
		Product       string `json:"product"`
		DefaultStatus string `json:"defaultStatus"`
		Versions      []struct {
			Version         string `json:"version"`
			Status          string `json:"status"`
			LessThan        string `json:"lessThan"`
			LessThanOrEqual string `json:"lessThanOrEqual"`
			VersionType     string `json:"versionType"`
		} `json:"versions"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Metrics      []map[string]json.RawMessage `json:"metrics"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWEID       string `json:"cweId"`
			Description string `json:"description"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
}

func parseCVEV5(path string) (vulndb.CVERecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return vulndb.CVERecord{}, err
	}
	var raw cveV5Record
	if err := json.Unmarshal(data, &raw); err != nil {
		return vulndb.CVERecord{}, fmt.Errorf("%s: %w", path, err)
	}
	r := vulndb.CVERecord{
		ID:        raw.Metadata.CVEID,
		Published: raw.Metadata.DatePublished,
		Modified:  raw.Metadata.DateUpdated,
		Status:    raw.Metadata.State,
		Title:     raw.Containers.CNA.Title,
		Source:    "cve",
	}
	for _, d := range raw.Containers.CNA.Descriptions {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			r.Description = d.Value
			break
		}
	}
	if r.Description == "" && len(raw.Containers.CNA.Descriptions) > 0 {
		r.Description = raw.Containers.CNA.Descriptions[0].Value
	}
	for _, p := range raw.Containers.CNA.ProblemTypes {
		for _, d := range p.Descriptions {
			if strings.HasPrefix(strings.ToUpper(d.CWEID), "CWE-") {
				r.CWE = d.CWEID
				break
			}
		}
		if r.CWE != "" {
			break
		}
	}
	parseCVEMetrics(raw.Containers.CNA.Metrics, &r)
	for _, a := range raw.Containers.CNA.Affected {
		if len(a.Versions) == 0 && strings.EqualFold(a.DefaultStatus, "affected") {
			r.Products = append(r.Products, vulndb.AffectedProduct{
				Vendor: a.Vendor, Product: a.Product,
				ProductNorm: vulndb.NormalizeVendorProduct(a.Vendor, a.Product),
				Source:      "cve", StartInclusive: true,
			})
		}
		for _, v := range a.Versions {
			if !strings.EqualFold(v.Status, "affected") {
				continue
			}
			p := vulndb.AffectedProduct{
				Vendor:         a.Vendor,
				Product:        a.Product,
				ProductNorm:    vulndb.NormalizeVendorProduct(a.Vendor, a.Product),
				VersionType:    v.VersionType,
				Source:         "cve",
				StartInclusive: true,
			}
			switch {
			case v.LessThan != "":
				if v.Version != "" && v.Version != "*" {
					p.VersionStart = v.Version
				}
				p.VersionEnd = v.LessThan
				p.EndInclusive = false
			case v.LessThanOrEqual != "":
				if v.Version != "" && v.Version != "*" {
					p.VersionStart = v.Version
				}
				p.VersionEnd = v.LessThanOrEqual
				p.EndInclusive = true
			case v.Version == "" || v.Version == "*":
				// Empty constraints intentionally mean all versions.
			default:
				p.ExactVersion = v.Version
			}
			r.Products = append(r.Products, p)
		}
	}
	for _, ref := range raw.Containers.CNA.References {
		if ref.URL != "" {
			r.References = append(r.References, vulndb.Reference{URL: ref.URL, Source: "cve"})
		}
	}
	return r, nil
}

func parseCVEMetrics(metrics []map[string]json.RawMessage, r *vulndb.CVERecord) {
	priority := []string{"cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"}
	for _, wanted := range priority {
		for _, metric := range metrics {
			raw, ok := metric[wanted]
			if !ok {
				continue
			}
			var cvss struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
				VectorString string  `json:"vectorString"`
			}
			if json.Unmarshal(raw, &cvss) == nil && cvss.BaseScore > 0 {
				r.CVSSScore = cvss.BaseScore
				r.CVSSVector = cvss.VectorString
				r.Severity = strings.ToLower(cvss.BaseSeverity)
				return
			}
		}
	}
}
EOF_internal_feeds_cve_go

cat > internal/feeds/kev.go <<'EOF_internal_feeds_kev_go'
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type KEVProvider struct{}

func (KEVProvider) Name() string { return "kev" }

func (KEVProvider) Sync(ctx context.Context, store *vulndb.Store, opts Options) (Result, error) {
	req, err := newRequest(ctx, http.MethodGet, kevURL)
	if err != nil {
		return Result{}, err
	}
	resp, err := httpClient(false, 2*time.Minute).Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("CISA KEV returned HTTP %d", resp.StatusCode)
	}
	var doc struct {
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID                      string   `json:"cveID"`
			VendorProject              string   `json:"vendorProject"`
			Product                    string   `json:"product"`
			VulnerabilityName          string   `json:"vulnerabilityName"`
			DateAdded                  string   `json:"dateAdded"`
			ShortDescription           string   `json:"shortDescription"`
			RequiredAction             string   `json:"requiredAction"`
			DueDate                    string   `json:"dueDate"`
			KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
			Notes                      string   `json:"notes"`
			CWEs                       []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Result{}, err
	}
	records := make([]vulndb.KEVRecord, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		records = append(records, vulndb.KEVRecord{
			CVEID:            v.CVEID,
			VendorProject:    v.VendorProject,
			Product:          v.Product,
			Vulnerability:    v.VulnerabilityName,
			DateAdded:        v.DateAdded,
			DueDate:          v.DueDate,
			KnownRansomware:  v.KnownRansomwareCampaignUse,
			RequiredAction:   v.RequiredAction,
			ShortDescription: v.ShortDescription,
			Notes:            v.Notes,
			CWE:              strings.Join(v.CWEs, ","),
		})
	}
	if err := store.ReplaceKEV(ctx, records); err != nil {
		return Result{Records: len(records)}, err
	}
	message := fmt.Sprintf("catalog %s", doc.CatalogVersion)
	if err := store.SetFeedState(ctx, vulndb.FeedState{
		Name:       "kev",
		LastUpdate: time.Now().UTC().Format(time.RFC3339),
		Status:     "ok",
		Records:    len(records),
		ETag:       resp.Header.Get("ETag"),
		Message:    message,
	}); err != nil {
		return Result{Records: len(records)}, err
	}
	return Result{Records: len(records), Message: message}, nil
}
EOF_internal_feeds_kev_go

cat > internal/feeds/epss.go <<'EOF_internal_feeds_epss_go'
package feeds

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

const epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

type EPSSProvider struct{}

func (EPSSProvider) Name() string { return "epss" }

func (EPSSProvider) Sync(ctx context.Context, store *vulndb.Store, opts Options) (Result, error) {
	if opts.WatchMode {
		state, _ := store.FeedState(ctx, "epss")
		if state.Name != "" && stateAge(state) < 20*time.Hour {
			return Result{Skipped: true, Message: "daily feed already refreshed"}, nil
		}
	}
	req, err := newRequest(ctx, http.MethodGet, epssURL)
	if err != nil {
		return Result{}, err
	}
	resp, err := httpClient(false, 5*time.Minute).Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("FIRST EPSS returned HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return Result{}, err
	}
	defer gz.Close()
	reader := csv.NewReader(gz)
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return Result{}, err
	}
	indexes := map[string]int{}
	for i, name := range header {
		indexes[strings.ToLower(strings.TrimSpace(name))] = i
	}
	cveIdx, ok1 := indexes["cve"]
	epssIdx, ok2 := indexes["epss"]
	pctIdx, ok3 := indexes["percentile"]
	if !ok1 || !ok2 || !ok3 {
		return Result{}, fmt.Errorf("unexpected EPSS CSV header: %v", header)
	}
	date := time.Now().UTC().Format("2006-01-02")
	const batchSize = 5000
	batch := make([]vulndb.EPSSRecord, 0, batchSize)
	count := 0
	for {
		row, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return Result{Records: count}, err
		}
		if cveIdx >= len(row) || epssIdx >= len(row) || pctIdx >= len(row) {
			continue
		}
		score, err1 := strconv.ParseFloat(strings.TrimSpace(row[epssIdx]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(row[pctIdx]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		batch = append(batch, vulndb.EPSSRecord{
			CVEID:      strings.TrimSpace(row[cveIdx]),
			Score:      score,
			Percentile: pct,
			Date:       date,
		})
		if len(batch) >= batchSize {
			if err := store.UpsertEPSS(ctx, batch); err != nil {
				return Result{Records: count}, err
			}
			count += len(batch)
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if err := store.UpsertEPSS(ctx, batch); err != nil {
			return Result{Records: count}, err
		}
		count += len(batch)
	}
	if err := store.SetFeedState(ctx, vulndb.FeedState{
		Name:       "epss",
		LastUpdate: time.Now().UTC().Format(time.RFC3339),
		Status:     "ok",
		Records:    count,
		ETag:       resp.Header.Get("ETag"),
		Message:    "FIRST EPSS daily scores",
	}); err != nil {
		return Result{Records: count}, err
	}
	return Result{Records: count}, nil
}
EOF_internal_feeds_epss_go

cat > internal/feeds/nvd.go <<'EOF_internal_feeds_nvd_go'
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDProvider struct{}

func (NVDProvider) Name() string { return "nvd" }

func (NVDProvider) Sync(ctx context.Context, store *vulndb.Store, opts Options) (Result, error) {
	state, _ := store.FeedState(ctx, "nvd")
	end := time.Now().UTC()
	var start *time.Time
	if !opts.NVDFull {
		if state.LastUpdate != "" {
			if t, err := time.Parse(time.RFC3339, state.LastUpdate); err == nil {
				t = t.Add(-5 * time.Minute)
				start = &t
			}
		}
		if start == nil {
			t := end.Add(-120 * 24 * time.Hour)
			start = &t
		}
	}

	count := 0
	if opts.NVDFull {
		n, err := syncNVDWindow(ctx, store, opts, nil, nil)
		count += n
		if err != nil {
			return Result{Records: count}, err
		}
	} else {
		cursor := *start
		for cursor.Before(end) {
			windowEnd := cursor.Add(119 * 24 * time.Hour)
			if windowEnd.After(end) {
				windowEnd = end
			}
			n, err := syncNVDWindow(ctx, store, opts, &cursor, &windowEnd)
			count += n
			if err != nil {
				return Result{Records: count}, err
			}
			cursor = windowEnd.Add(time.Second)
		}
	}

	message := "incremental enrichment"
	if opts.NVDFull {
		message = "full NVD enrichment"
	}
	if err := store.SetFeedState(ctx, vulndb.FeedState{
		Name:       "nvd",
		LastUpdate: end.Format(time.RFC3339),
		Status:     "ok",
		Records:    count,
		Message:    message,
	}); err != nil {
		return Result{Records: count}, err
	}
	return Result{Records: count, Message: message}, nil
}

func syncNVDWindow(ctx context.Context, store *vulndb.Store, opts Options, start, end *time.Time) (int, error) {
	startIndex := 0
	total := -1
	imported := 0
	for total < 0 || startIndex < total {
		endpoint, err := buildNVDURL(startIndex, start, end)
		if err != nil {
			return imported, err
		}
		req, err := newRequest(ctx, http.MethodGet, endpoint)
		if err != nil {
			return imported, err
		}
		if opts.NVDAPIKey != "" {
			req.Header.Set("apiKey", opts.NVDAPIKey)
		}
		resp, err := httpClient(false, 3*time.Minute).Do(req)
		if err != nil {
			return imported, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return imported, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
		}
		var doc nvdResponse
		err = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if err != nil {
			return imported, err
		}
		total = doc.TotalResults
		batch := make([]vulndb.CVERecord, 0, len(doc.Vulnerabilities))
		for _, item := range doc.Vulnerabilities {
			batch = append(batch, convertNVD(item.CVE))
		}
		if err := store.UpsertCVEs(ctx, batch); err != nil {
			return imported, err
		}
		imported += len(batch)
		startIndex = doc.StartIndex + doc.ResultsPerPage
		if opts.Log != nil && total > 0 {
			opts.Log("[nvd] %d/%d", min(startIndex, total), total)
		}
		if startIndex >= total || len(doc.Vulnerabilities) == 0 {
			break
		}
		delay := 6 * time.Second
		if opts.NVDAPIKey != "" {
			delay = 700 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return imported, ctx.Err()
		case <-time.After(delay):
		}
	}
	return imported, nil
}

func buildNVDURL(startIndex int, start, end *time.Time) (string, error) {
	u, err := url.Parse(nvdBaseURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("resultsPerPage", "2000")
	q.Set("startIndex", strconv.Itoa(startIndex))
	if start != nil && end != nil {
		q.Set("lastModStartDate", start.UTC().Format(time.RFC3339))
		q.Set("lastModEndDate", end.UTC().Format(time.RFC3339))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		Source   string `json:"source"`
		Type     string `json:"type"`
		CVSSData struct {
			Version      string  `json:"version"`
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []nvdNode `json:"configurations"`
}

type nvdNode struct {
	Operator string    `json:"operator"`
	Negate   bool      `json:"negate"`
	Nodes    []nvdNode `json:"nodes"`
	CPEMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
}

func convertNVD(c nvdCVE) vulndb.CVERecord {
	r := vulndb.CVERecord{
		ID:        c.ID,
		Published: c.Published,
		Modified:  c.LastModified,
		Status:    c.VulnStatus,
		Source:    "nvd",
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			r.Description = d.Value
			break
		}
	}
	for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		metrics := c.Metrics[key]
		if len(metrics) == 0 {
			continue
		}
		m := metrics[0]
		r.CVSSScore = m.CVSSData.BaseScore
		r.CVSSVector = m.CVSSData.VectorString
		r.Severity = strings.ToLower(m.CVSSData.BaseSeverity)
		break
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(strings.ToUpper(d.Value), "CWE-") {
				r.CWE = d.Value
				break
			}
		}
		if r.CWE != "" {
			break
		}
	}
	for _, ref := range c.References {
		if ref.URL != "" {
			r.References = append(r.References, vulndb.Reference{URL: ref.URL, Source: "nvd"})
		}
	}
	for _, config := range c.Configurations {
		collectNVDProducts(config, &r.Products)
	}
	return r
}

func collectNVDProducts(node nvdNode, out *[]vulndb.AffectedProduct) {
	for _, match := range node.CPEMatch {
		if !match.Vulnerable {
			continue
		}
		vendor, product, version := parseCPE23(match.Criteria)
		if product == "" {
			continue
		}
		p := vulndb.AffectedProduct{
			Vendor:      vendor,
			Product:     product,
			ProductNorm: vulndb.NormalizeVendorProduct(vendor, product),
			Source:      "nvd",
			CPE:         match.Criteria,
			VersionType: "cpe",
		}
		switch {
		case match.VersionStartIncluding != "":
			p.VersionStart = match.VersionStartIncluding
			p.StartInclusive = true
		case match.VersionStartExcluding != "":
			p.VersionStart = match.VersionStartExcluding
			p.StartInclusive = false
		default:
			p.StartInclusive = true
		}
		switch {
		case match.VersionEndIncluding != "":
			p.VersionEnd = match.VersionEndIncluding
			p.EndInclusive = true
		case match.VersionEndExcluding != "":
			p.VersionEnd = match.VersionEndExcluding
			p.EndInclusive = false
		}
		if p.VersionStart == "" && p.VersionEnd == "" && version != "" && version != "*" && version != "-" {
			p.ExactVersion = version
		}
		*out = append(*out, p)
	}
	for _, child := range node.Nodes {
		collectNVDProducts(child, out)
	}
}

func parseCPE23(value string) (string, string, string) {
	parts := splitEscaped(value, ':')
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", ""
	}
	return unescapeCPE(parts[3]), unescapeCPE(parts[4]), unescapeCPE(parts[5])
}

func splitEscaped(s string, sep rune) []string {
	var out []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			b.WriteRune(r)
			continue
		}
		if r == sep {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	out = append(out, b.String())
	return out
}

func unescapeCPE(s string) string {
	r := strings.NewReplacer(`\:`, `:`, `\!`, `!`, `\\`, `\`)
	return r.Replace(s)
}
EOF_internal_feeds_nvd_go

cat > internal/feeds/opencti.go <<'EOF_internal_feeds_opencti_go'
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

type OpenCTIProvider struct{}

func (OpenCTIProvider) Name() string { return "opencti" }

func (OpenCTIProvider) Sync(ctx context.Context, store *vulndb.Store, opts Options) (Result, error) {
	if strings.TrimSpace(opts.OpenCTIURL) == "" || strings.TrimSpace(opts.OpenCTICollection) == "" {
		return Result{Skipped: true, Message: "OpenCTI TAXII integration is not configured"}, nil
	}

	root := strings.TrimRight(strings.TrimSpace(opts.OpenCTIURL), "/")
	if !strings.Contains(root, "/taxii2/") && !strings.HasSuffix(root, "/taxii2") {
		root += "/taxii2/root"
	}
	objectsURL := root + "/collections/" + url.PathEscape(strings.TrimSpace(opts.OpenCTICollection)) + "/objects/"

	state, _ := store.FeedState(ctx, "opencti")
	params := url.Values{}
	params.Set("limit", "500")
	params.Set("match[type]", "vulnerability")
	if state.LastUpdate != "" {
		if t, err := time.Parse(time.RFC3339, state.LastUpdate); err == nil {
			params.Set("added_after", t.Add(-5*time.Minute).UTC().Format(time.RFC3339))
		}
	}

	client := httpClient(opts.OpenCTIInsecureTLS, 3*time.Minute)
	count := 0
	next := ""
	for {
		q := cloneValues(params)
		if next != "" {
			q.Set("next", next)
		}
		endpoint := objectsURL + "?" + q.Encode()
		req, err := newRequest(ctx, http.MethodGet, endpoint)
		if err != nil {
			return Result{Records: count}, err
		}
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
		if opts.OpenCTIToken != "" {
			req.Header.Set("Authorization", "Bearer "+opts.OpenCTIToken)
		}
		resp, err := client.Do(req)
		if err != nil {
			return Result{Records: count}, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return Result{Records: count}, fmt.Errorf("OpenCTI TAXII returned HTTP %d", resp.StatusCode)
		}
		var envelope struct {
			More    bool              `json:"more"`
			Next    string            `json:"next"`
			Objects []json.RawMessage `json:"objects"`
		}
		err = json.NewDecoder(resp.Body).Decode(&envelope)
		resp.Body.Close()
		if err != nil {
			return Result{Records: count}, err
		}
		var batch []vulndb.IntelRecord
		for _, raw := range envelope.Objects {
			records := parseOpenCTIObject(raw, opts.OpenCTICollection)
			batch = append(batch, records...)
		}
		if err := store.UpsertIntel(ctx, batch); err != nil {
			return Result{Records: count}, err
		}
		count += len(batch)
		if !envelope.More || envelope.Next == "" {
			break
		}
		next = envelope.Next
	}

	message := "OpenCTI TAXII 2.1 vulnerability collection"
	if opts.OpenCTIInsecureTLS {
		message += " (TLS verification disabled by explicit configuration)"
	}
	if err := store.SetFeedState(ctx, vulndb.FeedState{
		Name:       "opencti",
		LastUpdate: time.Now().UTC().Format(time.RFC3339),
		Status:     "ok",
		Records:    count,
		Message:    message,
	}); err != nil {
		return Result{Records: count}, err
	}
	return Result{Records: count, Message: message}, nil
}

func parseOpenCTIObject(raw json.RawMessage, collection string) []vulndb.IntelRecord {
	var obj struct {
		ID                 string   `json:"id"`
		Type               string   `json:"type"`
		Name               string   `json:"name"`
		Description        string   `json:"description"`
		Confidence         int      `json:"confidence"`
		Labels             []string `json:"labels"`
		Created            string   `json:"created"`
		Modified           string   `json:"modified"`
		OpenCTIScore       any      `json:"x_opencti_score"`
		ExternalReferences []struct {
			SourceName string `json:"source_name"`
			ExternalID string `json:"external_id"`
			URL        string `json:"url"`
		} `json:"external_references"`
	}
	if json.Unmarshal(raw, &obj) != nil || !strings.EqualFold(obj.Type, "vulnerability") {
		return nil
	}
	ids := map[string]bool{}
	for _, match := range cvePattern.FindAllString(obj.Name+" "+obj.Description, -1) {
		ids[strings.ToUpper(match)] = true
	}
	for _, ref := range obj.ExternalReferences {
		for _, match := range cvePattern.FindAllString(ref.ExternalID+" "+ref.URL, -1) {
			ids[strings.ToUpper(match)] = true
		}
	}
	if len(ids) == 0 {
		return nil
	}
	confidence := obj.Confidence
	if confidence == 0 {
		switch v := obj.OpenCTIScore.(type) {
		case float64:
			confidence = int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				confidence = n
			}
		}
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	labels := strings.Join(vulndb.UniqueStrings(obj.Labels), ",")
	source := "opencti"
	if collection != "" {
		source += ":" + collection
	}
	out := make([]vulndb.IntelRecord, 0, len(ids))
	for id := range ids {
		out = append(out, vulndb.IntelRecord{
			CVEID:      id,
			Source:     source,
			ObjectID:   obj.ID,
			Confidence: confidence,
			Labels:     labels,
			FirstSeen:  obj.Created,
			LastSeen:   obj.Modified,
			Raw:        string(raw),
		})
	}
	return out
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, values := range in {
		out[k] = append([]string(nil), values...)
	}
	return out
}
EOF_internal_feeds_opencti_go

cat > internal/feeds/feeds_test.go <<'EOF_internal_feeds_feeds_test_go'
package feeds

import (
	"encoding/json"
	"testing"
)

func TestParseCPE23(t *testing.T) {
	vendor, product, version := parseCPE23("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
	if vendor != "openbsd" || product != "openssh" || version != "9.6p1" {
		t.Fatalf("unexpected CPE parse: %q %q %q", vendor, product, version)
	}
}

func TestParseOpenCTIVulnerability(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"vulnerability",
		"id":"vulnerability--1234",
		"name":"CVE-2024-6387",
		"confidence":90,
		"labels":["exploited","ssh"],
		"created":"2026-01-01T00:00:00Z",
		"modified":"2026-01-02T00:00:00Z",
		"external_references":[{"source_name":"cve","external_id":"CVE-2024-6387"}]
	}`)
	records := parseOpenCTIObject(raw, "test-collection")
	if len(records) != 1 {
		t.Fatalf("expected one intel record, got %d", len(records))
	}
	if records[0].CVEID != "CVE-2024-6387" || records[0].Confidence != 90 {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}
EOF_internal_feeds_feeds_test_go

cat > internal/vuln/vuln.go <<'EOF_internal_vuln_vuln_go'
package vuln

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

type Engine struct {
	store *vulndb.Store
}

var versionTokenPattern = regexp.MustCompile(`(?i)[0-9]+|[a-z]+`)

type versionToken struct {
	numeric bool
	number  int
	text    string
}

func Open(path string) (*Engine, error) {
	store, err := vulndb.OpenExisting(path)
	if err != nil {
		return nil, err
	}
	return &Engine{store: store}, nil
}

func (e *Engine) Close() error {
	if e == nil || e.store == nil {
		return nil
	}
	return e.store.Close()
}

func (e *Engine) Match(service model.Service) []model.Finding {
	if e == nil || e.store == nil || strings.TrimSpace(service.Product) == "" || strings.TrimSpace(service.Version) == "" {
		return nil
	}
	ctx := context.Background()
	product := vulndb.NormalizeProduct(service.Product)
	candidates, err := e.store.Candidates(ctx, product)
	if err != nil {
		return nil
	}
	matched := map[string]vulndb.Candidate{}
	for _, candidate := range candidates {
		if versionApplies(service.Version, candidate) {
			if existing, ok := matched[candidate.CVEID]; !ok || candidate.CVSSScore > existing.CVSSScore {
				matched[candidate.CVEID] = candidate
			}
		}
	}
	findings := make([]model.Finding, 0, len(matched))
	for _, c := range matched {
		refs, _ := e.store.References(ctx, c.CVEID)
		intelRows, _ := e.store.Intel(ctx, c.CVEID)
		intel := make([]model.ThreatIntel, 0, len(intelRows))
		maxIntelConfidence := 0
		for _, item := range intelRows {
			intel = append(intel, model.ThreatIntel{
				Source:     item.Source,
				ObjectID:   item.ObjectID,
				Confidence: item.Confidence,
				Labels:     item.Labels,
				FirstSeen:  item.FirstSeen,
				LastSeen:   item.LastSeen,
			})
			if item.Confidence > maxIntelConfidence {
				maxIntelConfidence = item.Confidence
			}
		}
		risk := riskScore(c.CVSSScore, c.EPSSScore, c.KEV, maxIntelConfidence)
		severity := strings.ToLower(c.Severity)
		if severity == "" {
			severity = riskSeverity(risk)
		}
		title := c.Title
		if title == "" {
			title = "Potential vulnerability match"
		}
		description := c.Description
		if description == "" {
			description = "The remotely identified product and version match an affected-version entry in the local vulnerability intelligence database."
		}
		evidence := fmt.Sprintf(
			"Potential CVE match: remote fingerprint identified %s %s on %s:%d. Version-only remote detection cannot prove patch state or exploitability.",
			service.Product, service.Version, service.Target, service.Port,
		)
		if c.KEV {
			evidence += " CISA KEV indicates exploitation in the wild."
		}
		findings = append(findings, model.Finding{
			Target:         service.Target,
			ID:             c.CVEID,
			Title:          title,
			Severity:       severity,
			Port:           service.Port,
			Protocol:       service.Protocol,
			Description:    description,
			Evidence:       evidence,
			Remediation:    remediation(c),
			CVSSScore:      c.CVSSScore,
			CVSSVector:     c.CVSSVector,
			EPSSScore:      c.EPSSScore,
			EPSSPercentile: c.EPSSPercentile,
			KEV:            c.KEV,
			RiskScore:      risk,
			ThreatIntel:    intel,
			References:     refs,
		})
	}
	return findings
}

func remediation(c vulndb.Candidate) string {
	if c.KEVAction != "" {
		return c.KEVAction
	}
	return "Validate the finding against the vendor advisory and installed package patch state, then apply the vendor security update or upgrade to a fixed release."
}

func riskScore(cvss, epss float64, kev bool, intelConfidence int) float64 {
	cvssNorm := clamp(cvss/10, 0, 1)
	epssNorm := clamp(epss, 0, 1)
	kevNorm := 0.0
	if kev {
		kevNorm = 1
	}
	intelNorm := clamp(float64(intelConfidence)/100, 0, 1)
	score := (cvssNorm*0.35 + epssNorm*0.30 + kevNorm*0.25 + intelNorm*0.10) * 100
	return math.Round(score*10) / 10
}

func riskSeverity(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func clamp(v, minValue, maxValue float64) float64 {
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

func versionApplies(version string, c vulndb.Candidate) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if c.ExactVersion != "" {
		return matchExactOrExpression(version, c.ExactVersion)
	}
	if c.VersionStart != "" {
		cmp := compareVersions(version, c.VersionStart)
		if cmp < 0 || (cmp == 0 && !c.StartInclusive) {
			return false
		}
	}
	if c.VersionEnd != "" {
		cmp := compareVersions(version, c.VersionEnd)
		if cmp > 0 || (cmp == 0 && !c.EndInclusive) {
			return false
		}
	}
	return true
}

func matchExactOrExpression(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	for _, prefix := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(constraint, prefix) {
			other := strings.TrimSpace(strings.TrimPrefix(constraint, prefix))
			cmp := compareVersions(version, other)
			switch prefix {
			case "<=":
				return cmp <= 0
			case ">=":
				return cmp >= 0
			case "<":
				return cmp < 0
			case ">":
				return cmp > 0
			case "=":
				return cmp == 0
			}
		}
	}
	return compareVersions(version, constraint) == 0
}

func compareVersions(left, right string) int {
	a := tokenizeVersion(left)
	b := tokenizeVersion(right)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(a) {
			if remainingZero(b[i:]) {
				return 0
			}
			return -1
		}
		if i >= len(b) {
			if remainingZero(a[i:]) {
				return 0
			}
			return 1
		}
		at, bt := a[i], b[i]
		switch {
		case at.numeric && bt.numeric:
			if at.number < bt.number {
				return -1
			}
			if at.number > bt.number {
				return 1
			}
		case !at.numeric && !bt.numeric:
			if at.text < bt.text {
				return -1
			}
			if at.text > bt.text {
				return 1
			}
		case at.numeric && !bt.numeric:
			return 1
		default:
			return -1
		}
	}
	return 0
}

func tokenizeVersion(version string) []versionToken {
	raw := versionTokenPattern.FindAllString(strings.ToLower(strings.TrimSpace(version)), -1)
	tokens := make([]versionToken, 0, len(raw))
	for _, item := range raw {
		if n, err := strconv.Atoi(item); err == nil {
			tokens = append(tokens, versionToken{numeric: true, number: n})
		} else {
			tokens = append(tokens, versionToken{text: item})
		}
	}
	return tokens
}

func remainingZero(tokens []versionToken) bool {
	for _, token := range tokens {
		if !token.numeric || token.number != 0 {
			return false
		}
	}
	return true
}
EOF_internal_vuln_vuln_go

cat > internal/vuln/vuln_test.go <<'EOF_internal_vuln_vuln_test_go'
package vuln

import (
	"testing"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

func TestVersionRange(t *testing.T) {
	c := vulndb.Candidate{VersionStart: "8.5p1", StartInclusive: true, VersionEnd: "9.8p1", EndInclusive: false}
	if !versionApplies("9.6p1", c) {
		t.Fatal("expected 9.6p1 to match")
	}
	if versionApplies("9.8p1", c) {
		t.Fatal("expected 9.8p1 not to match")
	}
}

func TestRiskScore(t *testing.T) {
	score := riskScore(9.8, 0.9, true, 90)
	if score < 85 {
		t.Fatalf("expected high risk score, got %.1f", score)
	}
}
EOF_internal_vuln_vuln_test_go

cat > internal/report/report.go <<'EOF_internal_report_report_go'
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
)

func WriteAll(base string, r model.Report) error {
	if dir := filepath.Dir(base); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := writeJSON(base+".json", r); err != nil {
		return err
	}
	if err := writeCSV(base+".csv", r); err != nil {
		return err
	}
	if err := writeHTML(base+".html", r); err != nil {
		return err
	}
	return writeSARIF(base+".sarif", r)
}

func writeJSON(path string, r model.Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeCSV(path string, r model.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)
	defer w.Flush()
	if err := w.Write([]string{
		"target", "id", "severity", "risk_score", "cvss", "epss", "epss_percentile", "kev",
		"port", "protocol", "title", "evidence", "remediation", "references",
	}); err != nil {
		return err
	}
	for _, f := range r.Findings {
		if err := w.Write([]string{
			f.Target,
			f.ID,
			f.Severity,
			fmt.Sprintf("%.1f", f.RiskScore),
			fmt.Sprintf("%.1f", f.CVSSScore),
			fmt.Sprintf("%.6f", f.EPSSScore),
			fmt.Sprintf("%.6f", f.EPSSPercentile),
			strconv.FormatBool(f.KEV),
			strconv.Itoa(f.Port),
			f.Protocol,
			f.Title,
			f.Evidence,
			f.Remediation,
			strings.Join(f.References, " "),
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeHTML(path string, r model.Report) error {
	const tpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>ABSL Recon Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1500px;margin:40px auto;padding:0 20px;background:#111;color:#eee}
table{border-collapse:collapse;width:100%;margin-bottom:40px}th,td{border:1px solid #333;padding:10px;text-align:left;vertical-align:top}th{background:#222}code{white-space:pre-wrap}.critical{color:#ff4d4d;font-weight:bold}.high{color:#ff7b54;font-weight:bold}.medium{color:#ffd166}.low{color:#aaa}.kev{font-weight:bold}.risk{font-weight:bold}
</style></head><body>
<h1>ABSL Recon</h1>
<p>Target specification: {{.Target}}<br>Version: {{.Version}}<br>Hosts scanned: {{.Hosts}}<br>Ports scanned: {{.Scanned}}<br>Open services: {{len .Services}}<br>Findings: {{len .Findings}}</p>
<h2>Services</h2>
<table><tr><th>Target</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Confidence</th><th>TLS</th><th>Banner</th></tr>
{{range .Services}}<tr><td>{{.Target}}</td><td>{{.Port}}/tcp</td><td>{{.Name}}</td><td>{{.Product}}</td><td>{{.Version}}</td><td>{{.Confidence}}%</td><td>{{if .TLS}}{{.TLS.Version}}<br>{{.TLS.Cipher}}<br>{{if .TLS.Subject}}Subject: {{.TLS.Subject}}<br>{{end}}{{if .TLS.Issuer}}Issuer: {{.TLS.Issuer}}<br>{{end}}{{if .TLS.NotAfter}}Expires: {{.TLS.NotAfter}}{{end}}{{end}}</td><td><code>{{.Banner}}</code></td></tr>{{end}}</table>
<h2>Findings</h2>
<table><tr><th>Target</th><th>Severity</th><th>ID</th><th>Risk</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Port</th><th>Title</th><th>Evidence</th><th>Threat Intel</th><th>Remediation</th></tr>
{{range .Findings}}<tr><td>{{.Target}}</td><td class="{{.Severity}}">{{.Severity}}</td><td>{{.ID}}</td><td class="risk">{{printf "%.1f" .RiskScore}}</td><td>{{if .CVSSScore}}{{printf "%.1f" .CVSSScore}}{{end}}</td><td>{{if .EPSSScore}}{{printf "%.2f%%" (percent .EPSSScore)}}{{end}}</td><td class="kev">{{if .KEV}}YES{{end}}</td><td>{{.Port}}</td><td>{{.Title}}</td><td>{{.Evidence}}</td><td>{{range .ThreatIntel}}{{.Source}} {{if .Confidence}}({{.Confidence}}%){{end}} {{.Labels}}<br>{{end}}</td><td>{{.Remediation}}</td></tr>{{end}}</table>
</body></html>`
	funcs := template.FuncMap{"percent": func(v float64) float64 { return v * 100 }}
	t, err := template.New("report").Funcs(funcs).Parse(tpl)
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return t.Execute(file, r)
}

func writeSARIF(path string, r model.Report) error {
	rules := map[string]map[string]any{}
	var results []map[string]any
	for _, f := range r.Findings {
		rules[f.ID] = map[string]any{
			"id":               f.ID,
			"name":             strings.ReplaceAll(f.ID, "-", "_"),
			"shortDescription": map[string]string{"text": f.Title},
			"help":             map[string]string{"text": f.Remediation},
		}
		message := fmt.Sprintf("%s (%s tcp/%d): %s", f.Title, f.Target, f.Port, f.Evidence)
		if f.RiskScore > 0 {
			message += fmt.Sprintf(" Risk %.1f/100.", f.RiskScore)
		}
		results = append(results, map[string]any{
			"ruleId":  f.ID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]string{"text": message},
		})
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ruleList := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "ABSL Recon", "version": r.Version, "rules": ruleList}},
			"results": results,
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
EOF_internal_report_report_go

cat > cmd/abslscan/main.go <<'EOF_cmd_abslscan_main_go'
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abyssalsec/absl-recon/internal/discovery"
	"github.com/abyssalsec/absl-recon/internal/event"
	"github.com/abyssalsec/absl-recon/internal/feeds"
	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/report"
	"github.com/abyssalsec/absl-recon/internal/rules"
	"github.com/abyssalsec/absl-recon/internal/scanner"
	targetset "github.com/abyssalsec/absl-recon/internal/target"
	"github.com/abyssalsec/absl-recon/internal/terminal"
	"github.com/abyssalsec/absl-recon/internal/vuln"
	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

const version = "0.7.0"

type hostResult struct {
	services []model.Service
	err      error
}

type feedFlags struct {
	dbPath            *string
	cacheDir          *string
	only              *string
	nvdAPIKey         *string
	nvdFull           *bool
	openCTIURL        *string
	openCTIToken      *string
	openCTICollection *string
	openCTIInsecure   *bool
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "db" {
		runDB(os.Args[2:])
		return
	}
	runScan(os.Args[1:])
}

func runScan(args []string) {
	fs := flag.NewFlagSet("abslscan", flag.ExitOnError)
	portsSpec := fs.String("p", "21-25,53,80,110,143,443,445,465,587,993,995,1433,1521,2375-2376,3306,3389,5432,6379,8080,8443,9200,27017", "ports/ranges")
	concurrency := fs.Int("c", 200, "concurrent TCP connections per host")
	hostConcurrency := fs.Int("host-c", 4, "hosts scanned concurrently")
	timeout := fs.Duration("timeout", 800*time.Millisecond, "per-port timeout")
	outBase := fs.String("o", "", "output path without extension")
	rulesDir := fs.String("rules", "rules", "path to YAML rules directory")
	vulnScan := fs.Bool("vuln", true, "enable local vulnerability intelligence matching")
	vulnDBPath := fs.String("vulndb", vulndb.DefaultPath(), "path to SQLite vulnerability intelligence database")
	discover := fs.Bool("discover", true, "run TCP host discovery when scanning multiple targets")
	discoveryPortsSpec := fs.String("discover-ports", "22,80,443,445,3389,8080", "ports used for TCP host discovery")
	discoveryTimeout := fs.Duration("discover-timeout", 300*time.Millisecond, "timeout for each discovery connection")
	discoveryConcurrency := fs.Int("discover-c", 64, "concurrent host discovery workers")
	maxHosts := fs.Int("max-hosts", 4096, "maximum number of expanded targets")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: abslscan [options] <target|CIDR> [target ...]\n       abslscan db <init|update|watch|status|search> [options]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}

	started := time.Now()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	targets, err := targetset.Expand(fs.Args(), *maxHosts)
	fatalIf("target error", err, 2)
	ports, err := scanner.ParsePorts(*portsSpec)
	fatalIf("port error", err, 2)
	discoveryPorts, err := scanner.ParsePorts(*discoveryPortsSpec)
	fatalIf("discovery port error", err, 2)
	ruleEngine, err := rules.Load(*rulesDir)
	fatalIf("rule loading error", err, 1)

	var vulnEngine *vuln.Engine
	if *vulnScan {
		vulnEngine, err = vuln.Open(*vulnDBPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: vulnerability intelligence disabled: %v\n", err)
			fmt.Fprintln(os.Stderr, "         initialize it with: abslscan db init && abslscan db update")
		} else {
			defer vulnEngine.Close()
		}
	}

	targetSpec := strings.Join(fs.Args(), ",")
	liveTargets := append([]string(nil), targets...)
	if *discover && len(targets) > 1 {
		fmt.Printf("\033[1;36mABSL RECON\033[0m v%s\n", version)
		fmt.Printf("Target expansion: %d hosts\n", len(targets))
		fmt.Printf("Discovery: TCP ports %s | workers %d | timeout %s\n", *discoveryPortsSpec, *discoveryConcurrency, *discoveryTimeout)
		discoveryStarted := time.Now()
		liveTargets = discovery.Discover(ctx, targets, discovery.Config{
			Ports: discoveryPorts, Timeout: *discoveryTimeout, Concurrency: *discoveryConcurrency,
		})
		fmt.Printf("Discovery complete: %d/%d hosts responsive in %s\n\n", len(liveTargets), len(targets), time.Since(discoveryStarted).Round(time.Millisecond))
		if len(liveTargets) == 0 {
			fmt.Println("No responsive hosts found on the discovery ports.")
			fmt.Println("Use -discover=false to force scanning every expanded target.")
			return
		}
	}
	if ctx.Err() != nil {
		os.Exit(130)
	}
	if *hostConcurrency < 1 {
		*hostConcurrency = 1
	}
	if *hostConcurrency > len(liveTargets) {
		*hostConcurrency = len(liveTargets)
	}

	totalPorts := len(liveTargets) * len(ports)
	base := reportBase(targetSpec, *outBase)
	events := make(chan event.Event, 8192)
	renderer := terminal.New(terminal.Config{
		TargetSpec: targetSpec, Hosts: len(liveTargets), PortsPerHost: len(ports), Total: totalPorts,
		Workers: *concurrency, HostWorkers: *hostConcurrency, Rules: ruleEngine.Count(), Version: version,
	})
	renderer.PrintHeader()
	renderDone := make(chan struct{})
	go func() { renderer.Run(events); close(renderDone) }()

	scanStarted := time.Now()
	hostJobs := make(chan string)
	hostResults := make(chan hostResult)
	var wg sync.WaitGroup
	for i := 0; i < *hostConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostJobs {
				s := scanner.New(scanner.Config{
					Target: host, Ports: ports, Concurrency: *concurrency, Timeout: *timeout,
					Rules: ruleEngine, Vulns: vulnEngine, Events: events,
				})
				services, err := s.Run(ctx)
				select {
				case hostResults <- hostResult{services: services, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(hostJobs)
		for _, host := range liveTargets {
			select {
			case hostJobs <- host:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(hostResults) }()

	var services []model.Service
	var scanErr error
	for result := range hostResults {
		services = append(services, result.services...)
		if result.err != nil && scanErr == nil {
			scanErr = result.err
		}
	}
	close(events)
	<-renderDone
	ended := time.Now()
	sort.Slice(services, func(i, j int) bool {
		if services[i].Target == services[j].Target {
			return services[i].Port < services[j].Port
		}
		return services[i].Target < services[j].Target
	})
	var findings []model.Finding
	for _, service := range services {
		findings = append(findings, service.Findings...)
	}
	r := model.Report{
		Tool: "ABSL Recon", Version: version, Target: targetSpec, Targets: targets, LiveTargets: liveTargets,
		StartedAt: started.UTC(), EndedAt: ended.UTC(), Hosts: len(liveTargets), Scanned: totalPorts,
		Services: services, Findings: findings,
	}
	if err := report.WriteAll(base, r); err != nil {
		fmt.Fprintf(os.Stderr, "report error: %v\n", err)
		os.Exit(1)
	}
	renderer.PrintSummary(time.Since(scanStarted), base)
	if scanErr != nil {
		if scanErr == context.Canceled {
			fmt.Fprintln(os.Stderr, "\nscan interrupted")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "scan error:", scanErr)
		os.Exit(1)
	}
}

func runDB(args []string) {
	if len(args) == 0 {
		printDBUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		runDBInit(args[1:])
	case "update":
		runDBUpdate(args[1:])
	case "watch":
		runDBWatch(args[1:])
	case "status":
		runDBStatus(args[1:])
	case "search":
		runDBSearch(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown db command %q\n", args[0])
		printDBUsage()
		os.Exit(2)
	}
}

func printDBUsage() {
	fmt.Println(`ABSL Vulnerability Intelligence DB

Usage:
  abslscan db init [--db PATH]
  abslscan db update [options]
  abslscan db watch --interval 1h [options]
  abslscan db status [--db PATH]
  abslscan db search [--db PATH] <CVE-ID|text>

Providers:
  cve       official CVE List V5 via CVEProject/cvelistV5
  kev       CISA Known Exploited Vulnerabilities
  epss      FIRST EPSS daily scores
  nvd       NVD CVSS/CPE/CWE enrichment
  opencti   optional OpenCTI TAXII 2.1 vulnerability collection`)
}

func runDBInit(args []string) {
	fs := flag.NewFlagSet("db init", flag.ExitOnError)
	dbPath := fs.String("db", vulndb.DefaultPath(), "database path")
	_ = fs.Parse(args)
	store, err := vulndb.Open(*dbPath)
	fatalIf("database init failed", err, 1)
	defer store.Close()
	count, _ := store.CountCVEs(context.Background())
	fmt.Printf("ABSL Vulnerability Intelligence DB initialized\nDatabase: %s\nCVEs: %d\n", store.Path(), count)
}

func addFeedFlags(fs *flag.FlagSet) feedFlags {
	return feedFlags{
		dbPath:            fs.String("db", vulndb.DefaultPath(), "database path"),
		cacheDir:          fs.String("cache", "", "feed cache directory"),
		only:              fs.String("only", "", "comma-separated providers: cve,kev,epss,nvd,opencti"),
		nvdAPIKey:         fs.String("nvd-key", os.Getenv("NVD_API_KEY"), "NVD API key (or NVD_API_KEY)"),
		nvdFull:           fs.Bool("nvd-full", false, "perform full NVD enrichment instead of incremental/recent sync"),
		openCTIURL:        fs.String("opencti-url", os.Getenv("ABSL_OPENCTI_URL"), "OpenCTI base or TAXII root URL"),
		openCTIToken:      fs.String("opencti-token", os.Getenv("ABSL_OPENCTI_TOKEN"), "OpenCTI bearer token"),
		openCTICollection: fs.String("opencti-collection", os.Getenv("ABSL_OPENCTI_COLLECTION"), "OpenCTI TAXII collection ID"),
		openCTIInsecure:   fs.Bool("opencti-insecure", envBool("ABSL_OPENCTI_INSECURE"), "disable TLS verification for OpenCTI (lab only)"),
	}
}

func (f feedFlags) options(store *vulndb.Store, watch bool) feeds.Options {
	cache := *f.cacheDir
	if cache == "" {
		cache = filepath.Join(filepath.Dir(store.Path()), "feeds")
	}
	return feeds.Options{
		CacheDir: cache, NVDAPIKey: *f.nvdAPIKey, NVDFull: *f.nvdFull,
		OpenCTIURL: *f.openCTIURL, OpenCTIToken: *f.openCTIToken,
		OpenCTICollection: *f.openCTICollection, OpenCTIInsecureTLS: *f.openCTIInsecure,
		WatchMode: watch,
		Log:       func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	}
}

func runDBUpdate(args []string) {
	fs := flag.NewFlagSet("db update", flag.ExitOnError)
	ff := addFeedFlags(fs)
	_ = fs.Parse(args)
	store, err := vulndb.Open(*ff.dbPath)
	fatalIf("database open failed", err, 1)
	defer store.Close()
	fmt.Printf("ABSL Vulnerability Intelligence Update\nDatabase: %s\n\n", store.Path())
	results, syncErr := feeds.DefaultManager().Sync(context.Background(), store, ff.options(store, false), feeds.ParseOnly(*ff.only))
	printSyncResults(results)
	if syncErr != nil {
		fmt.Fprintln(os.Stderr, "update completed with errors:", syncErr)
		os.Exit(1)
	}
}

func runDBWatch(args []string) {
	fs := flag.NewFlagSet("db watch", flag.ExitOnError)
	ff := addFeedFlags(fs)
	interval := fs.Duration("interval", time.Hour, "feed refresh interval")
	_ = fs.Parse(args)
	if *interval < time.Minute {
		fmt.Fprintln(os.Stderr, "interval must be at least 1m")
		os.Exit(2)
	}
	store, err := vulndb.Open(*ff.dbPath)
	fatalIf("database open failed", err, 1)
	defer store.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	manager := feeds.DefaultManager()
	run := func() {
		fmt.Printf("\n[%s] vulnerability feed refresh\n", time.Now().Format(time.RFC3339))
		results, err := manager.Sync(ctx, store, ff.options(store, true), feeds.ParseOnly(*ff.only))
		printSyncResults(results)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "refresh completed with errors:", err)
		}
	}
	run()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	fmt.Printf("Watching feeds every %s. Ctrl+C to stop.\n", *interval)
	for {
		select {
		case <-ctx.Done():
			fmt.Println("feed watcher stopped")
			return
		case <-ticker.C:
			run()
		}
	}
}

func runDBStatus(args []string) {
	fs := flag.NewFlagSet("db status", flag.ExitOnError)
	dbPath := fs.String("db", vulndb.DefaultPath(), "database path")
	_ = fs.Parse(args)
	store, err := vulndb.OpenExisting(*dbPath)
	fatalIf("database open failed", err, 1)
	defer store.Close()
	ctx := context.Background()
	count, err := store.CountCVEs(ctx)
	fatalIf("database query failed", err, 1)
	states, err := store.FeedStates(ctx)
	fatalIf("feed state query failed", err, 1)
	fmt.Printf("ABSL Vulnerability Intelligence DB\nDatabase: %s\nCVEs: %d\n\n", store.Path(), count)
	fmt.Printf("%-12s %-25s %-9s %-10s %s\n", "SOURCE", "LAST UPDATE", "STATUS", "RECORDS", "MESSAGE")
	for _, st := range states {
		fmt.Printf("%-12s %-25s %-9s %-10d %s\n", st.Name, st.LastUpdate, st.Status, st.Records, st.Message)
	}
}

func runDBSearch(args []string) {
	fs := flag.NewFlagSet("db search", flag.ExitOnError)
	dbPath := fs.String("db", vulndb.DefaultPath(), "database path")
	limit := fs.Int("limit", 20, "maximum results")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: abslscan db search [--db PATH] <CVE-ID|text>")
		os.Exit(2)
	}
	store, err := vulndb.OpenExisting(*dbPath)
	fatalIf("database open failed", err, 1)
	defer store.Close()
	query := strings.Join(fs.Args(), " ")
	items, err := store.Search(context.Background(), query, *limit)
	fatalIf("database search failed", err, 1)
	if len(items) == 0 {
		fmt.Println("No matching CVEs.")
		return
	}
	for _, item := range items {
		fmt.Printf("\n%s\n%s\n", item.CVEID, strings.Repeat("-", len(item.CVEID)))
		if item.Title != "" {
			fmt.Println(item.Title)
		}
		fmt.Printf("Status: %s\nCVSS: %.1f %s\nEPSS: %.4f (%.2f%% percentile)\nKEV: %t\n", item.Status, item.CVSSScore, item.Severity, item.EPSSScore, item.EPSSPercentile*100, item.KEV)
		if item.CWE != "" {
			fmt.Println("CWE:", item.CWE)
		}
		if item.KEVRansomware != "" {
			fmt.Println("Ransomware use:", item.KEVRansomware)
		}
		if item.Description != "" {
			fmt.Println("Description:", compact(item.Description, 500))
		}
		if len(item.Products) > 0 {
			fmt.Println("Affected products:")
			for _, p := range item.Products {
				fmt.Printf("  - %s / %s %s\n", p.Vendor, p.Product, productRange(p))
			}
		}
		if len(item.Intel) > 0 {
			fmt.Println("Threat intelligence:")
			for _, intel := range item.Intel {
				fmt.Printf("  - %s confidence=%d labels=%s\n", intel.Source, intel.Confidence, intel.Labels)
			}
		}
	}
}

func printSyncResults(results []feeds.Result) {
	fmt.Println()
	fmt.Printf("%-12s %-10s %-10s %s\n", "SOURCE", "RECORDS", "TIME", "RESULT")
	for _, r := range results {
		status := r.Message
		if r.Skipped {
			status = "SKIPPED: " + status
		}
		fmt.Printf("%-12s %-10d %-10s %s\n", r.Provider, r.Records, r.Duration.Round(time.Millisecond), status)
	}
}

func productRange(p vulndb.AffectedProduct) string {
	if p.ExactVersion != "" {
		return "=" + p.ExactVersion
	}
	var parts []string
	if p.VersionStart != "" {
		op := ">"
		if p.StartInclusive {
			op = ">="
		}
		parts = append(parts, op+p.VersionStart)
	}
	if p.VersionEnd != "" {
		op := "<"
		if p.EndInclusive {
			op = "<="
		}
		parts = append(parts, op+p.VersionEnd)
	}
	if len(parts) == 0 {
		return "all versions"
	}
	return strings.Join(parts, " ")
}

func fatalIf(prefix string, err error, code int) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, prefix+":", err)
	os.Exit(code)
}

func envBool(name string) bool {
	v, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(name)))
	return v
}

func compact(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= max {
		return value
	}
	return value[:max-3] + "..."
}

func reportBase(targetSpec, configured string) string {
	if configured != "" {
		return configured
	}
	stamp := time.Now().Format("20060102-150405")
	safeTarget := strings.NewReplacer(":", "_", "/", "_", "\\", "_", ",", "_", " ", "_").Replace(targetSpec)
	if len(safeTarget) > 80 {
		safeTarget = "multi-target"
	}
	return filepath.Join("reports", safeTarget+"-"+stamp)
}
EOF_cmd_abslscan_main_go

cat > README.md <<'EOF_README'
# ABSL Recon

ABSL Recon is an extensible Go-based network reconnaissance and vulnerability intelligence framework.

## v0.7.0 highlights

- Concurrent TCP and multi-target/CIDR scanning
- Active service fingerprinting
- YAML security rules
- SQLite vulnerability intelligence database
- Official CVE List V5 ingestion
- CISA KEV enrichment
- FIRST EPSS enrichment
- NVD CVSS/CPE/CWE enrichment
- Optional OpenCTI TAXII 2.1 ingestion
- Risk-based CVE prioritization
- Automatic feed watch mode
- JSON, CSV, HTML and SARIF reports

## Vulnerability database

```bash
./bin/abslscan db init
./bin/abslscan db update
./bin/abslscan db status
./bin/abslscan db search CVE-2024-6387
./bin/abslscan db watch --interval 1h
```

For a full NVD enrichment pass:

```bash
export NVD_API_KEY=your-key
./bin/abslscan db update --nvd-full
```

The canonical CVE corpus comes from the official CVE List V5 repository. NVD is enrichment, so a full NVD pass is optional for the initial CVE corpus.

## OpenCTI TAXII 2.1

```bash
export ABSL_OPENCTI_URL=https://opencti.example.local/taxii2/root
export ABSL_OPENCTI_COLLECTION=collection-uuid
export ABSL_OPENCTI_TOKEN=token
./bin/abslscan db update --only opencti
```

For an isolated lab with a self-signed certificate only:

```bash
export ABSL_OPENCTI_INSECURE=true
```

## Build

```bash
go test ./...
go build -trimpath -ldflags="-s -w" -o bin/abslscan ./cmd/abslscan
```

## Authorization

Use ABSL Recon only against systems and networks you own or are explicitly authorized to assess.
EOF_README

cat > contrib/systemd/absl-recon-db.service <<'EOF_SERVICE'
[Unit]
Description=ABSL Recon vulnerability intelligence feed watcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/abslscan db watch --interval 1h
EnvironmentFile=-%h/.config/absl-recon/env
Restart=on-failure
RestartSec=15

[Install]
WantedBy=default.target
EOF_SERVICE

cat > contrib/absl-recon.env.example <<'EOF_ENV'
NVD_API_KEY=
ABSL_OPENCTI_URL=
ABSL_OPENCTI_COLLECTION=
ABSL_OPENCTI_TOKEN=
ABSL_OPENCTI_INSECURE=false
EOF_ENV

python3 - <<'PYTERM'
from pathlib import Path
p = Path("internal/terminal/renderer.go")
s = p.read_text()
needle = r'''		fmt.Printf(
			"      %-15s %s[%s]%s %s - %s\n",
			ev.Finding.Target,
			severityColor(
				severity,
			),
			strings.ToUpper(
				severity,
			),
			reset,
			ev.Finding.ID,
			ev.Finding.Title,
		)
'''
replacement = needle + r'''
		if strings.HasPrefix(strings.ToUpper(ev.Finding.ID), "CVE-") {
			kev := "no"
			if ev.Finding.KEV {
				kev = "YES"
			}
			fmt.Printf(
				"      %-15s %sRISK%s %.1f | CVSS %.1f | EPSS %.2f%% | KEV %s | INTEL %d\n",
				"",
				cyan,
				reset,
				ev.Finding.RiskScore,
				ev.Finding.CVSSScore,
				ev.Finding.EPSSScore*100,
				kev,
				len(ev.Finding.ThreatIntel),
			)
		}
'''
if needle not in s:
    raise SystemExit("terminal renderer patch point not found")
p.write_text(s.replace(needle, replacement, 1))
PYTERM

sed -i 's/ABSL-Recon\/0\.[0-9]/ABSL-Recon\/0.7/g' internal/fingerprint/fingerprint.go
rm -rf vulndb
go get modernc.org/sqlite
gofmt -w .
go mod tidy
go test ./...
mkdir -p bin
go build -trimpath -ldflags="-s -w" -o bin/abslscan ./cmd/abslscan
./bin/abslscan db init
echo
echo '========================================'
echo 'ABSL Recon v0.7.0 build complete'
echo '========================================'
echo
./bin/abslscan db status
