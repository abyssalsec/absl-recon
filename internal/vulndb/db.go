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
