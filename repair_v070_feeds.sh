#!/usr/bin/env bash
set -euo pipefail

if [ ! -f go.mod ] || [ ! -d internal/feeds ]; then
  echo "Run this from the absl-recon repository root" >&2
  exit 1
fi

cat > internal/feeds/feeds.go <<'EOF_FEEDS'
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
			state, _ := store.FeedState(ctx, provider.Name())
			state.Name = provider.Name()
			state.Status = "error"
			if res.Records > 0 {
				state.Records = res.Records
			}
			state.Message = err.Error()
			_ = store.SetFeedState(ctx, state)

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
EOF_FEEDS

cat > internal/feeds/cve.go <<'EOF_CVE'
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

	valid, err := validCVERepo(ctx, repoDir)
	if err != nil {
		return Result{}, err
	}

	if !valid {
		first = true
		if err := os.RemoveAll(repoDir); err != nil {
			return Result{}, fmt.Errorf("remove invalid CVE cache: %w", err)
		}
		if _, err := exec.LookPath("git"); err != nil {
			return Result{}, fmt.Errorf("git is required for CVE List V5 sync: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(repoDir), 0o755); err != nil {
			return Result{}, err
		}

		cmd := exec.CommandContext(
			ctx,
			"git",
			"clone",
			"--depth",
			"1",
			"--single-branch",
			"--branch",
			"main",
			cveRepoURL,
			repoDir,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			_ = os.RemoveAll(repoDir)
			return Result{}, fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	} else {
		oldHead, err = gitOutput(ctx, repoDir, "rev-parse", "--verify", "HEAD")
		if err != nil {
			return Result{}, err
		}

		cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "pull", "--ff-only")
		if output, err := cmd.CombinedOutput(); err != nil {
			return Result{}, fmt.Errorf("git pull failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}

	newHead, err := gitOutput(ctx, repoDir, "rev-parse", "--verify", "HEAD")
	if err != nil {
		// A cache can be left with a .git directory but without a usable HEAD
		// after an interrupted clone. Remove it so the next run can recover.
		_ = os.RemoveAll(repoDir)
		return Result{}, fmt.Errorf("CVE List cache has no valid HEAD and was removed: %w", err)
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

func validCVERepo(ctx context.Context, repoDir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "--verify", "HEAD")
	if err := cmd.Run(); err != nil {
		return false, nil
	}
	return true, nil
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
EOF_CVE

cat > internal/feeds/nvd.go <<'EOF_NVD'
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

	if opts.NVDFull {
		resume := 0

		if raw := strings.TrimSpace(os.Getenv("ABSL_NVD_START_INDEX")); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 0 {
				return Result{}, fmt.Errorf("invalid ABSL_NVD_START_INDEX %q", raw)
			}
			resume = value
		} else if strings.HasPrefix(state.Cursor, "full:") {
			raw := strings.TrimPrefix(state.Cursor, "full:")
			if value, err := strconv.Atoi(raw); err == nil && value >= 0 {
				resume = value
			}
		}

		if resume > 0 && opts.Log != nil {
			opts.Log("[nvd] resuming full enrichment at startIndex=%d", resume)
		}

		imported, total, err := syncNVDWindow(
			ctx,
			store,
			opts,
			nil,
			nil,
			resume,
			func(next, total int) error {
				return store.SetFeedState(ctx, vulndb.FeedState{
					Name:       "nvd",
					LastUpdate: state.LastUpdate,
					Status:     "partial",
					Records:    next,
					Cursor:     fmt.Sprintf("full:%d", next),
					Message:    fmt.Sprintf("full NVD enrichment %d/%d", next, total),
				})
			},
		)
		if err != nil {
			return Result{Records: imported}, err
		}

		if err := store.SetFeedState(ctx, vulndb.FeedState{
			Name:       "nvd",
			LastUpdate: end.Format(time.RFC3339),
			Status:     "ok",
			Records:    total,
			Cursor:     "",
			Message:    "full NVD enrichment",
		}); err != nil {
			return Result{Records: imported}, err
		}

		return Result{Records: imported, Message: "full NVD enrichment"}, nil
	}

	var start time.Time
	if state.LastUpdate != "" && state.Status == "ok" {
		if t, err := time.Parse(time.RFC3339, state.LastUpdate); err == nil {
			start = t.Add(-5 * time.Minute)
		}
	}
	if start.IsZero() {
		start = end.Add(-120 * 24 * time.Hour)
	}

	count := 0
	cursor := start
	for cursor.Before(end) {
		windowEnd := cursor.Add(119 * 24 * time.Hour)
		if windowEnd.After(end) {
			windowEnd = end
		}

		n, _, err := syncNVDWindow(
			ctx,
			store,
			opts,
			&cursor,
			&windowEnd,
			0,
			nil,
		)
		count += n
		if err != nil {
			return Result{Records: count}, err
		}

		cursor = windowEnd.Add(time.Second)
	}

	if err := store.SetFeedState(ctx, vulndb.FeedState{
		Name:       "nvd",
		LastUpdate: end.Format(time.RFC3339),
		Status:     "ok",
		Records:    count,
		Cursor:     "",
		Message:    "incremental enrichment",
	}); err != nil {
		return Result{Records: count}, err
	}

	return Result{Records: count, Message: "incremental enrichment"}, nil
}

func syncNVDWindow(
	ctx context.Context,
	store *vulndb.Store,
	opts Options,
	start, end *time.Time,
	initialIndex int,
	progress func(next, total int) error,
) (int, int, error) {
	startIndex := initialIndex
	total := -1
	imported := 0

	for total < 0 || startIndex < total {
		endpoint, err := buildNVDURL(startIndex, start, end)
		if err != nil {
			return imported, total, err
		}

		doc, err := fetchNVDPage(ctx, opts, endpoint, startIndex)
		if err != nil {
			return imported, total, err
		}

		total = doc.TotalResults
		batch := make([]vulndb.CVERecord, 0, len(doc.Vulnerabilities))
		for _, item := range doc.Vulnerabilities {
			batch = append(batch, convertNVD(item.CVE))
		}

		if err := store.UpsertCVEs(ctx, batch); err != nil {
			return imported, total, err
		}

		imported += len(batch)
		nextIndex := doc.StartIndex + doc.ResultsPerPage
		if nextIndex <= startIndex && len(doc.Vulnerabilities) > 0 {
			nextIndex = startIndex + len(doc.Vulnerabilities)
		}
		startIndex = nextIndex

		if progress != nil {
			if err := progress(startIndex, total); err != nil {
				return imported, total, err
			}
		}

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
		if err := sleepContext(ctx, delay); err != nil {
			return imported, total, err
		}
	}

	return imported, total, nil
}

func fetchNVDPage(
	ctx context.Context,
	opts Options,
	endpoint string,
	startIndex int,
) (nvdResponse, error) {
	const maxAttempts = 7

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := newRequest(ctx, http.MethodGet, endpoint)
		if err != nil {
			return nvdResponse{}, err
		}
		if opts.NVDAPIKey != "" {
			req.Header.Set("apiKey", opts.NVDAPIKey)
		}

		resp, err := httpClient(false, 3*time.Minute).Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var doc nvdResponse
			decodeErr := json.NewDecoder(resp.Body).Decode(&doc)
			resp.Body.Close()
			if decodeErr != nil {
				lastErr = fmt.Errorf("NVD response decode failed at startIndex=%d: %w", startIndex, decodeErr)
			} else {
				return doc, nil
			}
		} else if err != nil {
			lastErr = fmt.Errorf("NVD request failed at startIndex=%d: %w", startIndex, err)
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			status := resp.StatusCode
			retryAfter := resp.Header.Get("Retry-After")
			resp.Body.Close()

			if status != http.StatusTooManyRequests && status < 500 {
				return nvdResponse{}, fmt.Errorf(
					"NVD API returned HTTP %d at startIndex=%d: %s",
					status,
					startIndex,
					strings.TrimSpace(string(body)),
				)
			}

			lastErr = fmt.Errorf("NVD API returned HTTP %d at startIndex=%d", status, startIndex)
			if attempt < maxAttempts {
				delay := retryDelay(attempt, retryAfter)
				if opts.Log != nil {
					opts.Log(
						"[nvd] transient HTTP %d at %d, retry %d/%d in %s",
						status,
						startIndex,
						attempt,
						maxAttempts,
						delay,
					)
				}
				if err := sleepContext(ctx, delay); err != nil {
					return nvdResponse{}, err
				}
				continue
			}
		}

		if attempt < maxAttempts {
			delay := retryDelay(attempt, "")
			if opts.Log != nil {
				opts.Log(
					"[nvd] transient request failure at %d, retry %d/%d in %s",
					startIndex,
					attempt,
					maxAttempts,
					delay,
				)
			}
			if err := sleepContext(ctx, delay); err != nil {
				return nvdResponse{}, err
			}
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("NVD request failed at startIndex=%d", startIndex)
	}
	return nvdResponse{}, lastErr
}

func retryDelay(attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && seconds > 0 {
			d := time.Duration(seconds) * time.Second
			if d > 2*time.Minute {
				d = 2 * time.Minute
			}
			return d
		}
		if when, err := http.ParseTime(retryAfter); err == nil {
			d := time.Until(when)
			if d > 0 {
				if d > 2*time.Minute {
					d = 2 * time.Minute
				}
				return d
			}
		}
	}

	seconds := 5 << (attempt - 1)
	if seconds > 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
EOF_NVD

gofmt -w internal/feeds/feeds.go internal/feeds/cve.go internal/feeds/nvd.go
go mod tidy
go test ./...
mkdir -p bin
go build -trimpath -ldflags="-s -w" -o bin/abslscan ./cmd/abslscan

echo
echo "ABSL Recon v0.7.0 feed recovery patch installed."
echo "CVE cache now self-heals if a previous clone left .git without a valid HEAD."
echo "NVD now retries transient 429/5xx responses and full sync checkpoints its startIndex."
echo
