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
