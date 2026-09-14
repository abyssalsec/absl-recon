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
