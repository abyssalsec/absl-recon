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
