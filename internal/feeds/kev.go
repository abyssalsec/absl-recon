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
