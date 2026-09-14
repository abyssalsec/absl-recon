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

	state, err := store.FeedState(ctx, "cve")
	if err != nil {
		return Result{}, err
	}

	// Retry the full baseline whenever the previous CVE import did not
	// complete successfully, even if the local Git cache is already valid.
	first := state.Cursor == "" || !strings.EqualFold(state.Status, "ok")
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
			if info.IsDir() || !isCVERecordPath(path) {
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
			if rel == "" || !isCVERecordPath(rel) {
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

func isCVERecordPath(path string) bool {
	base := strings.ToUpper(filepath.Base(path))

	return strings.HasPrefix(base, "CVE-") &&
		strings.HasSuffix(base, ".JSON")
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

	if !strings.HasPrefix(
		strings.ToUpper(raw.Metadata.CVEID),
		"CVE-",
	) {
		return vulndb.CVERecord{},
			fmt.Errorf(
				"%s: missing or invalid cveMetadata.cveId",
				path,
			)
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
