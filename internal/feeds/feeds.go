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
