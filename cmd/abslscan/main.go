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
