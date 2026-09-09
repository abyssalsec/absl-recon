package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abyssalsec/absl-recon/internal/discovery"
	"github.com/abyssalsec/absl-recon/internal/event"
	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/report"
	"github.com/abyssalsec/absl-recon/internal/rules"
	"github.com/abyssalsec/absl-recon/internal/scanner"
	targetset "github.com/abyssalsec/absl-recon/internal/target"
	"github.com/abyssalsec/absl-recon/internal/terminal"
)

const version = "0.5.0"

type hostResult struct {
	services []model.Service
	err      error
}

func main() {
	portsSpec := flag.String(
		"p",
		"21-25,53,80,110,143,443,445,"+
			"465,587,993,995,"+
			"1433,1521,"+
			"2375-2376,"+
			"3306,3389,5432,6379,"+
			"8080,8443,9200,27017",
		"ports/ranges",
	)

	concurrency := flag.Int(
		"c",
		200,
		"concurrent TCP connections per host",
	)

	hostConcurrency := flag.Int(
		"host-c",
		4,
		"hosts scanned concurrently",
	)

	timeout := flag.Duration(
		"timeout",
		800*time.Millisecond,
		"per-port timeout",
	)

	outBase := flag.String(
		"o",
		"",
		"output path without extension",
	)

	rulesDir := flag.String(
		"rules",
		"rules",
		"path to YAML rules directory",
	)

	discover := flag.Bool(
		"discover",
		true,
		"run TCP host discovery when scanning multiple targets",
	)

	discoveryPortsSpec := flag.String(
		"discover-ports",
		"22,80,443,445,3389,8080",
		"ports used for TCP host discovery",
	)

	discoveryTimeout := flag.Duration(
		"discover-timeout",
		300*time.Millisecond,
		"timeout for each discovery connection",
	)

	discoveryConcurrency := flag.Int(
		"discover-c",
		64,
		"concurrent host discovery workers",
	)

	maxHosts := flag.Int(
		"max-hosts",
		4096,
		"maximum number of expanded targets",
	)

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(
			os.Stderr,
			"usage: abslscan [options] <target|CIDR> [target ...]\n",
		)

		flag.PrintDefaults()

		os.Exit(2)
	}

	started := time.Now()

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)

	defer cancel()

	targets, err := targetset.Expand(
		flag.Args(),
		*maxHosts,
	)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"target error:",
			err,
		)

		os.Exit(2)
	}

	ports, err := scanner.ParsePorts(
		*portsSpec,
	)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"port error:",
			err,
		)

		os.Exit(2)
	}

	discoveryPorts, err := scanner.ParsePorts(
		*discoveryPortsSpec,
	)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"discovery port error:",
			err,
		)

		os.Exit(2)
	}

	ruleEngine, err := rules.Load(
		*rulesDir,
	)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"rule loading error:",
			err,
		)

		os.Exit(1)
	}

	targetSpec := strings.Join(
		flag.Args(),
		",",
	)

	liveTargets := append(
		[]string(nil),
		targets...,
	)

	if *discover &&
		len(targets) > 1 {

		fmt.Printf(
			"\033[1;36mABSL RECON\033[0m v%s\n",
			version,
		)

		fmt.Printf(
			"Target expansion: %d hosts\n",
			len(targets),
		)

		fmt.Printf(
			"Discovery: TCP ports %s | workers %d | timeout %s\n",
			*discoveryPortsSpec,
			*discoveryConcurrency,
			*discoveryTimeout,
		)

		discoveryStarted := time.Now()

		liveTargets = discovery.Discover(
			ctx,
			targets,
			discovery.Config{
				Ports: discoveryPorts,

				Timeout: *discoveryTimeout,

				Concurrency: *discoveryConcurrency,
			},
		)

		fmt.Printf(
			"Discovery complete: %d/%d hosts responsive in %s\n\n",
			len(liveTargets),
			len(targets),
			time.Since(
				discoveryStarted,
			).Round(
				time.Millisecond,
			),
		)

		if len(liveTargets) == 0 {
			fmt.Println(
				"No responsive hosts found on the discovery ports.",
			)

			fmt.Println(
				"Use -discover=false to force scanning every expanded target.",
			)

			return
		}
	}

	if ctx.Err() != nil {
		os.Exit(130)
	}

	if *hostConcurrency < 1 {
		*hostConcurrency = 1
	}

	if *hostConcurrency >
		len(liveTargets) {

		*hostConcurrency =
			len(liveTargets)
	}

	totalPorts :=
		len(liveTargets) *
			len(ports)

	base := reportBase(
		targetSpec,
		*outBase,
	)

	events := make(
		chan event.Event,
		8192,
	)

	renderer := terminal.New(
		terminal.Config{
			TargetSpec: targetSpec,

			Hosts: len(liveTargets),

			PortsPerHost: len(ports),

			Total: totalPorts,

			Workers: *concurrency,

			HostWorkers: *hostConcurrency,

			Rules: ruleEngine.Count(),

			Version: version,
		},
	)

	renderer.PrintHeader()

	renderDone := make(
		chan struct{},
	)

	go func() {
		renderer.Run(events)
		close(renderDone)
	}()

	scanStarted := time.Now()

	hostJobs := make(
		chan string,
	)

	hostResults := make(
		chan hostResult,
	)

	var wg sync.WaitGroup

	for i := 0; i < *hostConcurrency; i++ {

		wg.Add(1)

		go func() {
			defer wg.Done()

			for host := range hostJobs {
				s := scanner.New(
					scanner.Config{
						Target: host,

						Ports: ports,

						Concurrency: *concurrency,

						Timeout: *timeout,

						Rules: ruleEngine,

						Events: events,
					},
				)

				services, err := s.Run(ctx)

				select {
				case hostResults <- hostResult{
					services: services,

					err: err,
				}:

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

	go func() {
		wg.Wait()
		close(hostResults)
	}()

	var services []model.Service
	var scanErr error

	for result := range hostResults {
		services = append(
			services,
			result.services...,
		)

		if result.err != nil &&
			scanErr == nil {

			scanErr =
				result.err
		}
	}

	close(events)

	<-renderDone

	ended := time.Now()

	sort.Slice(
		services,
		func(
			i int,
			j int,
		) bool {
			if services[i].Target ==
				services[j].Target {

				return services[i].Port <
					services[j].Port
			}

			return services[i].Target <
				services[j].Target
		},
	)

	var findings []model.Finding

	for _, service := range services {
		findings = append(
			findings,
			service.Findings...,
		)
	}

	r := model.Report{
		Tool: "ABSL Recon",

		Version: version,

		Target: targetSpec,

		Targets: targets,

		LiveTargets: liveTargets,

		StartedAt: started.UTC(),

		EndedAt: ended.UTC(),

		Hosts: len(liveTargets),

		Scanned: totalPorts,

		Services: services,

		Findings: findings,
	}

	if err := report.WriteAll(
		base,
		r,
	); err != nil {

		fmt.Fprintf(
			os.Stderr,
			"report error: %v\n",
			err,
		)

		os.Exit(1)
	}

	renderer.PrintSummary(
		time.Since(
			scanStarted,
		),
		base,
	)

	if scanErr != nil {
		if scanErr ==
			context.Canceled {

			fmt.Fprintln(
				os.Stderr,
				"\nscan interrupted",
			)

			os.Exit(130)
		}

		fmt.Fprintln(
			os.Stderr,
			"scan error:",
			scanErr,
		)

		os.Exit(1)
	}
}

func reportBase(
	targetSpec string,
	configured string,
) string {
	if configured != "" {
		return configured
	}

	stamp := time.Now().
		Format(
			"20060102-150405",
		)

	safeTarget := strings.NewReplacer(
		":",
		"_",
		"/",
		"_",
		"\\",
		"_",
		",",
		"_",
		" ",
		"_",
	).
		Replace(
			targetSpec,
		)

	if len(safeTarget) > 80 {
		safeTarget =
			"multi-target"
	}

	return filepath.Join(
		"reports",
		safeTarget+
			"-"+
			stamp,
	)
}
