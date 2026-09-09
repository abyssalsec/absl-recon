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
	"syscall"
	"time"

	"github.com/abyssalsec/absl-recon/internal/event"
	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/report"
	"github.com/abyssalsec/absl-recon/internal/rules"
	"github.com/abyssalsec/absl-recon/internal/scanner"
	"github.com/abyssalsec/absl-recon/internal/terminal"
)

const version = "0.3.0"

func main() {
	portsSpec :=
		flag.String(
			"p",
			"21-25,53,80,110,143,443,445,"+
				"465,587,993,995,"+
				"1433,1521,"+
				"2375-2376,"+
				"3306,3389,5432,6379,"+
				"8080,8443,9200,27017",
			"ports/ranges",
		)

	concurrency :=
		flag.Int(
			"c",
			200,
			"concurrent TCP connection attempts",
		)

	timeout :=
		flag.Duration(
			"timeout",
			800*time.Millisecond,
			"per-port timeout",
		)

	outBase :=
		flag.String(
			"o",
			"",
			"output path without extension",
		)

	rulesDir :=
		flag.String(
			"rules",
			"rules",
			"path to YAML rules directory",
		)

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(
			os.Stderr,
			"usage: abslscan [options] <target>\n",
		)

		flag.PrintDefaults()

		os.Exit(2)
	}

	target :=
		flag.Arg(0)

	ports, err :=
		scanner.ParsePorts(
			*portsSpec,
		)

	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"error:",
			err,
		)

		os.Exit(2)
	}

	ruleEngine, err :=
		rules.Load(
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

	base :=
		reportBase(
			target,
			*outBase,
		)

	started :=
		time.Now()

	ctx, cancel :=
		signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)

	defer cancel()

	events :=
		make(
			chan event.Event,
			4096,
		)

	renderer :=
		terminal.New(
			terminal.Config{
				Target:  target,
				Total:   len(ports),
				Workers: *concurrency,
				Rules:   ruleEngine.Count(),
				Version: version,
			},
		)

	renderer.PrintHeader()

	renderDone :=
		make(chan struct{})

	go func() {
		renderer.Run(events)

		close(renderDone)
	}()

	s :=
		scanner.New(
			scanner.Config{
				Target:      target,
				Ports:       ports,
				Concurrency: *concurrency,
				Timeout:     *timeout,
				Rules:       ruleEngine,
				Events:      events,
			},
		)

	services, scanErr :=
		s.Run(ctx)

	close(events)

	<-renderDone

	ended :=
		time.Now()

	sort.Slice(
		services,
		func(
			i int,
			j int,
		) bool {

			return services[i].Port <
				services[j].Port
		},
	)

	var findings []model.Finding

	for _, service := range services {

		findings =
			append(
				findings,
				service.Findings...,
			)
	}

	r :=
		model.Report{
			Tool:      "ABSL Recon",
			Version:   version,
			Target:    target,
			StartedAt: started.UTC(),
			EndedAt:   ended.UTC(),
			Scanned:   len(ports),
			Services:  services,
			Findings:  findings,
		}

	if err :=
		report.WriteAll(
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
		ended.Sub(started),
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
	target string,
	configured string,
) string {
	if configured != "" {
		return configured
	}

	stamp :=
		time.Now().
			Format(
				"20060102-150405",
			)

	safeTarget :=
		strings.NewReplacer(
			":",
			"_",
			"/",
			"_",
			"\\",
			"_",
		).
			Replace(
				target,
			)

	return filepath.Join(
		"reports",
		safeTarget+
			"-"+
			stamp,
	)
}
