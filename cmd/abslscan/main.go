package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/report"
	"github.com/abyssalsec/absl-recon/internal/rules"
	"github.com/abyssalsec/absl-recon/internal/scanner"
)

const version = "0.2.0"

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
		"concurrent TCP connection attempts",
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

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(
			os.Stderr,
			"usage: abslscan [options] <target>\n",
		)

		flag.PrintDefaults()

		os.Exit(2)
	}

	target := flag.Arg(0)

	ports, err := scanner.ParsePorts(
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

	fmt.Println(
		"\033[1;36mABSL RECON\033[0m",
	)

	fmt.Printf(
		"Version: %s\n",
		version,
	)

	fmt.Printf(
		"Target: %s | Ports: %d | Concurrency: %d | Timeout: %s\n",
		target,
		len(ports),
		*concurrency,
		*timeout,
	)

	fmt.Printf(
		"Rules: %d loaded from %s\n",
		ruleEngine.Count(),
		*rulesDir,
	)

	fmt.Println()

	started := time.Now().UTC()

	s := scanner.New(
		scanner.Config{
			Target:      target,
			Ports:       ports,
			Concurrency: *concurrency,
			Timeout:     *timeout,
			Rules:       ruleEngine,

			OnOpen: func(svc model.Service) {
				name := svc.Name

				if name == "" {
					name = "unknown"
				}

				fmt.Printf(
					"\033[32mOPEN\033[0m  %5d/tcp  %-24s %s\n",
					svc.Port,
					name,
					truncate(
						svc.Banner,
						72,
					),
				)

				if svc.TLS != nil {
					fmt.Printf(
						"      TLS: %s | %s\n",
						svc.TLS.Version,
						svc.TLS.Cipher,
					)
				}

				for _, finding := range svc.Findings {
					fmt.Printf(
						"      [%s] %s - %s\n",
						strings.ToUpper(
							finding.Severity,
						),
						finding.ID,
						finding.Title,
					)
				}
			},
		},
	)

	services, err := s.Run(
		context.Background(),
	)

	if err != nil &&
		err != context.Canceled {

		fmt.Fprintln(
			os.Stderr,
			"error:",
			err,
		)

		os.Exit(1)
	}

	ended := time.Now().UTC()

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
		findings = append(
			findings,
			service.Findings...,
		)
	}

	r := model.Report{
		Tool:      "ABSL Recon",
		Version:   version,
		Target:    target,
		StartedAt: started,
		EndedAt:   ended,
		Scanned:   len(ports),
		Services:  services,
		Findings:  findings,
	}

	fmt.Println()

	fmt.Printf(
		"Finished in %s | Open services: %d | Findings: %d\n",
		ended.Sub(started).
			Round(time.Millisecond),
		len(services),
		len(findings),
	)

	base := *outBase

	if base == "" {
		stamp := time.Now().
			Format(
				"20060102-150405",
			)

		safeTarget := strings.NewReplacer(
			":",
			"_",
			"/",
			"_",
		).
			Replace(
				target,
			)

		base = filepath.Join(
			"reports",
			safeTarget+
				"-"+
				stamp,
		)
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

	fmt.Printf(
		"\033[32mReports:\033[0m %s.{json,csv,html,sarif}\n",
		base,
	)
}

func truncate(
	s string,
	n int,
) string {
	s = strings.ReplaceAll(
		strings.ReplaceAll(
			s,
			"\r",
			" ",
		),
		"\n",
		" ",
	)

	if len(s) <= n {
		return s
	}

	return s[:n-1] + "..."
}
