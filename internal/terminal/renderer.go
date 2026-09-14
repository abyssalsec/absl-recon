package terminal

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abyssalsec/absl-recon/internal/event"
	"github.com/abyssalsec/absl-recon/internal/model"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	gray   = "\033[90m"
)

type Config struct {
	TargetSpec   string
	Hosts        int
	PortsPerHost int
	Total        int
	Workers      int
	HostWorkers  int
	Rules        int
	Version      string
}

type Renderer struct {
	mu sync.Mutex

	cfg     Config
	started time.Time
	scanned int
	open    int

	services map[string]model.Service
	findings []model.Finding
	severity map[string]int
}

func New(
	cfg Config,
) *Renderer {
	return &Renderer{
		cfg:      cfg,
		started:  time.Now(),
		services: make(map[string]model.Service),
		severity: make(map[string]int),
	}
}

func (r *Renderer) PrintHeader() {
	fmt.Printf(
		"%s%sABSL RECON%s %sv%s\n",
		bold,
		cyan,
		reset,
		gray,
		r.cfg.Version+reset,
	)

	fmt.Println(
		strings.Repeat(
			"-",
			88,
		),
	)

	fmt.Printf(
		"%-14s %s\n",
		"Target",
		r.cfg.TargetSpec,
	)

	fmt.Printf(
		"%-14s %s\n",
		"Scan",
		"TCP Connect + Active Fingerprinting",
	)

	fmt.Printf(
		"%-14s %d\n",
		"Hosts",
		r.cfg.Hosts,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Ports/Host",
		r.cfg.PortsPerHost,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Port Workers",
		r.cfg.Workers,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Host Workers",
		r.cfg.HostWorkers,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Rules",
		r.cfg.Rules,
	)

	fmt.Println()
}

func (r *Renderer) Run(
	events <-chan event.Event,
) {
	ticker := time.NewTicker(
		150 * time.Millisecond,
	)

	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				r.clearProgress()
				return
			}

			r.handle(ev)

		case <-ticker.C:
			r.renderProgress()
		}
	}
}

func (r *Renderer) handle(
	ev event.Event,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch ev.Type {
	case event.PortScanned:
		r.scanned++

	case event.ServiceFound:
		r.open++

		key := fmt.Sprintf(
			"%s:%d",
			ev.Service.Target,
			ev.Service.Port,
		)

		r.services[key] =
			ev.Service

		r.clearProgressLocked()

		fmt.Printf(
			"%sOPEN%s  %-15s %5d/tcp  %-14s %-24s %s\n",
			green,
			reset,
			ev.Service.Target,
			ev.Service.Port,
			serviceName(
				ev.Service,
			),
			productLabel(
				ev.Service,
			),
			truncate(
				ev.Service.Banner,
				42,
			),
		)

		if ev.Service.TLS != nil {
			fmt.Printf(
				"      %-15s           %sTLS%s %-8s %s\n",
				"",
				cyan,
				reset,
				ev.Service.TLS.Version,
				ev.Service.TLS.Cipher,
			)
		}

	case event.FindingFound:
		r.findings = append(
			r.findings,
			ev.Finding,
		)

		severity := strings.ToLower(
			ev.Finding.Severity,
		)

		r.severity[severity]++

		r.clearProgressLocked()

		fmt.Printf(
			"      %-15s %s[%s]%s %s - %s\n",
			ev.Finding.Target,
			severityColor(
				severity,
			),
			strings.ToUpper(
				severity,
			),
			reset,
			ev.Finding.ID,
			ev.Finding.Title,
		)

		if strings.HasPrefix(strings.ToUpper(ev.Finding.ID), "CVE-") {
			kev := "no"
			if ev.Finding.KEV {
				kev = "YES"
			}
			fmt.Printf(
				"      %-15s %sRISK%s %.1f | CVSS %.1f | EPSS %.2f%% | KEV %s | INTEL %d\n",
				"",
				cyan,
				reset,
				ev.Finding.RiskScore,
				ev.Finding.CVSSScore,
				ev.Finding.EPSSScore*100,
				kev,
				len(ev.Finding.ThreatIntel),
			)
		}
	}
}

func (r *Renderer) renderProgress() {
	r.mu.Lock()
	defer r.mu.Unlock()

	elapsed := time.Since(
		r.started,
	)

	rate := 0.0

	if elapsed.Seconds() > 0 {
		rate =
			float64(r.scanned) /
				elapsed.Seconds()
	}

	percent := 100.0

	if r.cfg.Total > 0 {
		percent =
			float64(r.scanned) /
				float64(r.cfg.Total) *
				100
	}

	if percent > 100 {
		percent = 100
	}

	bar := progressBar(
		percent,
		24,
	)

	fmt.Printf(
		"\r\033[2K%sSCANNING%s %s %6.2f%%  %d/%d  %8.0f p/s  open:%d  findings:%d",
		cyan,
		reset,
		bar,
		percent,
		r.scanned,
		r.cfg.Total,
		rate,
		r.open,
		len(r.findings),
	)
}

func (r *Renderer) PrintSummary(
	duration time.Duration,
	reportBase string,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Println()

	fmt.Println(
		strings.Repeat(
			"-",
			88,
		),
	)

	fmt.Printf(
		"%sSCAN COMPLETE%s in %s\n\n",
		bold+green,
		reset,
		duration.Round(
			time.Millisecond,
		),
	)

	fmt.Printf(
		"%-14s %d\n",
		"Hosts",
		r.cfg.Hosts,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Scanned",
		r.scanned,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Open",
		r.open,
	)

	fmt.Printf(
		"%-14s %d\n",
		"Findings",
		len(r.findings),
	)

	fmt.Println()

	if len(r.services) > 0 {
		fmt.Printf(
			"%sOPEN SERVICES%s\n",
			bold,
			reset,
		)

		fmt.Printf(
			"%-16s %-10s %-14s %-25s %-8s %s\n",
			"HOST",
			"PORT",
			"SERVICE",
			"PRODUCT",
			"CONF",
			"BANNER",
		)

		fmt.Printf(
			"%-16s %-10s %-14s %-25s %-8s %s\n",
			"----",
			"----",
			"-------",
			"-------",
			"----",
			"------",
		)

		services := make(
			[]model.Service,
			0,
			len(r.services),
		)

		for _, svc := range r.services {
			services = append(
				services,
				svc,
			)
		}

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

		for _, svc := range services {
			fmt.Printf(
				"%-16s %-10s %-14s %-25s %-8s %s\n",
				truncate(
					svc.Target,
					16,
				),
				fmt.Sprintf(
					"%d/tcp",
					svc.Port,
				),
				truncate(
					serviceName(svc),
					14,
				),
				truncate(
					productLabel(svc),
					25,
				),
				fmt.Sprintf(
					"%d%%",
					svc.Confidence,
				),
				truncate(
					svc.Banner,
					42,
				),
			)
		}

		fmt.Println()
	}

	fmt.Printf(
		"%sFINDINGS%s\n",
		bold,
		reset,
	)

	fmt.Printf(
		"%sCRITICAL%s  %d\n",
		red+bold,
		reset,
		r.severity["critical"],
	)

	fmt.Printf(
		"%sHIGH%s      %d\n",
		red,
		reset,
		r.severity["high"],
	)

	fmt.Printf(
		"%sMEDIUM%s    %d\n",
		yellow,
		reset,
		r.severity["medium"],
	)

	fmt.Printf(
		"%sLOW%s       %d\n",
		gray,
		reset,
		r.severity["low"],
	)

	fmt.Println()

	fmt.Printf(
		"%sREPORTS%s\n",
		bold,
		reset,
	)

	fmt.Printf(
		"JSON   %s.json\n",
		reportBase,
	)

	fmt.Printf(
		"CSV    %s.csv\n",
		reportBase,
	)

	fmt.Printf(
		"HTML   %s.html\n",
		reportBase,
	)

	fmt.Printf(
		"SARIF  %s.sarif\n",
		reportBase,
	)
}

func (r *Renderer) clearProgress() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clearProgressLocked()
}

func (r *Renderer) clearProgressLocked() {
	fmt.Print(
		"\r\033[2K",
	)
}

func progressBar(
	percent float64,
	width int,
) string {
	filled := int(
		percent /
			100 *
			float64(width),
	)

	if filled < 0 {
		filled = 0
	}

	if filled > width {
		filled = width
	}

	return "[" +
		strings.Repeat(
			"#",
			filled,
		) +
		strings.Repeat(
			"-",
			width-filled,
		) +
		"]"
}

func serviceName(
	svc model.Service,
) string {
	if svc.Name == "" {
		return "unknown"
	}

	return svc.Name
}

func productLabel(
	svc model.Service,
) string {
	switch {
	case svc.Product != "" &&
		svc.Version != "":

		return svc.Product +
			" " +
			svc.Version

	case svc.Product != "":
		return svc.Product

	case svc.Version != "":
		return svc.Version

	default:
		return "-"
	}
}

func severityColor(
	severity string,
) string {
	switch severity {
	case "critical":
		return red + bold

	case "high":
		return red

	case "medium":
		return yellow

	default:
		return gray
	}
}

func truncate(
	value string,
	max int,
) string {
	value = strings.ReplaceAll(
		value,
		"\r",
		" ",
	)

	value = strings.ReplaceAll(
		value,
		"\n",
		" ",
	)

	value = strings.TrimSpace(
		value,
	)

	if len(value) <= max {
		return value
	}

	if max <= 3 {
		return value[:max]
	}

	return value[:max-3] + "..."
}
