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
	Target  string
	Total   int
	Workers int
	Rules   int
	Version string
}

type Renderer struct {
	mu sync.Mutex

	cfg     Config
	started time.Time
	scanned int
	open    int

	services map[int]model.Service
	findings []model.Finding
	severity map[string]int
}

func New(cfg Config) *Renderer {
	return &Renderer{
		cfg:      cfg,
		started:  time.Now(),
		services: make(map[int]model.Service),
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
			64,
		),
	)

	fmt.Printf(
		"%-12s %s\n",
		"Target",
		r.cfg.Target,
	)

	fmt.Printf(
		"%-12s %s\n",
		"Scan",
		"TCP Connect",
	)

	fmt.Printf(
		"%-12s %d\n",
		"Ports",
		r.cfg.Total,
	)

	fmt.Printf(
		"%-12s %d\n",
		"Workers",
		r.cfg.Workers,
	)

	fmt.Printf(
		"%-12s %d\n",
		"Rules",
		r.cfg.Rules,
	)

	fmt.Println()
}

func (r *Renderer) Run(
	events <-chan event.Event,
) {
	ticker :=
		time.NewTicker(
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

		r.services[ev.Service.Port] = ev.Service

		r.clearProgressLocked()

		fmt.Printf(
			"%sOPEN%s  %5d/tcp  %-22s %s\n",
			green,
			reset,
			ev.Service.Port,
			serviceName(ev.Service),
			truncate(
				ev.Service.Banner,
				64,
			),
		)

		if ev.Service.TLS != nil {
			fmt.Printf(
				"      %sTLS%s   %-8s %s\n",
				cyan,
				reset,
				ev.Service.TLS.Version,
				ev.Service.TLS.Cipher,
			)
		}

	case event.FindingFound:
		r.findings =
			append(
				r.findings,
				ev.Finding,
			)

		severity :=
			strings.ToLower(
				ev.Finding.Severity,
			)

		r.severity[severity]++

		r.clearProgressLocked()

		fmt.Printf(
			"      %s[%s]%s %s - %s\n",
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
	}
}

func (r *Renderer) renderProgress() {
	r.mu.Lock()
	defer r.mu.Unlock()

	elapsed :=
		time.Since(
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

	bar :=
		progressBar(
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
			64,
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
		"%-12s %d\n",
		"Scanned",
		r.scanned,
	)

	fmt.Printf(
		"%-12s %d\n",
		"Open",
		r.open,
	)

	fmt.Printf(
		"%-12s %d\n",
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
			"%-8s %-24s %s\n",
			"PORT",
			"SERVICE",
			"FINGERPRINT",
		)

		fmt.Printf(
			"%-8s %-24s %s\n",
			"----",
			"-------",
			"-----------",
		)

		ports :=
			make(
				[]int,
				0,
				len(r.services),
			)

		for port := range r.services {

			ports =
				append(
					ports,
					port,
				)
		}

		sort.Ints(ports)

		for _, port := range ports {

			svc :=
				r.services[port]

			fingerprint :=
				svc.Banner

			if svc.TLS != nil &&
				fingerprint == "" {

				fingerprint =
					svc.TLS.Version +
						" / " +
						svc.TLS.Cipher
			}

			fmt.Printf(
				"%-8s %-24s %s\n",
				fmt.Sprintf(
					"%d/tcp",
					svc.Port,
				),
				truncate(
					serviceName(svc),
					24,
				),
				truncate(
					fingerprint,
					72,
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
	filled :=
		int(
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
	value =
		strings.ReplaceAll(
			value,
			"\r",
			" ",
		)

	value =
		strings.ReplaceAll(
			value,
			"\n",
			" ",
		)

	value =
		strings.TrimSpace(
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
