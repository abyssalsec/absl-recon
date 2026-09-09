package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abyssalsec/absl-recon/internal/event"
	"github.com/abyssalsec/absl-recon/internal/fingerprint"
	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/rules"
	"github.com/abyssalsec/absl-recon/internal/vuln"
)

type Config struct {
	Target      string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	Rules       *rules.Engine
	Vulns       *vuln.Engine
	Events      chan<- event.Event
}

type Scanner struct {
	cfg Config
}

func New(
	cfg Config,
) *Scanner {
	return &Scanner{
		cfg: cfg,
	}
}

func (s *Scanner) Run(
	ctx context.Context,
) ([]model.Service, error) {
	if s.cfg.Concurrency < 1 {
		s.cfg.Concurrency = 100
	}

	jobs := make(chan int)
	results := make(chan model.Service)

	var wg sync.WaitGroup

	for i := 0; i < s.cfg.Concurrency; i++ {

		wg.Add(1)

		go func() {
			defer wg.Done()

			for port := range jobs {
				select {
				case <-ctx.Done():
					return

				default:
				}

				svc, open :=
					s.scanPort(port)

				s.emit(
					event.Event{
						Type:   event.PortScanned,
						Target: s.cfg.Target,
						Port:   port,
						At:     time.Now(),
					},
				)

				if !open {
					continue
				}

				s.emit(
					event.Event{
						Type:    event.ServiceFound,
						Target:  s.cfg.Target,
						Port:    port,
						Service: svc,
						At:      time.Now(),
					},
				)

				for _, finding := range svc.Findings {

					s.emit(
						event.Event{
							Type:    event.FindingFound,
							Target:  s.cfg.Target,
							Port:    port,
							Finding: finding,
							At:      time.Now(),
						},
					)
				}

				select {
				case results <- svc:

				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)

		for _, port := range s.cfg.Ports {

			select {
			case jobs <- port:

			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var services []model.Service

	for svc := range results {
		services = append(
			services,
			svc,
		)
	}

	if ctx.Err() != nil {
		return services,
			ctx.Err()
	}

	return services, nil
}

func (s *Scanner) emit(
	ev event.Event,
) {
	if s.cfg.Events == nil {
		return
	}

	s.cfg.Events <- ev
}

func (s *Scanner) scanPort(
	port int,
) (model.Service, bool) {
	addr := net.JoinHostPort(
		s.cfg.Target,
		strconv.Itoa(port),
	)

	conn, err := net.DialTimeout(
		"tcp",
		addr,
		s.cfg.Timeout,
	)

	if err != nil {
		return model.Service{},
			false
	}

	_ = conn.Close()

	svc := fingerprint.Probe(
		fingerprint.Config{
			Target:  s.cfg.Target,
			Port:    port,
			Timeout: s.cfg.Timeout,
		},
	)

	if s.cfg.Rules != nil {
		svc.Findings =
			s.cfg.Rules.Run(svc)
	}

	if s.cfg.Vulns != nil {
		svc.Findings = append(
			svc.Findings,
			s.cfg.Vulns.Match(svc)...,
		)
	}

	return svc, true
}

func ParsePorts(
	spec string,
) ([]int, error) {
	seen := map[int]bool{}

	var out []int

	for _, token := range strings.Split(
		spec,
		",",
	) {

		token = strings.TrimSpace(
			token,
		)

		if token == "" {
			continue
		}

		if strings.Contains(
			token,
			"-",
		) {
			parts := strings.SplitN(
				token,
				"-",
				2,
			)

			start, err1 := strconv.Atoi(
				parts[0],
			)

			end, err2 := strconv.Atoi(
				parts[1],
			)

			if err1 != nil ||
				err2 != nil ||
				start < 1 ||
				end > 65535 ||
				start > end {

				return nil,
					fmt.Errorf(
						"invalid port range %q",
						token,
					)
			}

			for p := start; p <= end; p++ {

				if !seen[p] {
					seen[p] = true

					out = append(
						out,
						p,
					)
				}
			}

			continue
		}

		port, err := strconv.Atoi(token)

		if err != nil ||
			port < 1 ||
			port > 65535 {

			return nil,
				fmt.Errorf(
					"invalid port %q",
					token,
				)
		}

		if !seen[port] {
			seen[port] = true

			out = append(
				out,
				port,
			)
		}
	}

	if len(out) == 0 {
		return nil,
			fmt.Errorf(
				"no ports selected",
			)
	}

	return out, nil
}
