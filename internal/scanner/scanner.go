package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/rules"
)

type Config struct {
	Target      string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	Rules       *rules.Engine

	OnOpen func(model.Service)
}

type Scanner struct {
	cfg Config
}

func New(cfg Config) *Scanner {
	return &Scanner{
		cfg: cfg,
	}
}

func (s *Scanner) Run(ctx context.Context) ([]model.Service, error) {
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

				if svc, ok := s.scanPort(port); ok {
					select {
					case results <- svc:
					case <-ctx.Done():
						return
					}
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
		services = append(services, svc)

		if s.cfg.OnOpen != nil {
			s.cfg.OnOpen(svc)
		}
	}

	if ctx.Err() != nil {
		return services, ctx.Err()
	}

	return services, nil
}

func (s *Scanner) scanPort(port int) (model.Service, bool) {
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
		return model.Service{}, false
	}

	svc := model.Service{
		Port:     port,
		Protocol: "tcp",
		Name:     serviceName(port),
	}

	_ = conn.SetDeadline(
		time.Now().Add(s.cfg.Timeout),
	)

	switch {
	case isTLSPort(port):
		_ = conn.Close()

		tlsSvc, ok := s.scanTLS(port)
		if ok {
			svc = tlsSvc
		}

	case isHTTPPort(port):
		readHTTP(
			conn,
			s.cfg.Target,
			&svc,
		)

		_ = conn.Close()

	default:
		svc.Banner = readBanner(conn)
		_ = conn.Close()

		if svc.Banner != "" {
			svc.Name = fingerprint(
				svc.Name,
				svc.Banner,
			)
		}
	}

	if s.cfg.Rules != nil {
		svc.Findings = s.cfg.Rules.Run(svc)
	}

	return svc, true
}

func (s *Scanner) scanTLS(port int) (model.Service, bool) {
	addr := net.JoinHostPort(
		s.cfg.Target,
		strconv.Itoa(port),
	)

	dialer := &net.Dialer{
		Timeout: s.cfg.Timeout,
	}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		addr,
		&tls.Config{
			ServerName: s.cfg.Target,
			MinVersion: tls.VersionTLS12,
		},
	)

	if err != nil {
		return model.Service{
			Port:     port,
			Protocol: "tcp",
			Name:     serviceName(port),
		}, true
	}

	defer conn.Close()

	_ = conn.SetDeadline(
		time.Now().Add(s.cfg.Timeout),
	)

	state := conn.ConnectionState()

	svc := model.Service{
		Port:     port,
		Protocol: "tcp",
		Name:     serviceName(port),
		TLS: &model.TLSInfo{
			Version:    tlsVersion(state.Version),
			Cipher:     tls.CipherSuiteName(state.CipherSuite),
			ServerName: state.ServerName,
		},
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		svc.TLS.Issuer = cert.Issuer.String()
		svc.TLS.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	if isHTTPPort(port) {
		readHTTP(
			conn,
			s.cfg.Target,
			&svc,
		)
	} else {
		svc.Banner = readBanner(conn)

		if svc.Banner != "" {
			svc.Name = fingerprint(
				svc.Name,
				svc.Banner,
			)
		}
	}

	return svc, true
}

func readHTTP(
	conn net.Conn,
	host string,
	svc *model.Service,
) {
	_, _ = fmt.Fprintf(
		conn,
		"HEAD / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: ABSL-Recon/0.2\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		host,
	)

	reader := bufio.NewReader(
		io.LimitReader(conn, 16*1024),
	)

	status, err := reader.ReadString('\n')
	if err == nil {
		svc.Banner = strings.TrimSpace(status)
	}

	svc.Headers = map[string]string{}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		if line == "" {
			break
		}

		parts := strings.SplitN(
			line,
			":",
			2,
		)

		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(
			strings.TrimSpace(parts[0]),
		)

		value := strings.TrimSpace(
			parts[1],
		)

		svc.Headers[key] = value
	}

	if server := svc.Headers["server"]; server != "" {
		svc.Name = "http (" + server + ")"
	}
}

func readBanner(conn net.Conn) string {
	buf := make([]byte, 2048)

	n, err := conn.Read(buf)

	if err != nil || n == 0 {
		return ""
	}

	return strings.TrimSpace(
		strings.ReplaceAll(
			string(buf[:n]),
			"\x00",
			"",
		),
	)
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"

	case tls.VersionTLS12:
		return "TLS 1.2"

	default:
		return fmt.Sprintf(
			"0x%x",
			v,
		)
	}
}

func serviceName(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		465:   "smtps",
		587:   "smtp",
		636:   "ldaps",
		853:   "dns-tls",
		990:   "ftps",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		2375:  "docker",
		2376:  "docker-tls",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		8000:  "http",
		8008:  "http",
		8080:  "http",
		8081:  "http",
		8443:  "https",
		8888:  "http",
		9200:  "elasticsearch",
		27017: "mongodb",
	}

	if name, ok := services[port]; ok {
		return name
	}

	return "unknown"
}

func fingerprint(
	fallback string,
	banner string,
) string {
	b := strings.ToLower(banner)

	signatures := map[string]string{
		"openssh":       "ssh",
		"ssh-":          "ssh",
		"ftp":           "ftp",
		"smtp":          "smtp",
		"redis":         "redis",
		"mysql":         "mysql",
		"postgresql":    "postgresql",
		"elasticsearch": "elasticsearch",
	}

	for signature, name := range signatures {
		if strings.Contains(
			b,
			signature,
		) {
			return name
		}
	}

	return fallback
}

func isHTTPPort(port int) bool {
	switch port {
	case
		80,
		443,
		8000,
		8008,
		8080,
		8081,
		8443,
		8888,
		9200:

		return true

	default:
		return false
	}
}

func isTLSPort(port int) bool {
	switch port {
	case
		443,
		465,
		636,
		853,
		990,
		993,
		995,
		2376,
		8443:

		return true

	default:
		return false
	}
}

func ParsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}

	var out []int

	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)

		if token == "" {
			continue
		}

		if strings.Contains(token, "-") {
			parts := strings.SplitN(
				token,
				"-",
				2,
			)

			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])

			if err1 != nil ||
				err2 != nil ||
				start < 1 ||
				end > 65535 ||
				start > end {

				return nil, fmt.Errorf(
					"invalid port range %q",
					token,
				)
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}

			continue
		}

		port, err := strconv.Atoi(token)

		if err != nil ||
			port < 1 ||
			port > 65535 {

			return nil, fmt.Errorf(
				"invalid port %q",
				token,
			)
		}

		if !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf(
			"no ports selected",
		)
	}

	return out, nil
}
