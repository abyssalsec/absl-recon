package fingerprint

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abyssalsec/absl-recon/internal/model"
)

type Config struct {
	Target  string
	Port    int
	Timeout time.Duration
}

var (
	openSSHPattern = regexp.MustCompile(
		`(?i)OpenSSH[_-]([^\s]+)`,
	)

	proFTPDPattern = regexp.MustCompile(
		`(?i)ProFTPD[ /]([^\s]+)`,
	)

	vsFTPDPattern = regexp.MustCompile(
		`(?i)vsFTPd[ /]([^\s]+)`,
	)

	postfixPattern = regexp.MustCompile(
		`(?i)Postfix`,
	)

	eximPattern = regexp.MustCompile(
		`(?i)Exim(?:[ /]([^\s]+))?`,
	)
)

func Probe(
	cfg Config,
) model.Service {
	svc := model.Service{
		Target:     cfg.Target,
		Port:       cfg.Port,
		Protocol:   "tcp",
		Name:       "unknown",
		Confidence: 0,
	}

	if isLikelyTLSPort(cfg.Port) {
		if detected, ok := probeTLS(cfg); ok {
			if detected.Name == "tls" {
				if hint := serviceHint(cfg.Port); hint != "" {
					detected.Name = hint
				}
			}

			return detected
		}
	}

	if isLikelyHTTPPort(cfg.Port) {
		if detected, ok := probeHTTP(cfg); ok {
			return detected
		}
	}

	if raw := probeBanner(cfg); len(raw) > 0 {
		svc.Banner = sanitize(raw)

		if classifyBanner(
			&svc,
			raw,
		) {
			return svc
		}
	}

	if cfg.Port == 6379 {
		if detected, ok := probeRedis(cfg); ok {
			return detected
		}
	}

	if detected, ok := probeHTTP(cfg); ok {
		return detected
	}

	if detected, ok := probeTLS(cfg); ok {
		if detected.Name == "tls" {
			if hint := serviceHint(cfg.Port); hint != "" {
				detected.Name = hint
			}
		}

		return detected
	}

	if hint := serviceHint(cfg.Port); hint != "" {
		svc.Name = hint
		svc.Confidence = 20
	}

	return svc
}

func probeBanner(
	cfg Config,
) []byte {
	conn, err := dial(cfg)

	if err != nil {
		return nil
	}

	defer conn.Close()

	_ = conn.SetReadDeadline(
		time.Now().Add(
			probeTimeout(
				cfg.Timeout,
			),
		),
	)

	buf := make(
		[]byte,
		4096,
	)

	n, err := conn.Read(buf)

	if err != nil ||
		n == 0 {

		return nil
	}

	result := make(
		[]byte,
		n,
	)

	copy(
		result,
		buf[:n],
	)

	return result
}

func classifyBanner(
	svc *model.Service,
	raw []byte,
) bool {
	if len(raw) > 5 &&
		raw[4] == 0x0a {

		versionEnd := 5

		for versionEnd < len(raw) &&
			raw[versionEnd] != 0x00 {

			versionEnd++
		}

		version := ""

		if versionEnd > 5 {
			version = string(
				raw[5:versionEnd],
			)
		}

		svc.Name = "mysql"
		svc.Product = "MySQL"
		svc.Version = strings.TrimSpace(version)
		svc.Confidence = 100

		return true
	}

	banner := sanitize(raw)

	lower := strings.ToLower(
		banner,
	)

	if strings.HasPrefix(
		lower,
		"ssh-",
	) {
		svc.Name = "ssh"
		svc.Confidence = 100

		if match :=
			openSSHPattern.FindStringSubmatch(
				banner,
			); len(match) > 1 {

			svc.Product = "OpenSSH"
			svc.Version = cleanVersion(
				match[1],
			)
		}

		return true
	}

	if strings.HasPrefix(
		lower,
		"220",
	) &&
		strings.Contains(
			lower,
			"ftp",
		) {

		svc.Name = "ftp"
		svc.Confidence = 95

		if match :=
			vsFTPDPattern.FindStringSubmatch(
				banner,
			); len(match) > 1 {

			svc.Product = "vsftpd"
			svc.Version = cleanVersion(
				match[1],
			)

		} else if match :=
			proFTPDPattern.FindStringSubmatch(
				banner,
			); len(match) > 1 {

			svc.Product = "ProFTPD"
			svc.Version = cleanVersion(
				match[1],
			)
		}

		return true
	}

	if strings.Contains(
		lower,
		"smtp",
	) ||
		strings.Contains(
			lower,
			"esmtp",
		) {

		svc.Name = "smtp"
		svc.Confidence = 95

		switch {
		case postfixPattern.MatchString(
			banner,
		):

			svc.Product = "Postfix"

		case eximPattern.MatchString(
			banner,
		):

			svc.Product = "Exim"

			if match :=
				eximPattern.FindStringSubmatch(
					banner,
				); len(match) > 1 {

				svc.Version = cleanVersion(
					match[1],
				)
			}
		}

		return true
	}

	if strings.HasPrefix(
		lower,
		"+ok",
	) &&
		strings.Contains(
			lower,
			"pop",
		) {

		svc.Name = "pop3"
		svc.Confidence = 90

		return true
	}

	if strings.HasPrefix(
		lower,
		"* ok",
	) &&
		strings.Contains(
			lower,
			"imap",
		) {

		svc.Name = "imap"
		svc.Confidence = 90

		return true
	}

	return false
}

func probeHTTP(
	cfg Config,
) (model.Service, bool) {
	conn, err := dial(cfg)

	if err != nil {
		return model.Service{}, false
	}

	defer conn.Close()

	_ = conn.SetDeadline(
		time.Now().Add(
			probeTimeout(
				cfg.Timeout,
			),
		),
	)

	status, headers, ok :=
		probeHTTPConn(
			conn,
			cfg.Target,
		)

	if !ok {
		return model.Service{}, false
	}

	svc := model.Service{
		Target:     cfg.Target,
		Port:       cfg.Port,
		Protocol:   "tcp",
		Name:       "http",
		Confidence: 100,
		Banner:     status,
		Headers:    headers,
	}

	setHTTPProduct(
		&svc,
	)

	return svc, true
}

func probeTLS(
	cfg Config,
) (model.Service, bool) {
	dialer := &net.Dialer{
		Timeout: probeTimeout(
			cfg.Timeout,
		),
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		NextProtos: []string{
			"http/1.1",
		},
	}

	if net.ParseIP(
		cfg.Target,
	) == nil {

		tlsConfig.ServerName = cfg.Target
	}

	addr := net.JoinHostPort(
		cfg.Target,
		strconv.Itoa(
			cfg.Port,
		),
	)

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		addr,
		tlsConfig,
	)

	if err != nil {
		return model.Service{}, false
	}

	defer conn.Close()

	_ = conn.SetDeadline(
		time.Now().Add(
			probeTimeout(
				cfg.Timeout,
			),
		),
	)

	state := conn.ConnectionState()

	info := &model.TLSInfo{
		Version: tlsVersion(
			state.Version,
		),

		Cipher: tls.CipherSuiteName(
			state.CipherSuite,
		),

		ServerName: state.ServerName,

		ALPN: state.NegotiatedProtocol,
	}

	if len(
		state.PeerCertificates,
	) > 0 {

		cert := state.PeerCertificates[0]

		info.Subject =
			cert.Subject.String()

		info.Issuer =
			cert.Issuer.String()

		info.DNSNames =
			append(
				[]string(nil),
				cert.DNSNames...,
			)

		info.NotBefore =
			cert.NotBefore.
				UTC().
				Format(
					time.RFC3339,
				)

		info.NotAfter =
			cert.NotAfter.
				UTC().
				Format(
					time.RFC3339,
				)
	}

	svc := model.Service{
		Target:     cfg.Target,
		Port:       cfg.Port,
		Protocol:   "tcp",
		Name:       "tls",
		Confidence: 90,
		TLS:        info,
	}

	status, headers, httpOK :=
		probeHTTPConn(
			conn,
			cfg.Target,
		)

	if httpOK {
		svc.Name = "https"
		svc.Confidence = 100
		svc.Banner = status
		svc.Headers = headers

		setHTTPProduct(
			&svc,
		)
	}

	return svc, true
}

func probeHTTPConn(
	conn net.Conn,
	host string,
) (
	string,
	map[string]string,
	bool,
) {
	_, err := fmt.Fprintf(
		conn,
		"HEAD / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: ABSL-Recon/0.7\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		host,
	)

	if err != nil {
		return "", nil, false
	}

	reader := bufio.NewReader(
		io.LimitReader(
			conn,
			16*1024,
		),
	)

	status, err :=
		reader.ReadString('\n')

	if err != nil {
		return "", nil, false
	}

	status = strings.TrimSpace(
		status,
	)

	if !strings.HasPrefix(
		strings.ToUpper(
			status,
		),
		"HTTP/",
	) {
		return "", nil, false
	}

	headers := map[string]string{}

	for {
		line, err :=
			reader.ReadString('\n')

		if err != nil {
			break
		}

		line = strings.TrimSpace(
			line,
		)

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
			strings.TrimSpace(
				parts[0],
			),
		)

		value := strings.TrimSpace(
			parts[1],
		)

		headers[key] = value
	}

	return status,
		headers,
		true
}

func probeRedis(
	cfg Config,
) (model.Service, bool) {
	conn, err := dial(cfg)

	if err != nil {
		return model.Service{}, false
	}

	defer conn.Close()

	_ = conn.SetDeadline(
		time.Now().Add(
			probeTimeout(
				cfg.Timeout,
			),
		),
	)

	_, err = conn.Write(
		[]byte(
			"*1\r\n$4\r\nPING\r\n",
		),
	)

	if err != nil {
		return model.Service{}, false
	}

	buf := make(
		[]byte,
		1024,
	)

	n, err := conn.Read(buf)

	if err != nil ||
		n == 0 {

		return model.Service{}, false
	}

	response := strings.TrimSpace(
		string(
			buf[:n],
		),
	)

	lower := strings.ToLower(
		response,
	)

	if strings.HasPrefix(
		lower,
		"+pong",
	) ||
		strings.Contains(
			lower,
			"noauth",
		) ||
		strings.Contains(
			lower,
			"denied",
		) {

		return model.Service{
			Target:     cfg.Target,
			Port:       cfg.Port,
			Protocol:   "tcp",
			Name:       "redis",
			Product:    "Redis",
			Confidence: 100,
			Banner:     response,
		}, true
	}

	return model.Service{}, false
}

func setHTTPProduct(
	svc *model.Service,
) {
	if svc.Headers == nil {
		return
	}

	server := strings.TrimSpace(
		svc.Headers["server"],
	)

	if server == "" {
		return
	}

	product, version :=
		parseServerHeader(
			server,
		)

	svc.Product = product
	svc.Version = version
}

func parseServerHeader(
	server string,
) (string, string) {
	fields := strings.Fields(
		server,
	)

	if len(fields) == 0 {
		return "", ""
	}

	first := fields[0]

	parts := strings.SplitN(
		first,
		"/",
		2,
	)

	if len(parts) == 1 {
		return parts[0], ""
	}

	return parts[0],
		cleanVersion(
			parts[1],
		)
}

func dial(
	cfg Config,
) (net.Conn, error) {
	addr := net.JoinHostPort(
		cfg.Target,
		strconv.Itoa(
			cfg.Port,
		),
	)

	return net.DialTimeout(
		"tcp",
		addr,
		probeTimeout(
			cfg.Timeout,
		),
	)
}

func probeTimeout(
	configured time.Duration,
) time.Duration {
	const maxProbeTimeout = 500 * time.Millisecond

	if configured <= 0 {
		return maxProbeTimeout
	}

	if configured <
		maxProbeTimeout {

		return configured
	}

	return maxProbeTimeout
}

func tlsVersion(
	version uint16,
) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"

	case tls.VersionTLS12:
		return "TLS 1.2"

	case tls.VersionTLS11:
		return "TLS 1.1"

	case tls.VersionTLS10:
		return "TLS 1.0"

	default:
		return fmt.Sprintf(
			"0x%x",
			version,
		)
	}
}

func cleanVersion(
	version string,
) string {
	return strings.Trim(
		version,
		" ,;()[]{}",
	)
}

func sanitize(
	raw []byte,
) string {
	value := strings.ReplaceAll(
		string(raw),
		"\x00",
		" ",
	)

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

	return strings.Join(
		strings.Fields(
			value,
		),
		" ",
	)
}

func isLikelyHTTPPort(
	port int,
) bool {
	switch port {
	case
		80,
		3000,
		5000,
		8000,
		8008,
		8080,
		8081,
		8888,
		9000,
		9200:

		return true

	default:
		return false
	}
}

func isLikelyTLSPort(
	port int,
) bool {
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
		8443,
		9443:

		return true

	default:
		return false
	}
}

func serviceHint(
	port int,
) string {
	hints := map[int]string{
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
		8080:  "http",
		8443:  "https",
		9200:  "elasticsearch",
		27017: "mongodb",
	}

	return hints[port]
}
