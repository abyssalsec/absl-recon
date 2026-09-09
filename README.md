# ABSL Recon

ABSL Recon is an extensible terminal-based network reconnaissance and
security assessment framework written in Go.

## Features

- Concurrent TCP port scanning
- Multiple target scanning
- IPv4 CIDR expansion
- TCP host discovery
- Parallel host scheduling
- Active service fingerprinting
- HTTP service detection on non-standard ports
- SSH and common service banner detection
- TLS metadata and certificate inspection
- YAML-based security rule engine
- Local CVE intelligence engine
- Product/version vulnerability matching
- Live terminal progress and findings
- JSON reports
- CSV reports
- HTML reports
- SARIF reports

## Architecture

ABSL Recon separates discovery, fingerprinting, security rules,
vulnerability intelligence, reporting and terminal rendering.

```text
Targets / CIDR
      |
      v
Host Discovery
      |
      v
TCP Scanner
      |
      v
Active Fingerprinting
      |
      +------------------+
      |                  |
      v                  v
YAML Rule Engine     CVE Intelligence
      |                  |
      +--------+---------+
               |
               v
           Findings
               |
      +--------+--------+---------+
      |        |        |         |
      v        v        v         v
   Terminal   JSON     HTML      SARIF
```

## Build

```bash
go test ./...

go build \
  -trimpath \
  -ldflags="-s -w" \
  -o bin/abslscan \
  ./cmd/abslscan
```

## Usage

### Single host

```bash
./bin/abslscan 127.0.0.1
```

### Full TCP range

```bash
./bin/abslscan \
  10.0.0.10 \
  -p 1-65535 \
  -c 500
```

### Multiple hosts

```bash
./bin/abslscan \
  10.0.0.10 \
  10.0.0.20 \
  10.0.0.30
```

### CIDR

```bash
./bin/abslscan \
  10.0.0.0/24
```

### CIDR with custom concurrency

```bash
./bin/abslscan \
  10.0.0.0/24 \
  -p 1-10000 \
  -host-c 8 \
  -c 200
```

### Disable host discovery

```bash
./bin/abslscan \
  10.0.0.0/24 \
  -discover=false
```

### Disable CVE matching

```bash
./bin/abslscan \
  10.0.0.10 \
  -vuln=false
```

### Custom vulnerability database

```bash
./bin/abslscan \
  10.0.0.10 \
  -vulndb ./my-vulndb
```

## Security Rules

Security checks are loaded dynamically from the `rules/` directory.

A new YAML rule can be added without recompiling ABSL Recon.

## CVE Intelligence

CVE advisories are loaded dynamically from the `vulndb/` directory.

Example:

```yaml
id: CVE-2024-6387
product: OpenSSH

min_version: 8.5p1
max_version_exclusive: 9.8p1

severity: high

title: OpenSSH regreSSHion signal handler race condition
```

CVE matches based only on remotely visible product and version
information are reported as potential matches.

Vendor distributions may backport security fixes without changing the
upstream version string exposed by a network service.

The CVE intelligence engine should therefore be treated as remote
exposure intelligence rather than authenticated package verification.

## Reports

ABSL Recon generates:

- JSON
- CSV
- HTML
- SARIF

## Authorization

Use ABSL Recon only against systems and networks you own or are
explicitly authorized to assess.
