# ABSL Recon

ABSL Recon is an extensible Go-based network reconnaissance and vulnerability intelligence framework.

## v0.7.0 highlights

- Concurrent TCP and multi-target/CIDR scanning
- Active service fingerprinting
- YAML security rules
- SQLite vulnerability intelligence database
- Official CVE List V5 ingestion
- CISA KEV enrichment
- FIRST EPSS enrichment
- NVD CVSS/CPE/CWE enrichment
- Optional OpenCTI TAXII 2.1 ingestion
- Risk-based CVE prioritization
- Automatic feed watch mode
- JSON, CSV, HTML and SARIF reports

## Vulnerability database

```bash
./bin/abslscan db init
./bin/abslscan db update
./bin/abslscan db status
./bin/abslscan db search CVE-2024-6387
./bin/abslscan db watch --interval 1h
```

For a full NVD enrichment pass:

```bash
export NVD_API_KEY=your-key
./bin/abslscan db update --nvd-full
```

The canonical CVE corpus comes from the official CVE List V5 repository. NVD is enrichment, so a full NVD pass is optional for the initial CVE corpus.

## OpenCTI TAXII 2.1

```bash
export ABSL_OPENCTI_URL=https://opencti.example.local/taxii2/root
export ABSL_OPENCTI_COLLECTION=collection-uuid
export ABSL_OPENCTI_TOKEN=token
./bin/abslscan db update --only opencti
```

For an isolated lab with a self-signed certificate only:

```bash
export ABSL_OPENCTI_INSECURE=true
```

## Build

```bash
go test ./...
go build -trimpath -ldflags="-s -w" -o bin/abslscan ./cmd/abslscan
```

## Authorization

Use ABSL Recon only against systems and networks you own or are explicitly authorized to assess.
