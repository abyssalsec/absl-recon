package model

import "time"

type TLSInfo struct {
	Version    string   `json:"version,omitempty"`
	Cipher     string   `json:"cipher,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	ALPN       string   `json:"alpn,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
}

type ThreatIntel struct {
	Source     string `json:"source"`
	ObjectID   string `json:"object_id,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
	Labels     string `json:"labels,omitempty"`
	FirstSeen  string `json:"first_seen,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
}

type Finding struct {
	Target         string        `json:"target,omitempty"`
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Severity       string        `json:"severity"`
	Port           int           `json:"port,omitempty"`
	Protocol       string        `json:"protocol,omitempty"`
	Description    string        `json:"description"`
	Evidence       string        `json:"evidence,omitempty"`
	Remediation    string        `json:"remediation,omitempty"`
	CVSSScore      float64       `json:"cvss_score,omitempty"`
	CVSSVector     string        `json:"cvss_vector,omitempty"`
	EPSSScore      float64       `json:"epss_score,omitempty"`
	EPSSPercentile float64       `json:"epss_percentile,omitempty"`
	KEV            bool          `json:"kev,omitempty"`
	RiskScore      float64       `json:"risk_score,omitempty"`
	ThreatIntel    []ThreatIntel `json:"threat_intel,omitempty"`
	References     []string      `json:"references,omitempty"`
}

type Service struct {
	Target     string            `json:"target,omitempty"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Name       string            `json:"name,omitempty"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	Confidence int               `json:"confidence,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	TLS        *TLSInfo          `json:"tls,omitempty"`
	Findings   []Finding         `json:"findings,omitempty"`
}

type Report struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Target      string    `json:"target_spec"`
	Targets     []string  `json:"targets"`
	LiveTargets []string  `json:"live_targets"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	Hosts       int       `json:"hosts_scanned"`
	Scanned     int       `json:"ports_scanned"`
	Services    []Service `json:"services"`
	Findings    []Finding `json:"findings"`
}
