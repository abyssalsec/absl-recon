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

type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type Service struct {
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
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Scanned  int       `json:"ports_scanned"`
	Services []Service `json:"services"`
	Findings []Finding `json:"findings"`
}
