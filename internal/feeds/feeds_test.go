package feeds

import (
	"encoding/json"
	"testing"
)

func TestParseCPE23(t *testing.T) {
	vendor, product, version := parseCPE23("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
	if vendor != "openbsd" || product != "openssh" || version != "9.6p1" {
		t.Fatalf("unexpected CPE parse: %q %q %q", vendor, product, version)
	}
}

func TestParseOpenCTIVulnerability(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"vulnerability",
		"id":"vulnerability--1234",
		"name":"CVE-2024-6387",
		"confidence":90,
		"labels":["exploited","ssh"],
		"created":"2026-01-01T00:00:00Z",
		"modified":"2026-01-02T00:00:00Z",
		"external_references":[{"source_name":"cve","external_id":"CVE-2024-6387"}]
	}`)
	records := parseOpenCTIObject(raw, "test-collection")
	if len(records) != 1 {
		t.Fatalf("expected one intel record, got %d", len(records))
	}
	if records[0].CVEID != "CVE-2024-6387" || records[0].Confidence != 90 {
		t.Fatalf("unexpected record: %+v", records[0])
	}
}
