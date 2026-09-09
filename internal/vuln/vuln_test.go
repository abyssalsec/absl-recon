package vuln

import (
	"testing"

	"github.com/abyssalsec/absl-recon/internal/model"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		left     string
		right    string
		expected int
	}{
		{
			left:     "8.5p1",
			right:    "8.5p1",
			expected: 0,
		},
		{
			left:     "9.6p1",
			right:    "9.8p1",
			expected: -1,
		},
		{
			left:     "9.8p1",
			right:    "9.8p1",
			expected: 0,
		},
		{
			left:     "9.9p1",
			right:    "9.8p1",
			expected: 1,
		},
		{
			left:     "2.4.49",
			right:    "2.4.50",
			expected: -1,
		},
	}

	for _, test := range tests {
		actual := compareVersions(
			test.left,
			test.right,
		)

		if actual != test.expected {
			t.Fatalf(
				"compareVersions(%q, %q): expected %d, got %d",
				test.left,
				test.right,
				test.expected,
				actual,
			)
		}
	}
}

func TestOpenSSHRange(t *testing.T) {
	record := Record{
		ID:                  "CVE-TEST",
		Product:             "OpenSSH",
		MinVersion:          "8.5p1",
		MaxVersionExclusive: "9.8p1",
	}

	if !versionMatches(
		record,
		"9.6p1",
	) {
		t.Fatal(
			"expected OpenSSH 9.6p1 to match",
		)
	}

	if versionMatches(
		record,
		"9.8p1",
	) {
		t.Fatal(
			"expected OpenSSH 9.8p1 not to match",
		)
	}
}

func TestExactVersions(t *testing.T) {
	record := Record{
		ID: "CVE-TEST",

		Product: "Apache",

		ExactVersions: []string{
			"2.4.49",
			"2.4.50",
		},
	}

	if !versionMatches(
		record,
		"2.4.49",
	) {
		t.Fatal(
			"expected Apache 2.4.49 to match",
		)
	}

	if !versionMatches(
		record,
		"2.4.50",
	) {
		t.Fatal(
			"expected Apache 2.4.50 to match",
		)
	}

	if versionMatches(
		record,
		"2.4.51",
	) {
		t.Fatal(
			"expected Apache 2.4.51 not to match",
		)
	}
}

func TestEngineMatch(t *testing.T) {
	engine := &Engine{
		records: []Record{
			{
				ID: "CVE-TEST-0001",

				Product: "OpenSSH",

				MinVersion: "8.5p1",

				MaxVersionExclusive: "9.8p1",

				Severity: "high",

				Title: "Test advisory",

				Description: "Test description",

				Remediation: "Upgrade.",
			},
		},
	}

	service := model.Service{
		Target:     "127.0.0.1",
		Port:       22,
		Protocol:   "tcp",
		Name:       "ssh",
		Product:    "OpenSSH",
		Version:    "9.6p1",
		Confidence: 100,
	}

	findings := engine.Match(
		service,
	)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	if findings[0].ID !=
		"CVE-TEST-0001" {

		t.Fatalf(
			"unexpected finding id %q",
			findings[0].ID,
		)
	}
}
