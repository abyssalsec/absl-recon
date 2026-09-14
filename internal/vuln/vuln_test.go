package vuln

import (
	"testing"

	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

func TestVersionRange(t *testing.T) {
	c := vulndb.Candidate{VersionStart: "8.5p1", StartInclusive: true, VersionEnd: "9.8p1", EndInclusive: false}
	if !versionApplies("9.6p1", c) {
		t.Fatal("expected 9.6p1 to match")
	}
	if versionApplies("9.8p1", c) {
		t.Fatal("expected 9.8p1 not to match")
	}
}

func TestRiskScore(t *testing.T) {
	score := riskScore(9.8, 0.9, true, 90)
	if score < 85 {
		t.Fatalf("expected high risk score, got %.1f", score)
	}
}
