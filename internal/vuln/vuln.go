package vuln

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
	"github.com/abyssalsec/absl-recon/internal/vulndb"
)

type Engine struct {
	store *vulndb.Store
}

var versionTokenPattern = regexp.MustCompile(`(?i)[0-9]+|[a-z]+`)

type versionToken struct {
	numeric bool
	number  int
	text    string
}

func Open(path string) (*Engine, error) {
	store, err := vulndb.OpenExisting(path)
	if err != nil {
		return nil, err
	}
	return &Engine{store: store}, nil
}

func (e *Engine) Close() error {
	if e == nil || e.store == nil {
		return nil
	}
	return e.store.Close()
}

func (e *Engine) Match(service model.Service) []model.Finding {
	if e == nil || e.store == nil || strings.TrimSpace(service.Product) == "" || strings.TrimSpace(service.Version) == "" {
		return nil
	}
	ctx := context.Background()
	product := vulndb.NormalizeProduct(service.Product)
	candidates, err := e.store.Candidates(ctx, product)
	if err != nil {
		return nil
	}
	matched := map[string]vulndb.Candidate{}
	for _, candidate := range candidates {
		if versionApplies(service.Version, candidate) {
			if existing, ok := matched[candidate.CVEID]; !ok || candidate.CVSSScore > existing.CVSSScore {
				matched[candidate.CVEID] = candidate
			}
		}
	}
	findings := make([]model.Finding, 0, len(matched))
	for _, c := range matched {
		refs, _ := e.store.References(ctx, c.CVEID)
		intelRows, _ := e.store.Intel(ctx, c.CVEID)
		intel := make([]model.ThreatIntel, 0, len(intelRows))
		maxIntelConfidence := 0
		for _, item := range intelRows {
			intel = append(intel, model.ThreatIntel{
				Source:     item.Source,
				ObjectID:   item.ObjectID,
				Confidence: item.Confidence,
				Labels:     item.Labels,
				FirstSeen:  item.FirstSeen,
				LastSeen:   item.LastSeen,
			})
			if item.Confidence > maxIntelConfidence {
				maxIntelConfidence = item.Confidence
			}
		}
		risk := riskScore(c.CVSSScore, c.EPSSScore, c.KEV, maxIntelConfidence)
		severity := strings.ToLower(c.Severity)
		if severity == "" {
			severity = riskSeverity(risk)
		}
		title := c.Title
		if title == "" {
			title = "Potential vulnerability match"
		}
		description := c.Description
		if description == "" {
			description = "The remotely identified product and version match an affected-version entry in the local vulnerability intelligence database."
		}
		evidence := fmt.Sprintf(
			"Potential CVE match: remote fingerprint identified %s %s on %s:%d. Version-only remote detection cannot prove patch state or exploitability.",
			service.Product, service.Version, service.Target, service.Port,
		)
		if c.KEV {
			evidence += " CISA KEV indicates exploitation in the wild."
		}
		findings = append(findings, model.Finding{
			Target:         service.Target,
			ID:             c.CVEID,
			Title:          title,
			Severity:       severity,
			Port:           service.Port,
			Protocol:       service.Protocol,
			Description:    description,
			Evidence:       evidence,
			Remediation:    remediation(c),
			CVSSScore:      c.CVSSScore,
			CVSSVector:     c.CVSSVector,
			EPSSScore:      c.EPSSScore,
			EPSSPercentile: c.EPSSPercentile,
			KEV:            c.KEV,
			RiskScore:      risk,
			ThreatIntel:    intel,
			References:     refs,
		})
	}
	return findings
}

func remediation(c vulndb.Candidate) string {
	if c.KEVAction != "" {
		return c.KEVAction
	}
	return "Validate the finding against the vendor advisory and installed package patch state, then apply the vendor security update or upgrade to a fixed release."
}

func riskScore(cvss, epss float64, kev bool, intelConfidence int) float64 {
	cvssNorm := clamp(cvss/10, 0, 1)
	epssNorm := clamp(epss, 0, 1)
	kevNorm := 0.0
	if kev {
		kevNorm = 1
	}
	intelNorm := clamp(float64(intelConfidence)/100, 0, 1)
	score := (cvssNorm*0.35 + epssNorm*0.30 + kevNorm*0.25 + intelNorm*0.10) * 100
	return math.Round(score*10) / 10
}

func riskSeverity(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func clamp(v, minValue, maxValue float64) float64 {
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

func versionApplies(version string, c vulndb.Candidate) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if c.ExactVersion != "" {
		return matchExactOrExpression(version, c.ExactVersion)
	}
	if c.VersionStart != "" {
		cmp := compareVersions(version, c.VersionStart)
		if cmp < 0 || (cmp == 0 && !c.StartInclusive) {
			return false
		}
	}
	if c.VersionEnd != "" {
		cmp := compareVersions(version, c.VersionEnd)
		if cmp > 0 || (cmp == 0 && !c.EndInclusive) {
			return false
		}
	}
	return true
}

func matchExactOrExpression(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	for _, prefix := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(constraint, prefix) {
			other := strings.TrimSpace(strings.TrimPrefix(constraint, prefix))
			cmp := compareVersions(version, other)
			switch prefix {
			case "<=":
				return cmp <= 0
			case ">=":
				return cmp >= 0
			case "<":
				return cmp < 0
			case ">":
				return cmp > 0
			case "=":
				return cmp == 0
			}
		}
	}
	return compareVersions(version, constraint) == 0
}

func compareVersions(left, right string) int {
	a := tokenizeVersion(left)
	b := tokenizeVersion(right)
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(a) {
			if remainingZero(b[i:]) {
				return 0
			}
			return -1
		}
		if i >= len(b) {
			if remainingZero(a[i:]) {
				return 0
			}
			return 1
		}
		at, bt := a[i], b[i]
		switch {
		case at.numeric && bt.numeric:
			if at.number < bt.number {
				return -1
			}
			if at.number > bt.number {
				return 1
			}
		case !at.numeric && !bt.numeric:
			if at.text < bt.text {
				return -1
			}
			if at.text > bt.text {
				return 1
			}
		case at.numeric && !bt.numeric:
			return 1
		default:
			return -1
		}
	}
	return 0
}

func tokenizeVersion(version string) []versionToken {
	raw := versionTokenPattern.FindAllString(strings.ToLower(strings.TrimSpace(version)), -1)
	tokens := make([]versionToken, 0, len(raw))
	for _, item := range raw {
		if n, err := strconv.Atoi(item); err == nil {
			tokens = append(tokens, versionToken{numeric: true, number: n})
		} else {
			tokens = append(tokens, versionToken{text: item})
		}
	}
	return tokens
}

func remainingZero(tokens []versionToken) bool {
	for _, token := range tokens {
		if !token.numeric || token.number != 0 {
			return false
		}
	}
	return true
}
