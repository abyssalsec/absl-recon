package vuln

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
	"gopkg.in/yaml.v3"
)

type Record struct {
	ID                  string   `yaml:"id"`
	Product             string   `yaml:"product"`
	Aliases             []string `yaml:"aliases"`
	ExactVersions       []string `yaml:"exact_versions"`
	MinVersion          string   `yaml:"min_version"`
	MaxVersionExclusive string   `yaml:"max_version_exclusive"`
	Severity            string   `yaml:"severity"`
	Title               string   `yaml:"title"`
	Description         string   `yaml:"description"`
	Remediation         string   `yaml:"remediation"`
	References          []string `yaml:"references"`
	Note                string   `yaml:"note"`
}

type Engine struct {
	records []Record
}

var versionTokenPattern = regexp.MustCompile(
	`(?i)[0-9]+|[a-z]+`,
)

type versionToken struct {
	numeric bool
	number  int
	text    string
}

func Load(
	dir string,
) (*Engine, error) {
	var records []Record

	seen := map[string]bool{}

	err := filepath.Walk(
		dir,
		func(
			path string,
			info os.FileInfo,
			err error,
		) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			ext := strings.ToLower(
				filepath.Ext(path),
			)

			if ext != ".yaml" &&
				ext != ".yml" {

				return nil
			}

			data, err := os.ReadFile(path)

			if err != nil {
				return err
			}

			var record Record

			if err := yaml.Unmarshal(
				data,
				&record,
			); err != nil {

				return fmt.Errorf(
					"%s: %w",
					path,
					err,
				)
			}

			if err := validate(
				record,
			); err != nil {

				return fmt.Errorf(
					"%s: %w",
					path,
					err,
				)
			}

			key := strings.ToLower(
				record.ID +
					"|" +
					record.Product,
			)

			if seen[key] {
				return fmt.Errorf(
					"%s: duplicate advisory %s for product %s",
					path,
					record.ID,
					record.Product,
				)
			}

			seen[key] = true

			records = append(
				records,
				record,
			)

			return nil
		},
	)

	if err != nil {
		return nil, err
	}

	return &Engine{
		records: records,
	}, nil
}

func (e *Engine) Count() int {
	if e == nil {
		return 0
	}

	return len(e.records)
}

func (e *Engine) Match(
	service model.Service,
) []model.Finding {
	if e == nil {
		return nil
	}

	if strings.TrimSpace(
		service.Product,
	) == "" {

		return nil
	}

	if strings.TrimSpace(
		service.Version,
	) == "" {

		return nil
	}

	var findings []model.Finding

	for _, record := range e.records {
		if !productMatches(
			record,
			service.Product,
		) {

			continue
		}

		if !versionMatches(
			record,
			service.Version,
		) {

			continue
		}

		description := record.Description

		if record.Note != "" {
			description += " " + record.Note
		}

		findings = append(
			findings,
			model.Finding{
				Target: service.Target,

				ID: record.ID,

				Title: record.Title,

				Severity: strings.ToLower(
					record.Severity,
				),

				Port: service.Port,

				Protocol: service.Protocol,

				Description: description,

				Evidence: fmt.Sprintf(
					"Potential CVE match: remote fingerprint identified %s %s on %s:%d. Version-only remote detection cannot determine whether a vendor backported the security fix.",
					service.Product,
					service.Version,
					service.Target,
					service.Port,
				),

				Remediation: record.Remediation,

				References: append(
					[]string(nil),
					record.References...,
				),
			},
		)
	}

	return findings
}

func validate(
	record Record,
) error {
	if strings.TrimSpace(
		record.ID,
	) == "" {

		return fmt.Errorf(
			"id is required",
		)
	}

	if strings.TrimSpace(
		record.Product,
	) == "" {

		return fmt.Errorf(
			"product is required",
		)
	}

	if strings.TrimSpace(
		record.Title,
	) == "" {

		return fmt.Errorf(
			"title is required",
		)
	}

	if strings.TrimSpace(
		record.Severity,
	) == "" {

		return fmt.Errorf(
			"severity is required",
		)
	}

	if len(record.ExactVersions) == 0 &&
		record.MinVersion == "" &&
		record.MaxVersionExclusive == "" {

		return fmt.Errorf(
			"at least one version constraint is required",
		)
	}

	return nil
}

func productMatches(
	record Record,
	product string,
) bool {
	product = normalizeProduct(
		product,
	)

	if product ==
		normalizeProduct(
			record.Product,
		) {

		return true
	}

	for _, alias := range record.Aliases {
		if product ==
			normalizeProduct(
				alias,
			) {

			return true
		}
	}

	return false
}

func normalizeProduct(
	value string,
) string {
	value = strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)

	value = strings.ReplaceAll(
		value,
		" ",
		"",
	)

	value = strings.ReplaceAll(
		value,
		"-",
		"",
	)

	value = strings.ReplaceAll(
		value,
		"_",
		"",
	)

	return value
}

func versionMatches(
	record Record,
	version string,
) bool {
	version = strings.TrimSpace(
		version,
	)

	if version == "" {
		return false
	}

	if len(
		record.ExactVersions,
	) > 0 {

		for _, exact := range record.ExactVersions {

			if compareVersions(
				version,
				exact,
			) == 0 {

				return true
			}
		}

		return false
	}

	if record.MinVersion != "" {
		if compareVersions(
			version,
			record.MinVersion,
		) < 0 {

			return false
		}
	}

	if record.MaxVersionExclusive != "" {
		if compareVersions(
			version,
			record.MaxVersionExclusive,
		) >= 0 {

			return false
		}
	}

	return true
}

func compareVersions(
	left string,
	right string,
) int {
	a := tokenizeVersion(
		left,
	)

	b := tokenizeVersion(
		right,
	)

	max := len(a)

	if len(b) > max {
		max = len(b)
	}

	for i := 0; i < max; i++ {
		if i >= len(a) {
			if remainingZero(
				b[i:],
			) {
				return 0
			}

			return -1
		}

		if i >= len(b) {
			if remainingZero(
				a[i:],
			) {
				return 0
			}

			return 1
		}

		at := a[i]
		bt := b[i]

		switch {
		case at.numeric &&
			bt.numeric:

			if at.number < bt.number {
				return -1
			}

			if at.number > bt.number {
				return 1
			}

		case !at.numeric &&
			!bt.numeric:

			if at.text < bt.text {
				return -1
			}

			if at.text > bt.text {
				return 1
			}

		case at.numeric &&
			!bt.numeric:

			return 1

		default:
			return -1
		}
	}

	return 0
}

func tokenizeVersion(
	version string,
) []versionToken {
	version = strings.ToLower(
		strings.TrimSpace(
			version,
		),
	)

	rawTokens :=
		versionTokenPattern.
			FindAllString(
				version,
				-1,
			)

	tokens := make(
		[]versionToken,
		0,
		len(rawTokens),
	)

	for _, raw := range rawTokens {
		if number, err :=
			strconv.Atoi(raw); err == nil {

			tokens = append(
				tokens,
				versionToken{
					numeric: true,
					number:  number,
				},
			)

			continue
		}

		tokens = append(
			tokens,
			versionToken{
				text: strings.ToLower(
					raw,
				),
			},
		)
	}

	return tokens
}

func remainingZero(
	tokens []versionToken,
) bool {
	for _, token := range tokens {
		if token.numeric {
			if token.number != 0 {
				return false
			}

			continue
		}

		return false
	}

	return true
}
