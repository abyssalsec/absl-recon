package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
	"gopkg.in/yaml.v3"
)

type Match struct {
	Port          int    `yaml:"port"`
	Protocol      string `yaml:"protocol"`
	Service       string `yaml:"service"`
	HeaderMissing string `yaml:"header_missing"`
	TLSRequired   bool   `yaml:"tls_required"`
}

type Rule struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Remediation string `yaml:"remediation"`
	Match       Match  `yaml:"match"`
}

type Engine struct {
	rules []Rule
}

func Load(dir string) (*Engine, error) {
	var loaded []Rule

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var rule Rule

		if err := yaml.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		if rule.ID == "" {
			return fmt.Errorf("%s: rule id is required", path)
		}

		if rule.Name == "" {
			return fmt.Errorf("%s: rule name is required", path)
		}

		loaded = append(loaded, rule)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &Engine{
		rules: loaded,
	}, nil
}

func (e *Engine) Count() int {
	if e == nil {
		return 0
	}

	return len(e.rules)
}

func (e *Engine) Run(service model.Service) []model.Finding {
	if e == nil {
		return nil
	}

	var findings []model.Finding

	for _, rule := range e.rules {
		if !matches(rule, service) {
			continue
		}

		evidence := fmt.Sprintf(
			"Rule %s matched service %s on %s/%d",
			rule.ID,
			service.Name,
			service.Protocol,
			service.Port,
		)

		if rule.Match.HeaderMissing != "" {
			evidence = fmt.Sprintf(
				"HTTP header %s was not present in the response",
				rule.Match.HeaderMissing,
			)
		}

		findings = append(findings, model.Finding{
			ID:          rule.ID,
			Title:       rule.Name,
			Severity:    strings.ToLower(rule.Severity),
			Port:        service.Port,
			Protocol:    service.Protocol,
			Description: rule.Description,
			Evidence:    evidence,
			Remediation: rule.Remediation,
		})
	}

	return findings
}

func matches(rule Rule, service model.Service) bool {
	if rule.Match.Port != 0 && rule.Match.Port != service.Port {
		return false
	}

	if rule.Match.Protocol != "" &&
		!strings.EqualFold(rule.Match.Protocol, service.Protocol) {
		return false
	}

	if rule.Match.Service != "" &&
		!strings.Contains(
			strings.ToLower(service.Name),
			strings.ToLower(rule.Match.Service),
		) {
		return false
	}

	if rule.Match.TLSRequired && service.TLS == nil {
		return false
	}

	if rule.Match.HeaderMissing != "" {
		if service.Headers == nil {
			return false
		}

		header := strings.ToLower(rule.Match.HeaderMissing)

		if _, exists := service.Headers[header]; exists {
			return false
		}
	}

	return true
}
