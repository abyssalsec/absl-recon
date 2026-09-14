package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
)

func WriteAll(base string, r model.Report) error {
	if dir := filepath.Dir(base); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := writeJSON(base+".json", r); err != nil {
		return err
	}
	if err := writeCSV(base+".csv", r); err != nil {
		return err
	}
	if err := writeHTML(base+".html", r); err != nil {
		return err
	}
	return writeSARIF(base+".sarif", r)
}

func writeJSON(path string, r model.Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeCSV(path string, r model.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)
	defer w.Flush()
	if err := w.Write([]string{
		"target", "id", "severity", "risk_score", "cvss", "epss", "epss_percentile", "kev",
		"port", "protocol", "title", "evidence", "remediation", "references",
	}); err != nil {
		return err
	}
	for _, f := range r.Findings {
		if err := w.Write([]string{
			f.Target,
			f.ID,
			f.Severity,
			fmt.Sprintf("%.1f", f.RiskScore),
			fmt.Sprintf("%.1f", f.CVSSScore),
			fmt.Sprintf("%.6f", f.EPSSScore),
			fmt.Sprintf("%.6f", f.EPSSPercentile),
			strconv.FormatBool(f.KEV),
			strconv.Itoa(f.Port),
			f.Protocol,
			f.Title,
			f.Evidence,
			f.Remediation,
			strings.Join(f.References, " "),
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeHTML(path string, r model.Report) error {
	const tpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>ABSL Recon Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1500px;margin:40px auto;padding:0 20px;background:#111;color:#eee}
table{border-collapse:collapse;width:100%;margin-bottom:40px}th,td{border:1px solid #333;padding:10px;text-align:left;vertical-align:top}th{background:#222}code{white-space:pre-wrap}.critical{color:#ff4d4d;font-weight:bold}.high{color:#ff7b54;font-weight:bold}.medium{color:#ffd166}.low{color:#aaa}.kev{font-weight:bold}.risk{font-weight:bold}
</style></head><body>
<h1>ABSL Recon</h1>
<p>Target specification: {{.Target}}<br>Version: {{.Version}}<br>Hosts scanned: {{.Hosts}}<br>Ports scanned: {{.Scanned}}<br>Open services: {{len .Services}}<br>Findings: {{len .Findings}}</p>
<h2>Services</h2>
<table><tr><th>Target</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Confidence</th><th>TLS</th><th>Banner</th></tr>
{{range .Services}}<tr><td>{{.Target}}</td><td>{{.Port}}/tcp</td><td>{{.Name}}</td><td>{{.Product}}</td><td>{{.Version}}</td><td>{{.Confidence}}%</td><td>{{if .TLS}}{{.TLS.Version}}<br>{{.TLS.Cipher}}<br>{{if .TLS.Subject}}Subject: {{.TLS.Subject}}<br>{{end}}{{if .TLS.Issuer}}Issuer: {{.TLS.Issuer}}<br>{{end}}{{if .TLS.NotAfter}}Expires: {{.TLS.NotAfter}}{{end}}{{end}}</td><td><code>{{.Banner}}</code></td></tr>{{end}}</table>
<h2>Findings</h2>
<table><tr><th>Target</th><th>Severity</th><th>ID</th><th>Risk</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Port</th><th>Title</th><th>Evidence</th><th>Threat Intel</th><th>Remediation</th></tr>
{{range .Findings}}<tr><td>{{.Target}}</td><td class="{{.Severity}}">{{.Severity}}</td><td>{{.ID}}</td><td class="risk">{{printf "%.1f" .RiskScore}}</td><td>{{if .CVSSScore}}{{printf "%.1f" .CVSSScore}}{{end}}</td><td>{{if .EPSSScore}}{{printf "%.2f%%" (percent .EPSSScore)}}{{end}}</td><td class="kev">{{if .KEV}}YES{{end}}</td><td>{{.Port}}</td><td>{{.Title}}</td><td>{{.Evidence}}</td><td>{{range .ThreatIntel}}{{.Source}} {{if .Confidence}}({{.Confidence}}%){{end}} {{.Labels}}<br>{{end}}</td><td>{{.Remediation}}</td></tr>{{end}}</table>
</body></html>`
	funcs := template.FuncMap{"percent": func(v float64) float64 { return v * 100 }}
	t, err := template.New("report").Funcs(funcs).Parse(tpl)
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return t.Execute(file, r)
}

func writeSARIF(path string, r model.Report) error {
	rules := map[string]map[string]any{}
	var results []map[string]any
	for _, f := range r.Findings {
		rules[f.ID] = map[string]any{
			"id":               f.ID,
			"name":             strings.ReplaceAll(f.ID, "-", "_"),
			"shortDescription": map[string]string{"text": f.Title},
			"help":             map[string]string{"text": f.Remediation},
		}
		message := fmt.Sprintf("%s (%s tcp/%d): %s", f.Title, f.Target, f.Port, f.Evidence)
		if f.RiskScore > 0 {
			message += fmt.Sprintf(" Risk %.1f/100.", f.RiskScore)
		}
		results = append(results, map[string]any{
			"ruleId":  f.ID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]string{"text": message},
		})
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ruleList := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "ABSL Recon", "version": r.Version, "rules": ruleList}},
			"results": results,
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
