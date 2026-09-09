package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abyssalsec/absl-recon/internal/model"
)

func WriteAll(
	base string,
	r model.Report,
) error {
	dir := filepath.Dir(base)

	if dir != "." {
		if err := os.MkdirAll(
			dir,
			0755,
		); err != nil {
			return err
		}
	}

	if err := writeJSON(
		base+".json",
		r,
	); err != nil {
		return err
	}

	if err := writeCSV(
		base+".csv",
		r,
	); err != nil {
		return err
	}

	if err := writeHTML(
		base+".html",
		r,
	); err != nil {
		return err
	}

	return writeSARIF(
		base+".sarif",
		r,
	)
}

func writeJSON(
	path string,
	r model.Report,
) error {
	data, err :=
		json.MarshalIndent(
			r,
			"",
			"  ",
		)

	if err != nil {
		return err
	}

	return os.WriteFile(
		path,
		data,
		0644,
	)
}

func writeCSV(
	path string,
	r model.Report,
) error {
	file, err :=
		os.Create(path)

	if err != nil {
		return err
	}

	defer file.Close()

	writer :=
		csv.NewWriter(file)

	defer writer.Flush()

	_ = writer.Write(
		[]string{
			"id",
			"severity",
			"port",
			"protocol",
			"title",
			"evidence",
			"remediation",
		},
	)

	for _, finding := range r.Findings {

		_ = writer.Write(
			[]string{
				finding.ID,
				finding.Severity,
				fmt.Sprint(
					finding.Port,
				),
				finding.Protocol,
				finding.Title,
				finding.Evidence,
				finding.Remediation,
			},
		)
	}

	return writer.Error()
}

func writeHTML(
	path string,
	r model.Report,
) error {
	const tpl = `
<!doctype html>

<html>

<head>
<meta charset="utf-8">
<title>ABSL Recon Report</title>

<style>
body {
	font-family: system-ui, sans-serif;
	max-width: 1400px;
	margin: 40px auto;
	padding: 0 20px;
	background: #111;
	color: #eee;
}

table {
	border-collapse: collapse;
	width: 100%;
	margin-bottom: 40px;
}

th, td {
	border: 1px solid #333;
	padding: 10px;
	text-align: left;
	vertical-align: top;
}

th {
	background: #222;
}

code {
	white-space: pre-wrap;
}

.critical {
	color: #ff4d4d;
	font-weight: bold;
}

.high {
	color: #ff7b54;
	font-weight: bold;
}

.medium {
	color: #ffd166;
}

.low {
	color: #aaa;
}
</style>

</head>

<body>

<h1>ABSL Recon</h1>

<p>
Target: {{.Target}}<br>
Version: {{.Version}}<br>
Ports scanned: {{.Scanned}}<br>
Open services: {{len .Services}}<br>
Findings: {{len .Findings}}
</p>

<h2>Services</h2>

<table>

<tr>
<th>Port</th>
<th>Service</th>
<th>Product</th>
<th>Version</th>
<th>Confidence</th>
<th>TLS</th>
<th>Banner</th>
</tr>

{{range .Services}}

<tr>
<td>{{.Port}}/tcp</td>
<td>{{.Name}}</td>
<td>{{.Product}}</td>
<td>{{.Version}}</td>
<td>{{.Confidence}}%</td>

<td>
{{if .TLS}}
{{.TLS.Version}}<br>
{{.TLS.Cipher}}<br>
{{if .TLS.Subject}}Subject: {{.TLS.Subject}}<br>{{end}}
{{if .TLS.Issuer}}Issuer: {{.TLS.Issuer}}<br>{{end}}
{{if .TLS.NotAfter}}Expires: {{.TLS.NotAfter}}{{end}}
{{end}}
</td>

<td><code>{{.Banner}}</code></td>
</tr>

{{end}}

</table>

<h2>Findings</h2>

<table>

<tr>
<th>Severity</th>
<th>ID</th>
<th>Port</th>
<th>Title</th>
<th>Evidence</th>
<th>Remediation</th>
</tr>

{{range .Findings}}

<tr>
<td class="{{.Severity}}">{{.Severity}}</td>
<td>{{.ID}}</td>
<td>{{.Port}}</td>
<td>{{.Title}}</td>
<td>{{.Evidence}}</td>
<td>{{.Remediation}}</td>
</tr>

{{end}}

</table>

</body>

</html>
`

	t, err :=
		template.New(
			"report",
		).
			Parse(tpl)

	if err != nil {
		return err
	}

	file, err :=
		os.Create(path)

	if err != nil {
		return err
	}

	defer file.Close()

	return t.Execute(
		file,
		r,
	)
}

func writeSARIF(
	path string,
	r model.Report,
) error {
	rules :=
		map[string]map[string]any{}

	var results []map[string]any

	for _, finding := range r.Findings {

		rules[finding.ID] =
			map[string]any{
				"id": finding.ID,

				"name": strings.ReplaceAll(
					finding.ID,
					"-",
					"_",
				),

				"shortDescription": map[string]string{
					"text": finding.Title,
				},

				"help": map[string]string{
					"text": finding.Remediation,
				},
			}

		results =
			append(
				results,
				map[string]any{
					"ruleId": finding.ID,

					"level": sarifLevel(
						finding.Severity,
					),

					"message": map[string]string{
						"text": fmt.Sprintf(
							"%s (tcp/%d): %s",
							finding.Title,
							finding.Port,
							finding.Evidence,
						),
					},
				},
			)
	}

	ids :=
		make(
			[]string,
			0,
			len(rules),
		)

	for id := range rules {
		ids =
			append(
				ids,
				id,
			)
	}

	sort.Strings(ids)

	ruleList :=
		make(
			[]map[string]any,
			0,
			len(ids),
		)

	for _, id := range ids {
		ruleList =
			append(
				ruleList,
				rules[id],
			)
	}

	doc :=
		map[string]any{
			"version": "2.1.0",

			"$schema": "https://json.schemastore.org/sarif-2.1.0.json",

			"runs": []any{
				map[string]any{
					"tool": map[string]any{
						"driver": map[string]any{
							"name": "ABSL Recon",

							"version": r.Version,

							"rules": ruleList,
						},
					},

					"results": results,
				},
			},
		}

	data, err :=
		json.MarshalIndent(
			doc,
			"",
			"  ",
		)

	if err != nil {
		return err
	}

	return os.WriteFile(
		path,
		data,
		0644,
	)
}

func sarifLevel(
	severity string,
) string {
	switch strings.ToLower(
		severity,
	) {
	case
		"critical",
		"high":

		return "error"

	case "medium":
		return "warning"

	default:
		return "note"
	}
}
