package matrix

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"time"
)

const matrixHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>eyeexam — ATT&amp;CK matrix</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; margin: 1.5em; color: #1a1a1a; }
h1 { font-size: 1.4em; margin-bottom: 0.2em; }
.window { color: #555; font-size: 0.85em; margin-bottom: 1.5em; }
.matrix { display: grid; gap: 6px; align-items: start; grid-template-columns: repeat({{.NumTactics}}, minmax(160px, 1fr)); }
.col h2 { font-size: 0.85em; margin: 0 0 6px; padding: 4px 6px; background: #eee; border-radius: 3px; }
.cell { padding: 6px 8px; margin-bottom: 4px; border-radius: 3px; font-size: 0.78em; line-height: 1.25; }
.cell .id { font-weight: 600; }
.cell .name { display: block; }
.cell .counts { display: block; color: rgba(0,0,0,0.6); margin-top: 2px; font-size: 0.95em; }
.cell.green  { background: #c6e8c2; }
.cell.yellow { background: #f4e4a1; }
.cell.red    { background: #f0b3ad; }
.cell.grey   { background: #e7e7e7; color: #666; }
.legend { margin-top: 1.5em; font-size: 0.8em; }
.legend span { display: inline-block; padding: 2px 8px; margin-right: 8px; border-radius: 2px; }
.drift { margin-top: 2em; }
.drift h2 { font-size: 1em; }
.drift table { border-collapse: collapse; font-size: 0.85em; }
.drift td, .drift th { padding: 4px 8px; border: 1px solid #ddd; text-align: left; }
.drift td.from { background: #c6e8c2; }
.drift td.to.red { background: #f0b3ad; }
.drift td.to.yellow { background: #f4e4a1; }
</style>
</head>
<body>
<h1>ATT&amp;CK coverage matrix</h1>
<div class="window">window {{.Window.Since.Format "2006-01-02"}} → {{.Window.Until.Format "2006-01-02"}} · generated {{.GeneratedAt.Format "2006-01-02 15:04:05Z07:00"}}</div>

<div class="matrix">
{{range .Tactics}}
  <div class="col">
    <h2>{{.Name}} <small>({{.ID}})</small></h2>
    {{range .Cells}}
      <div class="cell {{.State}}" title="{{.TechniqueID}}">
        <span class="id">{{.TechniqueID}}</span>
        <span class="name">{{.TechniqueName}}</span>
        {{if or .Caught .Missed .Uncertain}}
          <span class="counts">✓ {{.Caught}} · ✗ {{.Missed}} · ? {{.Uncertain}}</span>
        {{end}}
      </div>
    {{end}}
  </div>
{{end}}
</div>

<div class="legend">
  <span class="cell green">caught</span>
  <span class="cell yellow">uncertain</span>
  <span class="cell red">missed</span>
  <span class="cell grey">no test</span>
</div>

{{if .Drift}}
<div class="drift">
  <h2>Recent regressions</h2>
  <table>
    <thead><tr><th>Technique</th><th>Was</th><th>Now</th><th>Last run</th></tr></thead>
    <tbody>
      {{range .Drift}}
      <tr>
        <td><strong>{{.TechniqueID}}</strong> — {{.TechniqueName}}</td>
        <td class="from {{.From}}">{{.From}}</td>
        <td class="to {{.To}}">{{.To}}</td>
        <td>{{.At.Format "2006-01-02 15:04Z"}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</div>
{{end}}
</body>
</html>
`

var matrixTpl = template.Must(template.New("matrix").Parse(matrixHTML))

// RenderHTML writes a self-contained HTML document for m.
func (m *Matrix) RenderHTML(w io.Writer) error {
	type viewModel struct {
		*Matrix
		NumTactics int
	}
	if m.GeneratedAt.IsZero() {
		m.GeneratedAt = time.Now().UTC()
	}
	var buf bytes.Buffer
	if err := matrixTpl.Execute(&buf, viewModel{Matrix: m, NumTactics: len(m.Tactics)}); err != nil {
		return fmt.Errorf("render matrix html: %w", err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}
