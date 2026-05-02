package report

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
)

//go:embed templates/*.html
var tplFS embed.FS

// pages binds each report's body template against the shared layout.
// Each page's "content" block is parsed alongside _layout.html so the
// {{template "layout" .}} dispatch resolves; pages live in their own
// templates because html/template's "define" namespace is global per
// parsed *Template.
var pages = func() map[string]*template.Template {
	out := map[string]*template.Template{}
	for _, name := range []string{"coverage.html", "run.html", "matrix.html"} {
		t := template.Must(template.New(name).ParseFS(
			tplFS, "templates/_layout.html", "templates/"+name,
		))
		out[name] = t
	}
	return out
}()

// renderHTML executes the named page template against data and returns
// the rendered bytes. Data must include Title and GeneratedAt fields
// (or be wrapped in a struct that does) — _layout.html references them.
func renderHTML(page string, data any) ([]byte, error) {
	t, ok := pages[page]
	if !ok {
		return nil, fmt.Errorf("report: unknown page %q", page)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		return nil, fmt.Errorf("render %s: %w", page, err)
	}
	return buf.Bytes(), nil
}
