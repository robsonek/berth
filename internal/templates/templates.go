// Package templates renders berth-managed config files from embedded templates.
package templates

import (
	"bytes"
	"embed"
	"text/template"
)

//go:embed *.tmpl
var files embed.FS

var tmpl = template.Must(template.New("").ParseFS(files, "*.tmpl"))

// Render executes the named template (e.g. "nginx_http.conf.tmpl") with data.
func Render(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# managed by berth\n")
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
