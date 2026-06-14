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

// markerText is the body of the "managed by berth" marker line; the comment
// prefix is chosen per config-file syntax.
const markerText = "managed by berth"

// Render executes the named template with data, prefixed with a hash-comment
// marker. Use it for formats where '#' starts a comment (nginx, sudoers, cron,
// .env, supervisor).
func Render(name string, data any) ([]byte, error) {
	return render("# "+markerText, name, data)
}

// RenderINI is like Render but uses a semicolon-comment marker, for INI-style
// files whose parser rejects '#' lines (notably PHP-FPM pool configs).
func RenderINI(name string, data any) ([]byte, error) {
	return render("; "+markerText, name, data)
}

func render(marker, name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(marker + "\n")
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
