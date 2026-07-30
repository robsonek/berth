package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/status"
)

func TestSanitizeCellEscapesHostileInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clear-screen", "\x1b[2Jv1.0", `\x1b[2Jv1.0`},
		{"osc-clipboard", "\x1b]52;c;ZXZpbA==\x07", `\x1b]52;c;ZXZpbA==\x07`},
		{"csi-color-run", "ok\x1b[31mFAKE\x1b[0m", `ok\x1b[31mFAKE\x1b[0m`},
		{"carriage-return-overwrite", "clean\rHACKED", `clean\rHACKED`},
		{"tab-into-next-column", "v1\tEXTRA", `v1\tEXTRA`},
		{"newline-into-next-row", "v1\nfake row", `v1\nfake row`},
		{"del", "a\x7fb", `a\x7fb`},
		{"c1-csi-codepoint", "a\u009bb", `a\x9bb`},
		{"raw-invalid-byte", "a\x9bb", `a\x9bb`},
		{"benign-ascii", "berth 0.27.1 (clean)", "berth 0.27.1 (clean)"},
		{"benign-utf8", "żółć æ 日本語 · ✓", "żółć æ 日本語 · ✓"},
		{"already-escaped-is-stable", `\x1b[2J`, `\x1b[2J`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeCell(tc.in); got != tc.want {
				t.Errorf("SanitizeCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeBlockKeepsDeliberateNewlines(t *testing.T) {
	in := "credentials missing; run:\n  berth secret set\x1b[2J"
	want := "credentials missing; run:\n  berth secret set" + `\x1b[2J`
	if got := SanitizeBlock(in); got != want {
		t.Errorf("SanitizeBlock(%q) = %q, want %q", in, got, want)
	}
}

// The finding's actual claim, proven at the renderer level: a hostile
// manifest VERSION (and a hostile probe error) must not be able to move the
// cursor, clear the screen or feed the tabwriter a fabricated column — no
// control byte may survive into the plain table.
func TestFleetTableHostileVersionCannotDriveTheTerminal(t *testing.T) {
	h := hostFixture()
	h.Provisioned.Version = "\x1b[2J\x1b[1;1H0.99-fake\tEXTRA"
	h.ProbeErrors = []string{"services: \x1b]52;c;ZXZpbA==\x07boom\rok"}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, ctrl := range []string{"\x1b", "\r", "\x07"} {
		if strings.Contains(out, ctrl) {
			t.Errorf("a control byte %q from the host reached the terminal:\n%q", ctrl, out)
		}
	}
	// Visibly escaped, not silently deleted — the operator must see that the
	// host sent something that was not a version string.
	for _, want := range []string{`\x1b[2J`, `\t`, `\r`} {
		if !strings.Contains(out, want) {
			t.Errorf("hostile input must be escaped visibly (%q missing):\n%s", want, out)
		}
	}
	// The row shape survives: the version cell stays one cell wide, so the
	// header and the host row still agree on the column count.
	header, row := "", ""
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "HOST"):
			header = line
		case strings.HasPrefix(line, "prod"):
			row = line
		}
	}
	if header == "" || row == "" {
		t.Fatalf("missing header or host row:\n%s", out)
	}
}

// Same guarantee for the provisioning renderer: reasons, changes, warnings
// and error text are remote-derived and must come out escaped.
func TestPlainRendererSanitizesEventText(t *testing.T) {
	var buf bytes.Buffer
	err := NewPlainRenderer(&buf, true).Render(feed(
		provision.Event{Step: "php", Kind: provision.EventSatisfied, Reason: "\x1b[31mall good\x1b[0m"},
		provision.Event{Step: "site", Kind: provision.EventApplied, Changes: []string{"write\rvhost"}},
		provision.Event{Step: "nginx", Kind: provision.EventFailed,
			Warnings: []string{"deferring\rvalidation"}, Err: errors.New("config broken\x1b[2J")},
	))
	if err == nil {
		t.Fatal("a failed event must surface as the terminal error")
	}
	out := buf.String()
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, '\r') {
		t.Errorf("control bytes reached the plain renderer output:\n%q", out)
	}
	for _, want := range []string{`\x1b[31m`, `\x1b[2J`, `write\rvhost`, `deferring\rvalidation`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected visible escape %q in:\n%s", want, out)
		}
	}
}

// And for the TUI's model view (the styled renderer): the DATA is sanitized
// before lipgloss composes its own styling, so berth's styling may add
// escapes of its own but none of the host's may survive inside the message
// text.
func TestStepModelViewSanitizesFailureAndWarnings(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "nginx", Kind: provision.EventFailed,
		Warnings: []string{"later\rmaybe"}, Err: errors.New("boom\x1b[2J")})
	out := m.view()
	if strings.Contains(out, "\x1b[2J") || strings.Contains(out, "\r") {
		t.Errorf("host-derived control sequences survived into the TUI view:\n%q", out)
	}
	for _, want := range []string{`\x1b[2J`, `\r`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected visible escape %q in:\n%s", want, out)
		}
	}
}
