package ui

import "io"

// New returns the live TUI renderer on a TTY, or the plain renderer
// otherwise; verbose applies only to the plain renderer (the caller never
// selects the TUI for a verbose run).
func New(w io.Writer, isTTY, verbose bool) Renderer {
	if isTTY {
		return NewTUIRenderer(w)
	}
	return NewPlainRenderer(w, verbose)
}
