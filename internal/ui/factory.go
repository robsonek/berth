package ui

import "io"

// New returns the live TUI renderer on a TTY, or the plain renderer otherwise.
func New(w io.Writer, isTTY bool) Renderer {
	if isTTY {
		return NewTUIRenderer(w)
	}
	return NewPlainRenderer(w)
}
