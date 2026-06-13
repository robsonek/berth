package ui

import (
	"bytes"
	"testing"
)

func TestNewPicksPlainWhenNotTTY(t *testing.T) {
	r := New(&bytes.Buffer{}, false)
	if _, ok := r.(*PlainRenderer); !ok {
		t.Errorf("non-TTY should yield PlainRenderer, got %T", r)
	}
}

func TestNewPicksTUIWhenTTY(t *testing.T) {
	r := New(&bytes.Buffer{}, true)
	if _, ok := r.(*TUIRenderer); !ok {
		t.Errorf("TTY should yield TUIRenderer, got %T", r)
	}
}
