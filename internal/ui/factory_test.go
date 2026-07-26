package ui

import (
	"bytes"
	"testing"
)

func TestNewPicksPlainWhenNotTTY(t *testing.T) {
	r := New(&bytes.Buffer{}, false, false)
	if _, ok := r.(*PlainRenderer); !ok {
		t.Errorf("non-TTY should yield PlainRenderer, got %T", r)
	}
}

func TestNewPicksTUIWhenTTY(t *testing.T) {
	r := New(&bytes.Buffer{}, true, false)
	if _, ok := r.(*TUIRenderer); !ok {
		t.Errorf("TTY should yield TUIRenderer, got %T", r)
	}
}

func TestNewVerbosePicksPlain(t *testing.T) {
	r := New(&bytes.Buffer{}, false, true)
	if _, ok := r.(*PlainRenderer); !ok {
		t.Errorf("verbose non-TTY should yield PlainRenderer, got %T", r)
	}
}
