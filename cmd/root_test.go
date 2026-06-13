package cmd

import (
	"bytes"
	"testing"
)

func TestRootVersionFlag(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected version output, got none")
	}
}
