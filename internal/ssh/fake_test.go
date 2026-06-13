package ssh

import (
	"context"
	"testing"
)

func TestFakeRunnerMatchesAndRecords(t *testing.T) {
	f := NewFakeRunner()
	f.On("id -u deploy", Result{ExitCode: 1}) // user missing
	f.On("getent passwd deploy", Result{Stdout: "deploy:x:1001:", ExitCode: 0})

	r, err := f.Run(context.Background(), "id -u deploy", nil)
	if err != nil || r.ExitCode != 1 {
		t.Fatalf("Run() = %+v, %v; want exit 1", r, err)
	}
	if got := f.Calls()[0].Cmd; got != "id -u deploy" {
		t.Errorf("recorded cmd = %q", got)
	}
}

func TestFakeRunnerUnexpectedCmdErrors(t *testing.T) {
	f := NewFakeRunner()
	if _, err := f.Run(context.Background(), "rm -rf /", nil); err == nil {
		t.Error("expected error for unstubbed command")
	}
}

func TestFakeRunnerWriteFileRecorded(t *testing.T) {
	f := NewFakeRunner()
	err := f.WriteFile(context.Background(), FileSpec{Path: "/etc/x", Content: []byte("y"), Mode: 0o644})
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if len(f.Writes()) != 1 || f.Writes()[0].Path != "/etc/x" {
		t.Errorf("writes = %+v", f.Writes())
	}
}
