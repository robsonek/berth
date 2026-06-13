package wizard

import (
	"os"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func valid() Answers {
	return Answers{
		Name: "example", Host: "203.0.113.10", Port: 22, Key: "~/.ssh/id_ed25519",
		PHPVersion: "8.5", PHPSource: "auto", DBName: "myapp", DBUser: "myapp",
		Valkey: true, Queue: true, Scheduler: true,
		Domain: "app.example.com", DeployPath: "/home/deploy/myapp",
	}
}

func TestWriteThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	path, err := valid().Write()
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%s) error = %v", path, err)
	}
	if got.PHP.Version != "8.5" || got.Sites[0].Domain != "app.example.com" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestWriteRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)
	if _, err := valid().Write(); err != nil {
		t.Fatal(err)
	}
	if _, err := valid().Write(); err == nil {
		t.Error("expected refusal to overwrite existing config")
	}
}

func TestWriteValidatesAnswers(t *testing.T) {
	a := valid()
	a.PHPVersion = "9.9"
	if _, err := a.Write(); err == nil {
		t.Error("expected validation error for bad php version")
	}
}
