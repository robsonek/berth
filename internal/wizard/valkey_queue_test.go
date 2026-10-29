package wizard

import (
	"os"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func valkeyQueueAnswers() Answers {
	a := defaults()
	a.Name, a.ID, a.Host = "vq", "test-machine-0001", "203.0.113.10"
	a.Sites = []SiteAnswers{{
		Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr",
		SchedulerOverride: "inherit", WorkersOverride: "inherit", CloudflareOverride: "inherit", BackupsOverride: "inherit",
	}}
	return a
}

// The wizard's queue answers reach the YAML and come back through
// config.Load: the knob and its own maxmemory (a distinct, non-default value
// so a dropped mapping shows).
func TestValkeyQueueAnswersRoundTrip(t *testing.T) {
	a := valkeyQueueAnswers()
	a.Valkey, a.ValkeyQueue = true, true
	a.Tuning.ValkeyQueueMaxmemory = "96mb"
	t.Chdir(t.TempDir())
	path, err := a.Write()
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	srv, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load(%s) error = %v", path, err)
	}
	if !srv.ValkeyQueue {
		t.Error("valkey_queue did not survive the YAML round trip")
	}
	if srv.Tuning.ValkeyQueueMaxmemory != "96mb" {
		t.Errorf("tuning.valkey_queue_maxmemory = %q, want 96mb", srv.Tuning.ValkeyQueueMaxmemory)
	}
}

// Without Valkey the queue answer is meaningless (the config would be
// refused); ToServer drops it so a back-navigated form never produces an
// unsatisfiable server. The hide function on the TUI group is a convenience
// no automated test can drive — this mapping is the contract.
func TestValkeyQueueAnswerDroppedWithoutValkey(t *testing.T) {
	a := valkeyQueueAnswers()
	a.Valkey, a.ValkeyQueue = false, true
	srv := a.ToServer()
	if srv.ValkeyQueue {
		t.Error("ValkeyQueue must be dropped when Valkey is off")
	}
	if err := srv.Validate(); err != nil {
		t.Errorf("the mapped server must validate; got %v", err)
	}
}

// A config written without the queue answer carries no valkey_queue line at
// all (omitempty), so existing wizard output is byte-for-byte unchanged.
func TestValkeyQueueAbsentFromYAMLWhenOff(t *testing.T) {
	a := valkeyQueueAnswers()
	a.Valkey = true
	t.Chdir(t.TempDir())
	path, err := a.Write()
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "valkey_queue") {
		t.Errorf("YAML without the queue answer must not mention valkey_queue:\n%s", raw)
	}
}
