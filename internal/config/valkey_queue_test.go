package config

import (
	"strings"
	"testing"
)

// valkey_queue is a second per-site Valkey instance beside the cache one, so
// it is meaningless without valkey: true — Validate must say so by name.
func TestValkeyQueueRequiresValkey(t *testing.T) {
	s := base()
	s.ValkeyQueue = true
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "valkey_queue") || !strings.Contains(err.Error(), "valkey: true") {
		t.Fatalf("valkey_queue without valkey must be refused naming both knobs; got %v", err)
	}
	s.Valkey = true
	if err := s.Validate(); err != nil {
		t.Fatalf("valkey + valkey_queue must validate; got %v", err)
	}
	// Load path: the yaml key binds through mapstructure, and a config that
	// never mentions the knob keeps it off.
	loaded, err := Load(writeTmpConfig(t, `id: vq-test
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
valkey: true
valkey_queue: true
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !loaded.ValkeyQueue {
		t.Error("valkey_queue: true did not bind to Server.ValkeyQueue")
	}
	plain, err := Load(writeTmpConfig(t, `id: vq-test-off
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
valkey: true
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if plain.ValkeyQueue {
		t.Error("a config without valkey_queue must leave it off")
	}
	if _, err := Load(writeTmpConfig(t, `id: vq-test-bad
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
valkey_queue: true
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`)); err == nil || !strings.Contains(err.Error(), "valkey_queue") {
		t.Errorf("Load must refuse valkey_queue without valkey; got %v", err)
	}
}

// reHostname accepts a hyphenated last label, so app.example.com-queue is a
// valid domain whose pool (app_example_com-queue) equals the queue instance
// name of app.example.com — two renderings of one unit file. Refused only
// while the knob is on: configs without it are untouched.
func TestValkeyQueueRefusesQueueSuffixedPool(t *testing.T) {
	s := base()
	s.Valkey = true
	s.Sites[0].Domain = "app.example.com-queue"
	if err := s.Validate(); err != nil {
		t.Fatalf("without valkey_queue a -queue pool is an ordinary domain; got %v", err)
	}
	s.ValkeyQueue = true
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "collide") || !strings.Contains(err.Error(), "app.example.com-queue") {
		t.Fatalf("with valkey_queue a -queue pool must be refused as a collision; got %v", err)
	}
}

func TestValkeyQueueMaxmemory(t *testing.T) {
	var zero Tuning
	if got := zero.ValkeyQueueMaxmemoryEff(); got != "256mb" {
		t.Errorf("ValkeyQueueMaxmemoryEff() default = %q, want 256mb", got)
	}
	// Distinct, non-default limits for BOTH instances: the queue accessor must
	// read its own field, not the cache one (and vice versa).
	tn := Tuning{ValkeyMaxmemory: "768mb", ValkeyQueueMaxmemory: "96mb"}
	if got := tn.ValkeyQueueMaxmemoryEff(); got != "96mb" {
		t.Errorf("ValkeyQueueMaxmemoryEff() = %q, want 96mb", got)
	}
	if got := tn.ValkeyMaxmemoryEff(); got != "768mb" {
		t.Errorf("ValkeyMaxmemoryEff() = %q, want 768mb (cache limit must not follow the queue knob)", got)
	}
	bad := Tuning{ValkeyQueueMaxmemory: "abc"}
	if err := bad.validate(); err == nil || !strings.Contains(err.Error(), "tuning.valkey_queue_maxmemory") {
		t.Errorf("an invalid queue limit must be refused by name; got %v", err)
	}
	loaded, err := Load(writeTmpConfig(t, `id: vq-mem
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
valkey: true
valkey_queue: true
tuning:
  valkey_queue_maxmemory: 96mb
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Tuning.ValkeyQueueMaxmemory != "96mb" {
		t.Errorf("tuning.valkey_queue_maxmemory did not bind: %q", loaded.Tuning.ValkeyQueueMaxmemory)
	}
}

// The queue instance's derived names: unit, socket (same runtime dir as the
// cache socket, a shorter leaf) and data dir (a sibling of the cache one).
func TestValkeyQueueDerivations(t *testing.T) {
	if got := ValkeyQueueInstanceUnit("app.example.com"); got != "berth-valkey-app_example_com-queue.service" {
		t.Errorf("ValkeyQueueInstanceUnit = %q", got)
	}
	if got := ValkeyQueueSocketPath("app_example_com"); got != "/run/berth-valkey/app_example_com/queue.sock" {
		t.Errorf("ValkeyQueueSocketPath = %q", got)
	}
	if got := ValkeyQueueDataDir("app_example_com"); got != "/var/lib/berth-valkey/app_example_com-queue" {
		t.Errorf("ValkeyQueueDataDir = %q", got)
	}
}
