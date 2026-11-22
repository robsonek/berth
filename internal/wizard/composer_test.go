package wizard

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The wizard's Composer auto-update answer maps onto the tri-state config
// knob: the default (on) is left unset so the written YAML carries no
// `composer:` block and keeps following berth's default, while an explicit
// "no" is pinned as `auto_update: false`.
func TestToServerComposerAutoUpdateMapping(t *testing.T) {
	a := defaults()
	if !a.ComposerAutoUpdate {
		t.Fatal("defaults().ComposerAutoUpdate = false, want true (berth's default is on)")
	}
	if srv := a.ToServer(); srv.Composer.AutoUpdate != nil {
		t.Errorf("answer yes must leave Composer.AutoUpdate unset; got %v", *srv.Composer.AutoUpdate)
	}
	a.ComposerAutoUpdate = false
	srv := a.ToServer()
	if srv.Composer.AutoUpdate == nil || *srv.Composer.AutoUpdate {
		t.Errorf("answer no must pin Composer.AutoUpdate=false; got %v", srv.Composer.AutoUpdate)
	}
	if srv.Composer.AutoUpdateEnabled() {
		t.Error("answer no must disable the self-update cron")
	}
}

// The written YAML is what the mapping is for: with the default answer the
// file carries no composer: block at all (it keeps following berth's
// default), and an explicit "no" writes exactly the opt-out.
func TestWrittenYAMLCarriesComposerOnlyWhenOptedOut(t *testing.T) {
	a := defaults()
	b, err := yaml.Marshal(a.ToServer())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "composer") {
		t.Errorf("default answers must write no composer: block; got:\n%s", b)
	}
	a.ComposerAutoUpdate = false
	if b, err = yaml.Marshal(a.ToServer()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "composer:\n    auto_update: false\n") {
		t.Errorf("the opt-out must be written as composer.auto_update: false; got:\n%s", b)
	}
}
