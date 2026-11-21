package wizard

import "testing"

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
