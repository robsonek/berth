package wizard

import "testing"

// The wizard's gzip answer maps onto the tri-state config knob: the default
// (on) is left unset so the written YAML carries no `gzip:` line and keeps
// following berth's default, while an explicit "no" is pinned as `gzip: false`.
func TestToServerGzipMapping(t *testing.T) {
	a := defaults()
	if !a.Gzip {
		t.Fatal("defaults().Gzip = false, want true (berth's default is on)")
	}
	a.Sites = []SiteAnswers{{Domain: "app.example.com", DeployPath: "/var/www/app", DBName: "app", DBUser: "app"}}
	if srv := a.ToServer(); srv.Nginx.Gzip != nil {
		t.Errorf("gzip answer yes must leave Nginx.Gzip unset; got %v", *srv.Nginx.Gzip)
	}
	a.Gzip = false
	srv := a.ToServer()
	if srv.Nginx.Gzip == nil || *srv.Nginx.Gzip {
		t.Errorf("gzip answer no must pin Nginx.Gzip=false; got %v", srv.Nginx.Gzip)
	}
	if srv.Nginx.GzipEnabled() {
		t.Error("gzip answer no must disable the drop-in")
	}
}
