package wizard

import "testing"

func TestToServerOpsBlocks(t *testing.T) {
	a := defaults()
	a.Name, a.Host = "t", "203.0.113.10"
	a.System = SystemAnswers{Swap: "2G", Sysctl: true}
	a.CloudflareOnly = true
	a.Backups = BackupsAnswers{Enabled: true, RetentionDays: 14, Schedule: "0 2 * * 0"}
	a.Sites = []SiteAnswers{
		{Domain: "a.example.com", DeployPath: "/srv/a", DBName: "a", DBUser: "a",
			SchedulerOverride: "inherit", CloudflareOverride: "off", BackupsOverride: "on"},
		{Domain: "b.example.com", DeployPath: "/srv/b", DBName: "b", DBUser: "b",
			SchedulerOverride: "inherit", CloudflareOverride: "inherit", BackupsOverride: "inherit"},
	}
	srv := a.ToServer()

	if srv.System.Swap != "2G" || !srv.System.Sysctl {
		t.Errorf("system = %+v, want {2G true}", srv.System)
	}
	if !srv.CloudflareOnly {
		t.Error("server CloudflareOnly should be true")
	}
	if !srv.Backups.Enabled || srv.Backups.Retention != 14 || srv.Backups.Schedule != "0 2 * * 0" {
		t.Errorf("backups = %+v, want {true 14 0 2 * * 0}", srv.Backups)
	}
	// site a: cloudflare off, backups on (explicit *bool)
	if srv.Sites[0].CloudflareOnly == nil || *srv.Sites[0].CloudflareOnly {
		t.Error("site a CloudflareOnly should be *false")
	}
	if srv.Sites[0].Backups == nil || !*srv.Sites[0].Backups {
		t.Error("site a Backups should be *true")
	}
	// site b: both inherit => nil
	if srv.Sites[1].CloudflareOnly != nil || srv.Sites[1].Backups != nil {
		t.Error("site b overrides should be nil (inherit)")
	}
	if err := srv.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
