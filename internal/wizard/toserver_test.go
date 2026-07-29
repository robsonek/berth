package wizard

import (
	"reflect"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func TestToServerOpsBlocks(t *testing.T) {
	a := defaults()
	a.Name, a.Host = "t", "203.0.113.10"
	a.ID = "test-machine-0001"
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

func TestToServerCarriesSystemTimezone(t *testing.T) {
	a := Answers{System: SystemAnswers{Timezone: "Europe/Warsaw"}}
	if s := a.ToServer(); s.System.Timezone != "Europe/Warsaw" {
		t.Errorf("ToServer() dropped system.timezone: %+v", s.System)
	}
}

func TestToServerCarriesPHPTuning(t *testing.T) {
	a := Answers{Tuning: TuningAnswers{
		PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
	}}
	s := a.ToServer()
	if s.Tuning.PHPMemoryLimit != "768M" || s.Tuning.PHPUploadMax != "64M" ||
		s.Tuning.PHPMaxExecutionTime != 120 || s.Tuning.PHPMaxInputVars != 5000 {
		t.Errorf("ToServer() dropped php tuning fields: %+v", s.Tuning)
	}
}

func TestToServerCarriesSystemHostname(t *testing.T) {
	a := Answers{System: SystemAnswers{Hostname: "web-1.example.com"}}
	if s := a.ToServer(); s.System.Hostname != "web-1.example.com" {
		t.Errorf("ToServer() dropped system.hostname: %+v", s.System)
	}
}

func TestToServerCarriesMariaDBSlowLog(t *testing.T) {
	a := Answers{Tuning: TuningAnswers{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5}}
	s := a.ToServer()
	if !s.Tuning.MariaDBSlowQueryLog || s.Tuning.MariaDBLongQueryTime != 5 {
		t.Errorf("ToServer() dropped the MariaDB slow-log knobs: %+v", s.Tuning)
	}
}

func TestToServerMapsOffsite(t *testing.T) {
	a := defaults()
	a.Name, a.Host = "t", "203.0.113.10"
	a.Backups = BackupsAnswers{Enabled: true, Offsite: OffsiteAnswers{
		Enabled: true, Backend: "s3", Endpoint: "s3.example.com", Bucket: "bkt",
		Prefix: "berth/custom", Schedule: "45 4 * * *",
		KeepDaily: 10, KeepWeekly: 5, KeepMonthly: 12,
	}}
	srv := a.ToServer()
	off := srv.Backups.Offsite
	if off == nil {
		t.Fatal("offsite answers must map to a non-nil config.Offsite")
	}
	want := &config.Offsite{Backend: "s3", Endpoint: "s3.example.com", Bucket: "bkt",
		Prefix: "berth/custom", Schedule: "45 4 * * *",
		Keep: config.OffsiteKeep{Daily: 10, Weekly: 5, Monthly: 12}}
	if !reflect.DeepEqual(off, want) {
		t.Errorf("offsite = %+v, want %+v", off, want)
	}
	a.Backups.Offsite.Enabled = false
	if a.ToServer().Backups.Offsite != nil {
		t.Error("disabled offsite must map to nil")
	}
}

func TestToServerCarriesBreakGlass(t *testing.T) {
	a := Answers{System: SystemAnswers{BreakGlass: true}}
	if s := a.ToServer(); !s.System.BreakGlass {
		t.Errorf("ToServer() dropped system.break_glass: %+v", s.System)
	}
}
