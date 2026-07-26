package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func siteKeyServer() *config.Server {
	return &config.Server{
		Host: "203.0.113.10",
		Sites: []config.Site{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "alpha", Repository: "git@github.com:acme/a.git"},
			{Domain: "b.example.com", DeployPath: "/srv/b", User: "beta"},
		},
	}
}

func TestPrintDeployKeysAllSites(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /home/alpha/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 0, Stdout: "ssh-ed25519 AAAAC3Nz alpha@github.com\n"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, siteKeyServer(), f, ""); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "ssh-ed25519 AAAAC3Nz alpha@github.com") {
		t.Errorf("missing the deploy key for a.example.com:\n%s", got)
	}
	if !strings.Contains(got, "b.example.com") || !strings.Contains(got, "no deploy key is managed") {
		t.Errorf("the repository-less site must be reported, not skipped silently:\n%s", got)
	}
}

func TestPrintDeployKeysDomainFilter(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /home/alpha/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 0, Stdout: "ssh-ed25519 AAAAC3Nz alpha@github.com\n"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, siteKeyServer(), f, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "b.example.com") {
		t.Errorf("domain filter must exclude other sites:\n%s", out.String())
	}
}

func TestPrintDeployKeysUnknownDomain(t *testing.T) {
	var out bytes.Buffer
	err := printDeployKeys(context.Background(), &out, siteKeyServer(), bssh.NewFakeRunner(), "nope.example.com")
	if err == nil || !strings.Contains(err.Error(), "no site with domain") {
		t.Errorf("unknown domain must error; got %v", err)
	}
}

func TestPrintDeployKeysNotProvisioned(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /home/alpha/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 1, Stderr: "No such file"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, siteKeyServer(), f, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "not generated yet") {
		t.Errorf("missing key must be reported as not provisioned:\n%s", out.String())
	}
}

func TestPrintDeployKeysSingleSiteDefaultUser(t *testing.T) {
	// A single-site config with no explicit user runs as the domain-derived
	// account — the key path must follow SiteUser, not the raw config field.
	s := &config.Server{
		Host:  "203.0.113.10",
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/srv/a", Repository: "git@github.com:acme/a.git"}},
	}
	user := config.DerivedSiteUser("a.example.com")
	f := bssh.NewFakeRunner()
	f.On("cat /home/"+user+"/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 0, Stdout: "ssh-ed25519 AAAAC3Nz " + user + "@github.com\n"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, s, f, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), user+"@github.com") {
		t.Errorf("expected the derived user's key printed:\n%s", out.String())
	}
}

func TestSiteKeySubcommandRegistered(t *testing.T) {
	root := newRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "site" {
			for _, sub := range c.Commands() {
				if sub.Name() == "key" {
					return
				}
			}
		}
	}
	t.Error("site key subcommand not registered")
}
