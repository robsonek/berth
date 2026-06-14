package config

import "testing"

func base() *Server {
	return &Server{
		Host:     "203.0.113.10",
		SSH:      SSH{User: "root", Port: 22},
		PHP:      PHP{Version: "8.5", Source: "auto"},
		Nginx:    Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Name: "myapp", User: "myapp", Source: "debian"},
		Sites:    []Site{{Domain: "app.example.com", DeployPath: "/home/deploy/myapp"}},
	}
}

func TestValidateOK(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidatePostgresEngine(t *testing.T) {
	// postgres + pgdg upstream is valid.
	s := base()
	s.Database.Engine = "postgres"
	s.Database.Source = "pgdg"
	if err := s.Validate(); err != nil {
		t.Errorf("postgres + pgdg should be valid; got %v", err)
	}
	// postgres + debian is valid too.
	s.Database.Source = "debian"
	if err := s.Validate(); err != nil {
		t.Errorf("postgres + debian should be valid; got %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Server){
		"bad php version":  func(s *Server) { s.PHP.Version = "9.9" },
		"bad php source":   func(s *Server) { s.PHP.Source = "ppa" },
		"bad db name":      func(s *Server) { s.Database.Name = "my-app; DROP" },
		"bad engine":       func(s *Server) { s.Database.Engine = "oracle" },
		"bad nginx source": func(s *Server) { s.Nginx.Source = "openresty" },
		"bad db source":    func(s *Server) { s.Database.Source = "percona" },
		"pg with mariadb source": func(s *Server) {
			s.Database.Engine = "postgres"
			s.Database.Source = "mariadb" // wrong upstream for postgres
		},
		"relative path":   func(s *Server) { s.Sites[0].DeployPath = "deploy/x" },
		"shell meta path": func(s *Server) { s.Sites[0].DeployPath = "/home/$(whoami)" },
		"ssl no email":    func(s *Server) { s.Sites[0].SSL = true },
		"ssl bad email": func(s *Server) {
			s.Sites[0].SSL = true
			s.Sites[0].SSLEmail = "x@y.com; reboot"
		},
		"bad port": func(s *Server) { s.SSH.Port = 0 },
		"no sites": func(s *Server) { s.Sites = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(s)
			if err := s.Validate(); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestGitHost(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:owner/repo.git":        "github.com",
		"https://github.com/owner/repo.git":    "github.com",
		"ssh://git@example.org:22/owner/r.git": "example.org",
	} {
		got, err := GitHost(in)
		if err != nil || got != want {
			t.Errorf("GitHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
