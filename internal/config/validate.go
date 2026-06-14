package config

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	reHostname = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	reSQLIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	rePHPVer   = regexp.MustCompile(`^\d+\.\d+$`)
	reEmail    = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

var allowedPHPVersions = map[string]bool{"8.2": true, "8.3": true, "8.4": true, "8.5": true}
var allowedPHPSources = map[string]bool{"auto": true, "sury": true, "debian": true}
var allowedNginxSources = map[string]bool{"debian": true, "nginx": true}
var allowedDBSources = map[string]bool{"debian": true, "mariadb": true}

// Validate checks every field that reaches a shell, SQL statement, or path.
func (s *Server) Validate() error {
	if !reHostname.MatchString(s.Host) {
		return fmt.Errorf("host %q is not a valid hostname or IP", s.Host)
	}
	if s.SSH.Port < 1 || s.SSH.Port > 65535 {
		return fmt.Errorf("ssh.port %d out of range", s.SSH.Port)
	}
	if !rePHPVer.MatchString(s.PHP.Version) || !allowedPHPVersions[s.PHP.Version] {
		return fmt.Errorf("php.version %q is not an allowed version", s.PHP.Version)
	}
	if !allowedPHPSources[s.PHP.Source] {
		return fmt.Errorf("php.source %q must be auto, sury, or debian", s.PHP.Source)
	}
	if !allowedNginxSources[s.Nginx.Source] {
		return fmt.Errorf("nginx.source %q must be debian or nginx", s.Nginx.Source)
	}
	if s.Database.Engine != "mariadb" {
		return fmt.Errorf("database.engine %q unsupported (v1 supports mariadb)", s.Database.Engine)
	}
	if !allowedDBSources[s.Database.Source] {
		return fmt.Errorf("database.source %q must be debian or mariadb", s.Database.Source)
	}
	if !reSQLIdent.MatchString(s.Database.Name) {
		return fmt.Errorf("database.name %q is not a valid SQL identifier", s.Database.Name)
	}
	if !reSQLIdent.MatchString(s.Database.User) {
		return fmt.Errorf("database.user %q is not a valid SQL identifier", s.Database.User)
	}
	if len(s.Sites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	for i := range s.Sites {
		if err := s.Sites[i].validate(); err != nil {
			return fmt.Errorf("site %d: %w", i, err)
		}
	}
	return nil
}

func (st *Site) validate() error {
	if !reHostname.MatchString(st.Domain) {
		return fmt.Errorf("domain %q is not a valid hostname", st.Domain)
	}
	if !path.IsAbs(st.DeployPath) || strings.ContainsAny(st.DeployPath, " ;&|$`\n\t") {
		return fmt.Errorf("deploy_path %q must be an absolute path without shell metacharacters", st.DeployPath)
	}
	if st.Repository != "" && !validGitURL(st.Repository) {
		return fmt.Errorf("repository %q must be an SSH git URL (scp-like or ssh://); HTTPS is out of v1 scope", st.Repository)
	}
	if st.SSL {
		if st.SSLEmail == "" {
			return fmt.Errorf("ssl_email is required when ssl is true")
		}
		if !reEmail.MatchString(st.SSLEmail) {
			return fmt.Errorf("ssl_email %q is not a valid email address", st.SSLEmail)
		}
	}
	return nil
}

// validGitURL accepts only SSH git URLs in v1 (scp-like git@host:path or
// ssh://…), because berth generates an SSH deploy key for the repository.
// HTTPS repositories are out of v1 scope (no deploy key would be generated).
func validGitURL(s string) bool {
	if strings.HasPrefix(s, "ssh://") {
		u, err := url.Parse(s)
		return err == nil && u.Host != "" && strings.Trim(u.Path, "/") != ""
	}
	// scp-like: user@host:path
	return regexp.MustCompile(`^[\w.-]+@[\w.-]+:[\w./~-]+$`).MatchString(s)
}

// GitHost extracts the host from a repository URL for known_hosts (Plan 2 uses it).
func GitHost(repo string) (string, error) {
	if strings.HasPrefix(repo, "http") || strings.HasPrefix(repo, "ssh://") {
		u, err := url.Parse(repo)
		if err != nil {
			return "", err
		}
		return u.Hostname(), nil
	}
	at := strings.Index(repo, "@")
	colon := strings.Index(repo, ":")
	if at < 0 || colon < 0 || colon < at {
		return "", fmt.Errorf("cannot parse host from %q", repo)
	}
	return repo[at+1 : colon], nil
}
