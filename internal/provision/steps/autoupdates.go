package steps

import (
	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
)

// phpUpstream returns the Surý repo and whether this config installs PHP from
// it. The php step and upstreamRepos both go through here, so base's
// unattended-upgrades drop-in can never disagree with the installed source.
// The repo is returned even when unused: the removal branch needs it.
func phpUpstream(s *config.Server) (apt.Repo, bool, error) {
	used, err := useSury(s.PHP)
	return apt.Sury(), used, err
}

// nginxUpstream returns the nginx.org repo and whether the nginx step installs
// from it.
func nginxUpstream(s *config.Server) (apt.Repo, bool) {
	return apt.NginxOrg(), s.Nginx.Source == "nginx"
}

// databaseUpstream returns the engine's producer repo, whether the engine has
// one, and whether the config installs from it (any database.source other
// than "debian").
func databaseUpstream(eng dbpkg.Engine, s *config.Server) (repo apt.Repo, has bool, used bool) {
	repo, has = eng.UpstreamRepo()
	return repo, has, has && s.Database.Source != "debian"
}

// upstreamRepos returns berth's own upstream apt repos this config installs
// from, in a fixed order (sury, nginx, database) — composed from the same
// per-component functions the php, nginx and database steps use.
func upstreamRepos(s *config.Server) ([]apt.Repo, error) {
	var repos []apt.Repo
	sury, used, err := phpUpstream(s)
	if err != nil {
		return nil, err
	}
	if used {
		repos = append(repos, sury)
	}
	if repo, used := nginxUpstream(s); used {
		repos = append(repos, repo)
	}
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return nil, err
	}
	if repo, _, used := databaseUpstream(eng, s); used {
		repos = append(repos, repo)
	}
	return repos, nil
}
