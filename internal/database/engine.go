// Package database provides pluggable database engines.
package database

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type Engine interface {
	Name() string
	InstallSteps() []provision.Step
	EnsureDatabase(ctx context.Context, r bssh.Runner, name string) error
	EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error
}

var registry = map[string]Engine{}

func Register(e Engine) { registry[e.Name()] = e }

func Get(name string) (Engine, error) {
	e, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown database engine %q", name)
	}
	return e, nil
}
