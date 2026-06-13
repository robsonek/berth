package ssh

import (
	"context"
	"fmt"
)

// Call records a Run invocation.
type Call struct {
	Cmd   string
	Stdin []byte
}

// FakeRunner is an in-memory Runner for tests.
type FakeRunner struct {
	responses map[string]Result
	errs      map[string]error
	calls     []Call
	writes    []FileSpec
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{responses: map[string]Result{}, errs: map[string]error{}}
}

// On stubs the result for an exact command string.
func (f *FakeRunner) On(cmd string, r Result) *FakeRunner { f.responses[cmd] = r; return f }

// OnError stubs a transport error for an exact command string.
func (f *FakeRunner) OnError(cmd string, err error) *FakeRunner { f.errs[cmd] = err; return f }

func (f *FakeRunner) Run(_ context.Context, cmd string, stdin []byte) (Result, error) {
	f.calls = append(f.calls, Call{Cmd: cmd, Stdin: stdin})
	if err, ok := f.errs[cmd]; ok {
		return Result{}, err
	}
	if r, ok := f.responses[cmd]; ok {
		return r, nil
	}
	return Result{}, fmt.Errorf("FakeRunner: unstubbed command %q", cmd)
}

func (f *FakeRunner) WriteFile(_ context.Context, fs FileSpec) error {
	f.writes = append(f.writes, fs)
	return nil
}

func (f *FakeRunner) Calls() []Call      { return f.calls }
func (f *FakeRunner) Writes() []FileSpec { return f.writes }
