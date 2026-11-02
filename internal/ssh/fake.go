package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Call records a Run invocation.
type Call struct {
	Cmd   string
	Stdin []byte
}

// FakeRunner is an in-memory Runner for tests.
type FakeRunner struct {
	responses map[string]Result
	sequences map[string][]Result
	errs      map[string]error
	calls     []Call
	writes    []FileSpec
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{responses: map[string]Result{}, sequences: map[string][]Result{}, errs: map[string]error{}}
}

// On stubs the result for an exact command string.
func (f *FakeRunner) On(cmd string, r Result) *FakeRunner { f.responses[cmd] = r; return f }

// OnSeq stubs successive results for repeated calls to the same command string;
// once the sequence is down to its last entry that entry repeats. Used to model
// a command that fails transiently (e.g. apt-lock contention) then succeeds.
func (f *FakeRunner) OnSeq(cmd string, rs ...Result) *FakeRunner {
	f.sequences[cmd] = append(f.sequences[cmd], rs...)
	return f
}

// OnError stubs a transport error for an exact command string.
func (f *FakeRunner) OnError(cmd string, err error) *FakeRunner { f.errs[cmd] = err; return f }

func (f *FakeRunner) Run(_ context.Context, cmd string, stdin []byte) (Result, error) {
	f.calls = append(f.calls, Call{Cmd: cmd, Stdin: stdin})
	if err, ok := f.errs[cmd]; ok {
		return Result{}, err
	}
	if seq, ok := f.sequences[cmd]; ok && len(seq) > 0 {
		r := seq[0]
		if len(seq) > 1 {
			f.sequences[cmd] = seq[1:]
		}
		return r, nil
	}
	if r, ok := f.responses[cmd]; ok {
		return r, nil
	}
	return Result{}, fmt.Errorf("FakeRunner: unstubbed command %q", cmd)
}

// WriteFile records the spec after applying the same STATIC contract the live
// client enforces. Without this a unit test would happily accept a FileSpec that
// production rejects, and the difference would only surface on a real host. The
// ancestry probe is deliberately not simulated here — it depends on live state,
// so tests that need it stub the probe command like any other.
func (f *FakeRunner) WriteFile(_ context.Context, fs FileSpec) error {
	if err := validateRootDestination(fs); err != nil {
		return err
	}
	f.writes = append(f.writes, fs)
	return nil
}

func (f *FakeRunner) Calls() []Call      { return f.calls }
func (f *FakeRunner) Writes() []FileSpec { return f.writes }

// FakeLease is an in-memory Lease for tests. It is safe for concurrent use
// (a heartbeat goroutine may Send while the test inspects it).
type FakeLease struct {
	mu       sync.Mutex
	sent     []string
	released bool
	done     chan struct{}
	doneOnce sync.Once
}

func NewFakeLease() *FakeLease { return &FakeLease{done: make(chan struct{})} }

// Send records line while the lease is live; once it has ended (End or
// Release) it fails like the live client's write to a finished command.
func (l *FakeLease) Send(line string) error {
	select {
	case <-l.done:
		return errors.New("FakeLease: send on an ended lease")
	default:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sent = append(l.sent, line)
	return nil
}

func (l *FakeLease) Done() <-chan struct{} { return l.done }

// Release marks the lease released and closes Done. Idempotent.
func (l *FakeLease) Release(_ time.Duration) error {
	l.mu.Lock()
	l.released = true
	l.mu.Unlock()
	l.End()
	return nil
}

// End simulates the remote command ending on its own: Done closes, the lease
// is NOT marked released.
func (l *FakeLease) End() { l.doneOnce.Do(func() { close(l.done) }) }

func (l *FakeLease) Sent() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.sent...)
}

func (l *FakeLease) Released() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.released
}

var _ Holder = (*FakeHolder)(nil)

// FakeHolder is an in-memory Holder for tests, keyed by the exact command
// string like FakeRunner. ctx and ready are ignored.
type FakeHolder struct {
	mu     sync.Mutex
	leases map[string]*FakeLease
	exits  map[string]*HoldExitError
	errs   map[string]error
	calls  []string
}

func NewFakeHolder() *FakeHolder {
	return &FakeHolder{leases: map[string]*FakeLease{}, exits: map[string]*HoldExitError{}, errs: map[string]error{}}
}

// OnHold stubs a command that becomes ready: Hold returns l.
func (f *FakeHolder) OnHold(cmd string, l *FakeLease) *FakeHolder {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leases[cmd] = l
	return f
}

// OnHoldExit stubs a command that ends before ready: Hold returns e.
func (f *FakeHolder) OnHoldExit(cmd string, e *HoldExitError) *FakeHolder {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exits[cmd] = e
	return f
}

// OnHoldError stubs a transport error for cmd.
func (f *FakeHolder) OnHoldError(cmd string, err error) *FakeHolder {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[cmd] = err
	return f
}

func (f *FakeHolder) Hold(_ context.Context, cmd, _ string) (Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	if err, ok := f.errs[cmd]; ok {
		return nil, err
	}
	if e, ok := f.exits[cmd]; ok {
		return nil, e
	}
	if l, ok := f.leases[cmd]; ok {
		return l, nil
	}
	return nil, fmt.Errorf("FakeHolder: unstubbed hold command %q", cmd)
}

func (f *FakeHolder) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}
