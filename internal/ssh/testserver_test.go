package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// execBehavior scripts how the test server services one exec request. It runs
// after the exec request has been ACKed; reqs carries any further session
// requests (e.g. "signal"). The session channel is closed by the caller.
type execBehavior func(srv *testServer, ch xssh.Channel, reqs <-chan *xssh.Request)

// testServer is a minimal in-process SSH server for exercising Client's
// context handling. Session channels + exec requests only — deliberately NO
// SFTP subsystem (spec decision: not worth building for one phase).
type testServer struct {
	addr        string
	signals     chan string   // signal names observed by hanging execs
	execStarted chan struct{} // one send per ACKed exec request
}

func startTestServer(t *testing.T, behavior execBehavior, deaf bool) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &xssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &testServer{
		addr:        ln.Addr().String(),
		signals:     make(chan string, 4),
		execStarted: make(chan struct{}, 4),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed by t.Cleanup
			}
			go srv.handle(c, cfg, behavior, deaf)
		}
	}()
	return srv
}

func (s *testServer) handle(c net.Conn, cfg *xssh.ServerConfig, behavior execBehavior, deaf bool) {
	sconn, chans, globals, err := xssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	if deaf {
		// Simulate a dead peer for keepalive probes: drain global requests
		// WITHOUT replying, so a wantReply SendRequest blocks forever.
		go func() {
			for range globals {
			}
		}()
	} else {
		// DiscardRequests replies (false) to wantReply requests — any reply,
		// even a failure, proves the transport is live.
		go xssh.DiscardRequests(globals)
	}
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(xssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, reqs, behavior)
	}
}

func (s *testServer) session(ch xssh.Channel, reqs <-chan *xssh.Request, behavior execBehavior) {
	defer ch.Close()
	for req := range reqs {
		if req.Type == "exec" {
			req.Reply(true, nil)
			s.execStarted <- struct{}{}
			behavior(s, ch, reqs)
			return
		}
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// exitStatusMsg is the exit-status channel request payload (RFC 4254 §6.10).
type exitStatusMsg struct{ Status uint32 }

// completeExec writes stdout and finishes with the given exit code.
func completeExec(stdout string, code uint32) execBehavior {
	return func(_ *testServer, ch xssh.Channel, _ <-chan *xssh.Request) {
		if stdout != "" {
			ch.Write([]byte(stdout))
		}
		ch.SendRequest("exit-status", false, xssh.Marshal(exitStatusMsg{Status: code}))
	}
}

// hangExec never sends exit-status; it records signal requests and returns
// only when the client closes the session (which ends reqs).
func hangExec(srv *testServer, _ xssh.Channel, reqs <-chan *xssh.Request) {
	for req := range reqs {
		if req.Type == "signal" {
			var p struct{ Signal string }
			_ = xssh.Unmarshal(req.Payload, &p)
			select {
			case srv.signals <- p.Signal:
			default:
			}
		}
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// dialTest opens a raw connection to the harness and wraps it in a Client
// with no SFTP subsystem (exec paths only; WriteFile past the ctx fast path
// would panic on the nil sftp client — by design, see Global Constraints).
func dialTest(t *testing.T, srv *testServer) *Client {
	t.Helper()
	conn, err := xssh.Dial("tcp", srv.addr, &xssh.ClientConfig{
		User:            "test",
		HostKeyCallback: xssh.InsecureIgnoreHostKey(), // in-process test server
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Client{conn: conn}
}

func TestExecCompletesNormallyOverHarness(t *testing.T) {
	srv := startTestServer(t, completeExec("hello\n", 0), false)
	c := dialTest(t, srv)
	res, err := c.exec(context.Background(), "echo hello", nil)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 0 || res.Stdout != "hello\n" {
		t.Errorf("res = %+v, want exit 0 stdout %q", res, "hello\n")
	}
}

func TestExecNonZeroExitIsDataOverHarness(t *testing.T) {
	srv := startTestServer(t, completeExec("", 3), false)
	c := dialTest(t, srv)
	res, err := c.exec(context.Background(), "false", nil)
	if err != nil {
		t.Fatalf("non-zero exit must be data, not a Go error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
}

func TestExecPreCancelledContext(t *testing.T) {
	srv := startTestServer(t, completeExec("", 0), false)
	c := dialTest(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.exec(ctx, "true", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled (no session for a dead ctx)", err)
	}
}

func TestExecCancelReturnsPromptlyAndSignalsTERM(t *testing.T) {
	srv := startTestServer(t, hangExec, false)
	c := dialTest(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := c.exec(ctx, "sleep 999", nil)
		done <- outcome{res, err}
	}()

	// Deterministic: wait until the server ACKed the exec, then cancel.
	select {
	case <-srv.execStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("exec request never reached the server")
	}
	start := time.Now()
	cancel()

	var got outcome
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("exec did not return after cancel — ctx is still dead")
	}
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", got.err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancel-to-return took %v, want well under 1s", elapsed)
	}
	if got.res.Stdout != "" || got.res.Stderr != "" || got.res.ExitCode != 0 {
		t.Errorf("cancel path must return a zero Result (buffers may still be racing); got %+v", got.res)
	}
	select {
	case sig := <-srv.signals:
		if sig != "TERM" {
			t.Errorf("signal = %q, want TERM (lets apt/dpkg release locks; sudo relays TERM)", sig)
		}
	case <-time.After(2 * time.Second):
		t.Error("server never observed a signal request — the remote command would keep running")
	}
}

func TestWriteFilePreCancelledContext(t *testing.T) {
	srv := startTestServer(t, completeExec("", 0), false)
	c := dialTest(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// nil c.sftp is safe here: the pre-cancelled ctx must short-circuit in
	// exec("mktemp") before anything touches the SFTP subsystem.
	err := c.WriteFile(ctx, FileSpec{Path: "/tmp/x", Content: []byte("y")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestKeepaliveClosesDeadConnection(t *testing.T) {
	srv := startTestServer(t, completeExec("", 0), true) // deaf: probes never get a reply
	conn, err := xssh.Dial("tcp", srv.addr, &xssh.ClientConfig{
		User:            "test",
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Shrink the tuning vars (the resolveA stub pattern) and restore after.
	oldI, oldB, oldM := keepaliveInterval, keepaliveReplyBudget, keepaliveMaxMissed
	keepaliveInterval, keepaliveReplyBudget, keepaliveMaxMissed = 20*time.Millisecond, 20*time.Millisecond, 2
	t.Cleanup(func() { keepaliveInterval, keepaliveReplyBudget, keepaliveMaxMissed = oldI, oldB, oldM })

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) }) // harmless if keepalive already returned
	go keepalive(conn, stop)

	waitErr := make(chan error, 1)
	go func() { waitErr <- conn.Wait() }()
	select {
	case <-waitErr:
		// Connection closed by the keepalive loop — dead transport detected.
	case <-time.After(3 * time.Second):
		t.Fatal("keepalive never closed the dead connection")
	}
}
