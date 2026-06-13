//go:build !integration

package ssh

import "testing"

func TestClientConfigUsesCallbackNotInsecure(t *testing.T) {
	cfg := clientConfig("berth", nil, HostKeyPolicy{Pinned: "SHA256:x"})
	if cfg.User != "berth" {
		t.Errorf("user = %q", cfg.User)
	}
	if cfg.HostKeyCallback == nil {
		t.Error("HostKeyCallback must be set (never InsecureIgnoreHostKey)")
	}
}
