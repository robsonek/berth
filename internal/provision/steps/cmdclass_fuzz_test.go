package steps

import (
	"strings"
	"testing"
)

// FuzzClassifyCommand pins two properties that make the classifier trustworthy
// under inputs nobody thought of: it must never panic, and it must never return
// a permissive verdict for a command containing a shell metacharacter unless
// that exact text is registered. Everything else may be rejected freely —
// over-rejection is the safe direction.
func FuzzClassifyCommand(f *testing.F) {
	for _, seed := range []string{
		"cat /etc/hosts", "systemctl start nginx", "nginx -t",
		"cat /x && rm /y", "printf '%s' \"$(rm -rf /)\"", "",
		"\x00", "cat\n/x", "sed -n 'w /tmp/x' /x", "find / -delete",
	} {
		f.Add(seed, []byte(nil))
	}
	f.Fuzz(func(t *testing.T, cmd string, stdin []byte) {
		verdict, _ := classifyCommand(cmd, stdin) // must not panic
		permissive := verdict == cmdReadOnly || verdict == cmdException
		if !permissive {
			return
		}
		if len(stdin) > 0 {
			t.Fatalf("permissive verdict %s for a command with stdin: %q", verdict, cmd)
		}
		if strings.ContainsAny(cmd, shellMetachars) {
			t.Fatalf("permissive verdict %s for a command containing a metacharacter: %q", verdict, cmd)
		}
	})
}
