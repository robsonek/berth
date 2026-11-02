package hostlock

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestProvisionNeverImportsHostlock freezes "steps and the engine never
// import hostlock": callers wrap the whole engine run in Run, and steps only
// see the guarded Runner it hands out. A step that took or released the lock
// itself would break the one-session-per-host guarantee. Every .go file under
// internal/provision is scanned, tests and build-tagged files included.
func TestProvisionNeverImportsHostlock(t *testing.T) {
	self := reflect.TypeFor[Mode]().PkgPath()
	root := filepath.Join("..", "provision")
	fset := token.NewFileSet()
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		scanned++
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				t.Errorf("%s imports %s — steps and the engine must never take the host session lock", path, self)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Guard against a vacuous pass if the tree moves: the engine and the
	// steps alone are dozens of files.
	if scanned < 20 {
		t.Fatalf("scanned %d Go files under %s, want the engine and every step", scanned, root)
	}
}
