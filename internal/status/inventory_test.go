package status

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("id: x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInventoryPrefersExplicitArgs(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "a.yml", "b.yml")
	got, err := Inventory([]string{"servers/only.yml"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"servers/only.yml"}) {
		t.Errorf("got %v, want the explicit arg alone", got)
	}
}

func TestInventoryGlobsDirectorySorted(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "prod.yml", "alpha.yaml", "notes.txt")
	got, err := Inventory(nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "alpha.yaml"), filepath.Join(dir, "prod.yml")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (sorted, .yml+.yaml only)", got, want)
	}
}

// TestInventoryEmptyDirectoryIsAnError: silently reporting an empty fleet
// would read as "everything is fine" when the real cause is a wrong -C.
func TestInventoryEmptyDirectoryIsAnError(t *testing.T) {
	if _, err := Inventory(nil, t.TempDir()); err == nil {
		t.Error("expected an error for a directory with no configs")
	}
}

func TestInventoryMissingDirectoryIsAnError(t *testing.T) {
	if _, err := Inventory(nil, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error for a missing directory")
	}
}
