package status

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Inventory resolves the set of server configs to probe. Explicit arguments
// win verbatim; with none, it globs *.yml and *.yaml in dir.
//
// There is deliberately no registry file: a registry would become a fourth
// source of truth about a server (beside the YAML, the host itself and the
// secret cache) and would drift on its own. The inventory is a directory of
// files, because a server is one YAML file.
func Inventory(args []string, dir string) ([]string, error) {
	if len(args) > 0 {
		return append([]string(nil), args...), nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("inventory directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("inventory path %s is not a directory", dir)
	}
	var paths []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no server configs (*.yml, *.yaml) in %s — pass config paths explicitly or use --config-dir", dir)
	}
	sort.Strings(paths)
	return paths, nil
}
