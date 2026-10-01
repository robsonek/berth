package database

import "testing"

// Only an engine whose server package is an unversioned, default-major
// metapackage may be installed with --no-upgrade: PGDG's postgresql would
// otherwise pull a second major on any later run.
func TestServerPackageTracksMajor(t *testing.T) {
	if !(Postgres{}).ServerPackageTracksMajor() {
		t.Error("postgres: the postgresql metapackage tracks PGDG's default major")
	}
	if (MariaDB{}).ServerPackageTracksMajor() {
		t.Error("mariadb: mariadb-server follows the series pinned by the repo URI")
	}
}
