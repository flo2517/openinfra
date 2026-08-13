// Package testsupport holds helpers shared by tests across packages.
// It imports "testing" on purpose, like net/http/httptest does -- it is
// only ever linked into test binaries.
package testsupport

import (
	"os"
	"testing"
)

// databaseURLVariable is the single name every Postgres-backed test in
// this module reads. Kept here rather than repeated as a literal in each
// package, so renaming it cannot leave a stale guard behind that silently
// skips forever.
const databaseURLVariable = "OPENINFRA_TEST_DATABASE_URL"

// RequireDatabaseURL returns the Postgres URL a Postgres-backed test
// should connect to.
//
// It skips on a developer machine without a database, and **fails** in
// CI. That asymmetry is the whole point (issue #98): every Postgres-backed
// test in this module guards on this variable, CI never set it, and a
// skipped test is reported as a passing job -- so the tenant-isolation
// assertions, the most security-relevant tests in the repo, were green
// without ever running. A broken test merged that way stayed invisible
// until someone ran the suite locally against a real database.
//
// t.Skip stays correct for local development (no Docker, no database, run
// the unit tests anyway); it is only wrong in CI, where a missing
// dependency means the pipeline is misconfigured, not that the test is
// inapplicable. "CI" is set to a non-empty value by GitHub Actions and by
// essentially every other CI runner.
func RequireDatabaseURL(t *testing.T) string {
	t.Helper()
	databaseURL := os.Getenv(databaseURLVariable)
	if databaseURL != "" {
		return databaseURL
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("%s is not set: in CI this is a misconfigured pipeline, not a test to skip (issue #98)", databaseURLVariable)
	}
	t.Skipf("%s is not set", databaseURLVariable)
	return ""
}
