package blockchainbridge

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
)

// runtimeVersionBlockPattern anchors to the actual `pub const VERSION:
// RuntimeVersion = RuntimeVersion { ... };` struct literal in
// blockchain/runtime/src/lib.rs (non-greedy up to the first `};`, since
// the literal itself contains no nested braces). specVersionPattern is
// then applied only within that anchored block, not the whole file: a
// bare `spec_version:\s*(\d+)` search across the entire file would match
// the *first* occurrence anywhere -- silently validating against the
// wrong value if the file ever gains another spec_version-shaped literal
// above the real one (a test fixture, a doc example, a second runtime
// config), with no signal that the wrong occurrence was picked.
//
// Both are deliberately line-scans, not a Rust parser: they exist only to
// detect drift between this constant and the runtime's real spec_version,
// not to understand Rust syntax in general. If the RuntimeVersion literal
// is ever restructured (field renamed, no longer a bare `spec_version: N,`
// line, or the literal grows nested braces), these patterns -- and
// TestSupportedSpecVersionMatchesRuntime below -- will need updating too.
var (
	runtimeVersionBlockPattern = regexp.MustCompile(`(?s)pub const VERSION: RuntimeVersion = RuntimeVersion \{.*?\};`)
	specVersionPattern         = regexp.MustCompile(`spec_version:\s*(\d+)`)
)

// TestSupportedSpecVersionMatchesRuntime is a drift detector for the class
// of bug filed as issue #123: supportedSpecVersion above is a hand-maintained
// copy of blockchain/runtime/src/lib.rs's real spec_version, checked by
// exact equality at three call sites (EnsureActive, lease finalization,
// Network Validator registration). #37 bumped the runtime's spec_version
// from 2 to 3 without updating this constant, and nothing in `go test`
// caught it -- the drift only surfaced when PR #121 exercised a real
// on-chain write against a live chain and hit "unsupported runtime version
// spec=3 transaction=1".
//
// This test reads the runtime source directly and compares its
// spec_version against supportedSpecVersion, so a future bump that forgets
// to update registrar.go fails fast here instead of only in a full e2e run.
func TestSupportedSpecVersionMatchesRuntime(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine this test file's own path via runtime.Caller")
	}
	// control-plane and blockchain are sibling directories at the repo
	// root: control-plane/internal/blockchainbridge/<this file> ->
	// ../../../blockchain/runtime/src/lib.rs.
	runtimeLibPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "blockchain", "runtime", "src", "lib.rs")

	contents, err := os.ReadFile(runtimeLibPath)
	if err != nil {
		t.Fatalf(
			"could not read blockchain/runtime/src/lib.rs at %q: %v\n"+
				"this test assumes control-plane/ and blockchain/ are sibling directories "+
				"checked out from the same repo (e.g. it will fail in a build/packaging "+
				"context that only checks out control-plane/ on its own); if that's not "+
				"the case here, this test needs a different way to obtain the runtime's "+
				"spec_version rather than being skipped silently",
			runtimeLibPath, err,
		)
	}

	block := runtimeVersionBlockPattern.Find(contents)
	if block == nil {
		t.Fatalf(
			"could not find `pub const VERSION: RuntimeVersion = RuntimeVersion { ... };` in %q; "+
				"it may have been restructured -- update runtimeVersionBlockPattern in this "+
				"test to match its new shape",
			runtimeLibPath,
		)
	}

	match := specVersionPattern.FindSubmatch(block)
	if match == nil {
		t.Fatalf(
			"could not find a `spec_version: N` field within the RuntimeVersion literal in %q; "+
				"the literal may have been restructured -- update specVersionPattern in this "+
				"test to match its new shape",
			runtimeLibPath,
		)
	}
	runtimeSpecVersion, err := strconv.Atoi(string(match[1]))
	if err != nil {
		t.Fatalf("parsed spec_version %q from %q is not an integer: %v", match[1], runtimeLibPath, err)
	}

	if runtimeSpecVersion != supportedSpecVersion {
		t.Fatalf(
			"blockchain/runtime/src/lib.rs declares spec_version: %d, but registrar.go's "+
				"supportedSpecVersion is still %d -- update supportedSpecVersion in "+
				"control-plane/internal/blockchainbridge/registrar.go to match (see the "+
				"comment on supportedSpecVersion for why this constant exists and what goes "+
				"wrong when it drifts)",
			runtimeSpecVersion, supportedSpecVersion,
		)
	}
}
