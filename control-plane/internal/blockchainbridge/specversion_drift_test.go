package blockchainbridge

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
)

// specVersionPattern matches the exact `spec_version: 3,` field of the
// RuntimeVersion struct literal in blockchain/runtime/src/lib.rs, e.g.:
//
//	#[runtime_version]
//	pub const VERSION: RuntimeVersion = RuntimeVersion {
//	    ...
//	    spec_version: 3,
//	    ...
//	};
//
// This is deliberately a line-scan, not a Rust parser: it exists only to
// detect drift between this constant and the runtime's real spec_version,
// not to understand Rust syntax in general. If the RuntimeVersion literal
// is ever restructured (field renamed, no longer a bare `spec_version: N,`
// line), this pattern -- and TestSupportedSpecVersionMatchesRuntime below --
// will need updating too.
var specVersionPattern = regexp.MustCompile(`spec_version:\s*(\d+)`)

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

	match := specVersionPattern.FindSubmatch(contents)
	if match == nil {
		t.Fatalf(
			"could not find a `spec_version: N` field in %q; the RuntimeVersion struct "+
				"literal may have been restructured -- update specVersionPattern in this "+
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
