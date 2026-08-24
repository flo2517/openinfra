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
// the literal itself contains no nested braces). specVersionPattern and
// transactionVersionPattern are then applied only within that anchored
// block, not the whole file: a bare `spec_version:\s*(\d+)` (or
// `transaction_version:\s*(\d+)`) search across the entire file would match
// the *first* occurrence anywhere -- silently validating against the
// wrong value if the file ever gains another spec_version-shaped literal
// above the real one (a test fixture, a doc example, a second runtime
// config), with no signal that the wrong occurrence was picked.
//
// All three are deliberately line-scans, not a Rust parser: they exist only
// to detect drift between these constants and the runtime's real
// spec_version/transaction_version, not to understand Rust syntax in
// general. If the RuntimeVersion literal is ever restructured (a field
// renamed, no longer a bare `field: N,` line, or the literal grows nested
// braces), these patterns -- and the two tests below -- will need updating
// too.
var (
	runtimeVersionBlockPattern = regexp.MustCompile(`(?s)pub const VERSION: RuntimeVersion = RuntimeVersion \{.*?\};`)
	specVersionPattern         = regexp.MustCompile(`spec_version:\s*(\d+)`)
	transactionVersionPattern  = regexp.MustCompile(`transaction_version:\s*(\d+)`)
)

// runtimeLibPath returns blockchain/runtime/src/lib.rs's path, relative to
// this test file's own path via runtime.Caller -- control-plane and
// blockchain are sibling directories at the repo root:
// control-plane/internal/blockchainbridge/<this file> ->
// ../../../blockchain/runtime/src/lib.rs.
func runtimeLibPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine this test file's own path via runtime.Caller")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "blockchain", "runtime", "src", "lib.rs")
}

// readRuntimeVersionBlock reads blockchain/runtime/src/lib.rs and returns
// just the `pub const VERSION: RuntimeVersion = RuntimeVersion { ... };`
// literal, shared by TestSupportedSpecVersionMatchesRuntime and
// TestSupportedTransactionVersionMatchesRuntime so both drift detectors
// anchor to the exact same block instead of two independently-written,
// possibly-diverging file reads.
func readRuntimeVersionBlock(t *testing.T) (path string, block []byte) {
	t.Helper()
	path = runtimeLibPath(t)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf(
			"could not read blockchain/runtime/src/lib.rs at %q: %v\n"+
				"this test assumes control-plane/ and blockchain/ are sibling directories "+
				"checked out from the same repo (e.g. it will fail in a build/packaging "+
				"context that only checks out control-plane/ on its own); if that's not "+
				"the case here, this test needs a different way to obtain the runtime's "+
				"version fields rather than being skipped silently",
			path, err,
		)
	}
	block = runtimeVersionBlockPattern.Find(contents)
	if block == nil {
		t.Fatalf(
			"could not find `pub const VERSION: RuntimeVersion = RuntimeVersion { ... };` in %q; "+
				"it may have been restructured -- update runtimeVersionBlockPattern in this "+
				"test to match its new shape",
			path,
		)
	}
	return path, block
}

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
	path, block := readRuntimeVersionBlock(t)

	match := specVersionPattern.FindSubmatch(block)
	if match == nil {
		t.Fatalf(
			"could not find a `spec_version: N` field within the RuntimeVersion literal in %q; "+
				"the literal may have been restructured -- update specVersionPattern in this "+
				"test to match its new shape",
			path,
		)
	}
	runtimeSpecVersion, err := strconv.Atoi(string(match[1]))
	if err != nil {
		t.Fatalf("parsed spec_version %q from %q is not an integer: %v", match[1], path, err)
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

// TestSupportedTransactionVersionMatchesRuntime is
// TestSupportedSpecVersionMatchesRuntime's sibling for
// supportedTransactionVersion, added for ADR-032: transaction_version had
// never changed since genesis before ADR-032 bumped it (1 -> 2) for
// ChargeTip's new TxExtension element, so no drift guard existed for this
// field until now -- closing the gap before this field can ever repeat
// issue #123's exact failure mode (a hand-maintained constant silently
// drifting from the runtime's real value, caught only by a live e2e run).
func TestSupportedTransactionVersionMatchesRuntime(t *testing.T) {
	path, block := readRuntimeVersionBlock(t)

	match := transactionVersionPattern.FindSubmatch(block)
	if match == nil {
		t.Fatalf(
			"could not find a `transaction_version: N` field within the RuntimeVersion literal "+
				"in %q; the literal may have been restructured -- update "+
				"transactionVersionPattern in this test to match its new shape",
			path,
		)
	}
	runtimeTransactionVersion, err := strconv.Atoi(string(match[1]))
	if err != nil {
		t.Fatalf("parsed transaction_version %q from %q is not an integer: %v", match[1], path, err)
	}

	if runtimeTransactionVersion != supportedTransactionVersion {
		t.Fatalf(
			"blockchain/runtime/src/lib.rs declares transaction_version: %d, but registrar.go's "+
				"supportedTransactionVersion is still %d -- update supportedTransactionVersion in "+
				"control-plane/internal/blockchainbridge/registrar.go to match (see the "+
				"comment on supportedSpecVersion/supportedTransactionVersion for why these "+
				"constants exist and what goes wrong when they drift)",
			runtimeTransactionVersion, supportedTransactionVersion,
		)
	}
}
