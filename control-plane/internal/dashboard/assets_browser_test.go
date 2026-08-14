package dashboard

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDashboardAssetsLoadInABrowser evaluates every <script> index.html
// loads, in order, against one shared global context -- the thing a
// browser does and no other test here does.
//
// The gap this closes is not theoretical. Every Go test in this package
// serves the assets as bytes and asserts on JSON from the handlers; none
// of them ever evaluates a line of the JavaScript. So when auth.js
// arrived declaring a top-level `const $` that app.js already declared,
// the redeclaration SyntaxError meant app.js never executed and the
// entire main dashboard went blank -- with a fully green test suite and a
// green CI run.
//
// It deliberately does NOT skip when node is missing. A test that skips
// itself into silence reports as a pass, which is the precise failure
// mode issue #98 was filed for (Postgres-backed tests skipping in CI and
// the job going green anyway). CI installs node explicitly for this
// reason; a local run without node should fail loudly and tell you what
// to install.
func TestDashboardAssetsLoadInABrowser(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required to run the dashboard asset harness and was not found on PATH: %v\n"+
			"Install Node.js (any maintained LTS) and re-run. This test is not skipped when node is\n"+
			"absent on purpose -- a skipped test reports as a pass, and this is the only test that\n"+
			"catches a dashboard that fails to load at all.", err)
	}

	output, err := exec.Command(node, "assets_browser_harness.js", "assets").CombinedOutput()
	if err != nil {
		t.Fatalf("dashboard assets failed to load the way a browser loads them:\n%s", strings.TrimSpace(string(output)))
	}
	t.Log(strings.TrimSpace(string(output)))
}
