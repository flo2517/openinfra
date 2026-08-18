package dashboard

import (
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

type operatorPanelRun struct {
	PanelHidden             bool     `json:"panel_hidden"`
	Requested               []string `json:"requested"`
	UnauthenticatedRequests []string `json:"unauthenticated_requests"`
	ExpiredLeaseRowsMarked  int      `json:"expired_lease_rows_marked"`
}

// runOperatorPanel drives assets/operator.js through one scenario. Like
// TestDashboardAssetsLoadInABrowser it fails rather than skips without
// node: a skipped test reports as a pass (issue #98).
func runOperatorPanel(t *testing.T, scenario string) operatorPanelRun {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required to drive the operator panel and was not found on PATH: %v", err)
	}
	output, err := exec.Command(node, "operator_panel_harness.js", "assets", scenario).CombinedOutput()
	if err != nil {
		t.Fatalf("scenario %q failed:\n%s", scenario, strings.TrimSpace(string(output)))
	}
	var run operatorPanelRun
	if err := json.Unmarshal(output, &run); err != nil {
		t.Fatalf("scenario %q: decode harness output %q: %v", scenario, string(output), err)
	}
	return run
}

const operatorEndpointCount = 4

// A non-operator must not be shown the panel, and -- just as important --
// the client must not even request operator data on their behalf. The
// server would refuse it anyway; asking would still mean a tenant's
// browser generating a burst of 403s on every page load.
func TestOperatorPanelStaysHiddenForANonOperator(t *testing.T) {
	for _, scenario := range []string{"no-session", "tenant"} {
		run := runOperatorPanel(t, scenario)
		if !run.PanelHidden {
			t.Errorf("scenario %q: panel is visible, want hidden", scenario)
		}
		for _, url := range run.Requested {
			if strings.HasPrefix(url, "/api/v1/operator/") {
				t.Errorf("scenario %q: requested operator data at %s", scenario, url)
			}
		}
	}
}

// "We could not determine the role" must fail closed. An unreachable
// /api/v1/me is a Control Plane problem; resolving it in the viewer's
// favour would paint an operator panel for whoever happens to be logged
// in during an outage.
func TestOperatorPanelFailsClosedWhenTheRoleIsUnknown(t *testing.T) {
	for _, scenario := range []string{"me-fails", "unknown-role"} {
		run := runOperatorPanel(t, scenario)
		if !run.PanelHidden {
			t.Errorf("scenario %q: panel is visible, want hidden", scenario)
		}
	}
}

func TestOperatorPanelLoadsEverySectionForAnOperator(t *testing.T) {
	for _, scenario := range []string{"operator_readonly", "operator_admin"} {
		run := runOperatorPanel(t, scenario)
		if run.PanelHidden {
			t.Errorf("scenario %q: panel is hidden, want visible", scenario)
		}
		for _, endpoint := range []string{
			"/api/v1/operator/health",
			"/api/v1/operator/queue",
			"/api/v1/operator/workers",
			"/api/v1/operator/audit",
		} {
			if !slices.Contains(run.Requested, endpoint) {
				t.Errorf("scenario %q: %s was never requested; requested %v", scenario, endpoint, run.Requested)
			}
		}
		if len(run.UnauthenticatedRequests) > 0 {
			t.Errorf("scenario %q: requests sent without an Authorization header: %v", scenario, run.UnauthenticatedRequests)
		}
		if got := len(run.Requested); got != operatorEndpointCount+1 {
			t.Errorf("scenario %q: made %d requests (%v), want %d operator reads plus /api/v1/me",
				scenario, got, run.Requested, operatorEndpointCount+1)
		}
	}
}

// A worker holding claims past its lease is the stuck-claim signal this
// table exists for, so it must be visually distinguishable and not just
// another row -- #14's "no false green status" applied to a single row.
func TestOperatorPanelMarksAnExpiredWorkerLease(t *testing.T) {
	run := runOperatorPanel(t, "operator_readonly")
	if run.ExpiredLeaseRowsMarked != 1 {
		t.Fatalf("expired-lease rows marked = %d, want 1", run.ExpiredLeaseRowsMarked)
	}
}
