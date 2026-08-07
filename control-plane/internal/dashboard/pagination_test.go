package dashboard

import (
	"net/http/httptest"
	"testing"
)

func TestBoundedQueryIntFallsBackOnMissingOrUnparsableValue(t *testing.T) {
	query := httptest.NewRequest("GET", "/?limit=not-a-number", nil).URL.Query()
	if got := boundedQueryInt(query, "limit", 42, 1, 100); got != 42 {
		t.Fatalf("unparsable value: got %d, want fallback 42", got)
	}
	if got := boundedQueryInt(query, "missing", 42, 1, 100); got != 42 {
		t.Fatalf("missing key: got %d, want fallback 42", got)
	}
}

func TestBoundedQueryIntClampsToRange(t *testing.T) {
	tooLow := httptest.NewRequest("GET", "/?v=-5", nil).URL.Query()
	if got := boundedQueryInt(tooLow, "v", 10, 0, 100); got != 0 {
		t.Fatalf("negative value: got %d, want clamped to min 0", got)
	}
	tooHigh := httptest.NewRequest("GET", "/?v=99999", nil).URL.Query()
	if got := boundedQueryInt(tooHigh, "v", 10, 0, 500); got != 500 {
		t.Fatalf("oversized value: got %d, want clamped to max 500", got)
	}
	inRange := httptest.NewRequest("GET", "/?v=17", nil).URL.Query()
	if got := boundedQueryInt(inRange, "v", 10, 0, 500); got != 17 {
		t.Fatalf("in-range value: got %d, want 17", got)
	}
}

// TestParseOverviewPaginationDefaultsMatchThePrePaginationBehavior pins
// this endpoint's backward-compatibility guarantee: a caller that never
// sends providers_limit/providers_offset/workloads_limit/workloads_offset
// must see the exact same page shape as before pagination existed
// (LIMIT 500 / LIMIT 100, offset 0).
func TestParseOverviewPaginationDefaultsMatchThePrePaginationBehavior(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/v1/overview", nil)
	got := parseOverviewPagination(request)
	want := overviewPagination{ProvidersLimit: 500, ProvidersOffset: 0, WorkloadsLimit: 100, WorkloadsOffset: 0}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseOverviewPaginationHonorsExplicitBoundedValues(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/v1/overview?providers_limit=10&providers_offset=20&workloads_limit=5&workloads_offset=15", nil)
	got := parseOverviewPagination(request)
	want := overviewPagination{ProvidersLimit: 10, ProvidersOffset: 20, WorkloadsLimit: 5, WorkloadsOffset: 15}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseOverviewPaginationClampsOversizedLimits(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/v1/overview?providers_limit=99999&workloads_limit=99999", nil)
	got := parseOverviewPagination(request)
	if got.ProvidersLimit != maxProvidersLimit {
		t.Fatalf("providers_limit = %d, want clamped to %d", got.ProvidersLimit, maxProvidersLimit)
	}
	if got.WorkloadsLimit != maxWorkloadsLimit {
		t.Fatalf("workloads_limit = %d, want clamped to %d", got.WorkloadsLimit, maxWorkloadsLimit)
	}
}
