package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/openinfra/network/internal/userauth"
)

// TestProbeClassifiesEachOutcome pins the three-way classification the
// whole view rests on: reachable and normal, reachable but not normal,
// and unreachable. It drives s.probe with stub checks rather than real
// dependencies, so the classification is tested independently of whether
// Postgres/Redis/the chain happen to be running.
func TestProbeClassifiesEachOutcome(t *testing.T) {
	// A clock that advances 5ms per reading, so latency is a real
	// computed value rather than always zero.
	current := time.Unix(0, 0)
	server := &Server{now: func() time.Time { current = current.Add(5 * time.Millisecond); return current }}

	ok := server.probe(context.Background(), "dep", func(context.Context) (string, error) { return "", nil })
	if ok.Status != "ok" || ok.Detail != "" {
		t.Fatalf("healthy probe = %+v, want status ok with no detail", ok)
	}
	if ok.LatencyUS != 5_000 {
		t.Fatalf("latency_us = %d, want the elapsed 5ms expressed in microseconds", ok.LatencyUS)
	}

	degraded := server.probe(context.Background(), "dep", func(context.Context) (string, error) { return "syncing", nil })
	if degraded.Status != "degraded" || degraded.Detail != "syncing" {
		t.Fatalf("qualified probe = %+v, want status degraded carrying its qualifier", degraded)
	}

	// The raw error must not reach the response: driver errors can embed
	// connection strings, which is exactly what a redaction audit
	// (ADR-016 §6) exists to keep out of an operator-visible payload.
	down := server.probe(context.Background(), "dep", func(context.Context) (string, error) {
		return "", errors.New("dial tcp 10.0.0.1:5432: password=hunter2 refused")
	})
	if down.Status != "unavailable" {
		t.Fatalf("failed probe = %+v, want status unavailable", down)
	}
	if down.Detail != "probe failed" {
		t.Fatalf("detail = %q, want the fixed string, never the driver error", down.Detail)
	}
}

func TestOperatorHealthRejectsATenant(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleTenant)

	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/health", rawKey)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a tenant calling an operator_readonly-gated route", recorder.Code)
	}
}

func TestOperatorHealthRaisesAnAlertForExpiredWorkerClaims(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	expired := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(2 * time.Hour)
	insertMinimalWorkload(t, ctx, pool, "SCHEDULING", 1, strPtr("worker-stuck"), &expired)
	insertMinimalWorkload(t, ctx, pool, "SCHEDULING", 1, strPtr("worker-healthy"), &future)

	rawKey := issueSessionKey(t, server, userauth.RoleOperatorReadOnly)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/health", rawKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response OperatorHealth
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	alert := findAlert(response.Alerts, "worker_claim_expired")
	if alert == nil {
		t.Fatalf("no worker_claim_expired alert in %+v", response.Alerts)
	}
	if alert.Count != 1 {
		t.Fatalf("count = %d, want only the expired claim counted, not the healthy one", alert.Count)
	}
	if alert.Severity != "critical" || alert.Source == "" {
		t.Fatalf("alert = %+v, want a critical severity and a named source", *alert)
	}
}

// TestOperatorHealthIgnoresRetriesOnTerminalWorkloads pins the one
// judgement call in the retry alert: a workload that burned its attempts
// and then reached a terminal state is history, not something an operator
// can act on, so alerting on it would be permanent noise.
func TestOperatorHealthIgnoresRetriesOnTerminalWorkloads(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	insertMinimalWorkload(t, ctx, pool, "FAILED", operatorRetryExhaustionThreshold+2, nil, nil)

	rawKey := issueSessionKey(t, server, userauth.RoleOperatorReadOnly)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/health", rawKey)
	var response OperatorHealth
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if findAlert(response.Alerts, "retry_exhaustion") != nil {
		t.Fatal("a terminal workload's exhausted retries must not raise a live alert")
	}

	insertMinimalWorkload(t, ctx, pool, "SCHEDULING", operatorRetryExhaustionThreshold, nil, nil)
	recorder = doAuthedGet(t, server.Handler(), "/api/v1/operator/health", rawKey)
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	alert := findAlert(response.Alerts, "retry_exhaustion")
	if alert == nil {
		t.Fatal("a non-terminal workload at the threshold must raise the alert")
	}
	if alert.Count != 1 {
		t.Fatalf("count = %d, want only the non-terminal workload", alert.Count)
	}
}

// TestOperatorHealthReportsEveryDependencyIndependently is the reason
// this endpoint exists rather than reusing /readyz: readyz short-circuits
// on the first failure, so it can never say which of the three is down.
func TestOperatorHealthReportsEveryDependencyIndependently(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleOperatorReadOnly)

	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/health", rawKey)
	var response OperatorHealth
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]string, len(response.Dependencies))
	for _, dependency := range response.Dependencies {
		names[dependency.Name] = dependency.Status
	}
	for _, want := range []string{"postgres", "redis", "blockchain"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("dependency %q missing from %+v", want, response.Dependencies)
		}
	}
	if names["postgres"] != "ok" {
		t.Fatalf("postgres = %q, want ok -- this test runs against a live Postgres", names["postgres"])
	}
}

func findAlert(alerts []OperatorAlert, id string) *OperatorAlert {
	for index := range alerts {
		if alerts[index].ID == id {
			return &alerts[index]
		}
	}
	return nil
}
