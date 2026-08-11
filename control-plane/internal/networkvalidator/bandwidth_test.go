package networkvalidator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestMeasureBandwidthPassesWhenThroughputComfortablyExceedsTolerance
// probes a real loopback gRPC server: any real network trivially clears a
// 1 Mbps declared figure, so this deterministically exercises the
// passing path without needing to control real transfer timing.
func TestMeasureBandwidthPassesWhenThroughputComfortablyExceedsTolerance(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{
		privateKey:          agentPriv,
		declaredIngressMbps: 1,
		declaredEgressMbps:  1,
	})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != passingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d (reason=%q)", result.ScoreBps, passingScoreBps, result.Reason)
	}
	if result.SampleCount != 1 {
		t.Fatalf("SampleCount = %d, want 1", result.SampleCount)
	}
}

// TestMeasureBandwidthFailsWhenThroughputWellUnderTolerance declares an
// astronomically high bandwidth figure (petabits/sec) that no real test
// environment's loopback link can plausibly clear 70% of -- a
// deterministic way to exercise the failing path without needing to
// simulate a genuinely slow link.
func TestMeasureBandwidthFailsWhenThroughputWellUnderTolerance(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{
		privateKey:          agentPriv,
		declaredIngressMbps: 100_000_000, // 100 Pbps
		declaredEgressMbps:  100_000_000,
	})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d (reason=%q)", result.ScoreBps, failingScoreBps, result.Reason)
	}
	if result.Reason == "" {
		t.Fatal("expected a non-empty failure reason")
	}
}

func TestMeasureBandwidthFailsOnTamperedUploadHash(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{
		privateKey:                agentPriv,
		declaredIngressMbps:       1, // low enough that tolerance alone would pass
		declaredEgressMbps:        1,
		tamperBandwidthUploadHash: true,
	})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for a tampered upload_payload_hash", result.ScoreBps, failingScoreBps)
	}
}

func TestMeasureBandwidthFailsOnTamperedSignature(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{
		privateKey:               agentPriv,
		declaredIngressMbps:      1,
		declaredEgressMbps:       1,
		tamperBandwidthSignature: true,
	})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for a tampered signature", result.ScoreBps, failingScoreBps)
	}
}

func TestMeasureBandwidthReportsFailureForUnreachableAgent(t *testing.T) {
	// A dashboard that resolves to a closed port -- the Agent is
	// unreachable, which must score 0 with a reason, not return an error
	// from MeasureBandwidth itself (see its doc comment).
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_endpoint":         "https://127.0.0.1:1", // reserved, nothing listens here
			"public_key":             hex.EncodeToString(make([]byte, 32)),
			"bandwidth_ingress_mbps": int32(1),
			"bandwidth_egress_mbps":  int32(1),
		})
	}))
	defer dashboard.Close()

	resolver, err := NewEndpointResolver(dashboard.URL)
	if err != nil {
		t.Fatalf("new endpoint resolver: %v", err)
	}
	client := NewChallengeClient(ChallengeClientConfig{
		Resolver:          resolver,
		ClientCertificate: testValidatorClientCert(t),
		DialTimeout:       1 * time.Second,
		ChallengeTimeout:  1 * time.Second,
	})
	result, err := client.MeasureBandwidth(context.Background(), "irrelevant")
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for an unreachable agent", result.ScoreBps, failingScoreBps)
	}
	if result.Reason == "" {
		t.Fatal("expected a non-empty failure reason")
	}
}

// newChallengeClientWithProbes is newChallengeClient plus an explicit
// BandwidthProbesPerRound, for ADR-025 §1's multi-probe tests -- kept
// separate from newChallengeClient so every other test in this package
// keeps exercising the default probe count unchanged.
func newChallengeClientWithProbes(t *testing.T, harness *testAgentHarness, probes int) *ChallengeClient {
	t.Helper()
	resolver, err := NewEndpointResolver(harness.dashboard.URL)
	if err != nil {
		t.Fatalf("new endpoint resolver: %v", err)
	}
	return NewChallengeClient(ChallengeClientConfig{
		Resolver:                resolver,
		ClientCertificate:       testValidatorClientCert(t),
		AgentServerCAPool:       nil,
		DialTimeout:             2 * time.Second,
		ChallengeTimeout:        2 * time.Second,
		BandwidthProbesPerRound: probes,
	})
}

// TestMeasureBandwidthRunsExactlyConfiguredProbeCount pins ADR-025 §1's
// core behavior change: MeasureBandwidth is no longer a single round trip.
func TestMeasureBandwidthRunsExactlyConfiguredProbeCount(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{privateKey: agentPriv, declaredIngressMbps: 1, declaredEgressMbps: 1}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClientWithProbes(t, harness, 5)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != passingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d (reason=%q)", result.ScoreBps, passingScoreBps, result.Reason)
	}
	fake.mu.Lock()
	calls := fake.measureBandwidthCalls
	fake.mu.Unlock()
	if calls != 5 {
		t.Fatalf("measureBandwidthCalls = %d, want 5 (BandwidthProbesPerRound)", calls)
	}
}

// TestMeasureBandwidthFailsTheWholeRoundIfAnySingleProbeFails is ADR-025
// §1's anti-gaming property made concrete: a provider that sustains
// bandwidth for most probes but fails even one must not pass overall --
// there is no valid measurement to take a minimum over for that probe.
func TestMeasureBandwidthFailsTheWholeRoundIfAnySingleProbeFails(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey:            agentPriv,
		declaredIngressMbps:   1,
		declaredEgressMbps:    1,
		tamperBandwidthOnCall: 2, // the middle of 3 probes
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClientWithProbes(t, harness, 3)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d when probe 2/3 fails signature verification", result.ScoreBps, failingScoreBps)
	}
	fake.mu.Lock()
	calls := fake.measureBandwidthCalls
	fake.mu.Unlock()
	if calls != 2 {
		t.Fatalf("measureBandwidthCalls = %d, want 2 (stops at the first failing probe, does not run probe 3)", calls)
	}
}

// passesBandwidthTolerance and estimateThroughputMbps are pure and cheap
// to unit-test directly, independent of any real network round trip.
func TestPassesBandwidthToleranceTreatsNonPositiveDeclaredAsAutoPass(t *testing.T) {
	if !passesBandwidthTolerance(0, 0) {
		t.Fatal("expected a non-positive declared figure to trivially pass")
	}
	if !passesBandwidthTolerance(0, -5) {
		t.Fatal("expected a negative declared figure to trivially pass")
	}
}

func TestPassesBandwidthToleranceAppliesTheConfiguredFraction(t *testing.T) {
	// 70% of 100 Mbps is 70 Mbps.
	if !passesBandwidthTolerance(70, 100) {
		t.Fatal("expected exactly the threshold to pass")
	}
	if passesBandwidthTolerance(69.9, 100) {
		t.Fatal("expected just under the threshold to fail")
	}
}

func TestEstimateThroughputMbpsSplitsProportionallyBySize(t *testing.T) {
	// 1 second of network time, symmetric byte counts -> each direction
	// gets ~half the time and each direction's Mbps reflects its own byte
	// count over that half.
	ingress, egress := estimateThroughputMbps(1*time.Second, 0, 1_000_000, 1_000_000)
	if ingress <= 0 || egress <= 0 {
		t.Fatalf("expected positive throughput in both directions, got ingress=%v egress=%v", ingress, egress)
	}
	if ingress != egress {
		t.Fatalf("expected symmetric byte counts to produce equal throughput, got ingress=%v egress=%v", ingress, egress)
	}

	// All bytes in one direction: the other direction must be exactly 0,
	// not merely small.
	ingressOnly, egressOnly := estimateThroughputMbps(1*time.Second, 0, 1_000_000, 0)
	if ingressOnly <= 0 {
		t.Fatal("expected positive ingress throughput")
	}
	if egressOnly != 0 {
		t.Fatalf("expected exactly zero egress throughput when downloadBytes is 0, got %v", egressOnly)
	}
}
