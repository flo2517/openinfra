package networkvalidator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// A declared capacity (1/1 Mbps above) makes this dimension judgeable:
	// an unreachable Agent is a genuine failure, not a gap in discovery
	// data, and must never be conflated with Unscored (see
	// ChallengeResult.Unscored's doc comment) just because the network
	// partition and the "nothing to verify against" case both surface as
	// a failed probe internally.
	if result.Unscored {
		t.Fatal("Unscored = true; capacity was declared, so an unreachable Agent must be a genuine failure, not an unscored gap")
	}
}

// TestMeasureBandwidthFailsOnContextDeadlineDuringProbe is the "agent
// accepts the connection but never responds in time" partition variant,
// distinct from TestMeasureBandwidthReportsFailureForUnreachableAgent's
// immediate connection-refused: the Agent here is reachable and the gRPC
// call is genuinely in flight, but it exceeds the validator's own
// deadline. Must resolve the same way -- a failed, judged result, not a
// hang and not an error returned from MeasureBandwidth itself.
func TestMeasureBandwidthFailsOnContextDeadlineDuringProbe(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey:          agentPriv,
		declaredIngressMbps: 1,
		declaredEgressMbps:  1,
		// Longer than the client's ChallengeTimeout below, so the RPC's
		// own context expires mid-flight rather than the connection ever
		// being refused.
		artificialLatency: 3 * time.Second,
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	resolver, err := NewEndpointResolver(harness.dashboard.URL)
	if err != nil {
		t.Fatalf("new endpoint resolver: %v", err)
	}
	client := NewChallengeClient(ChallengeClientConfig{
		Resolver:                resolver,
		ClientCertificate:       testValidatorClientCert(t),
		DialTimeout:             1 * time.Second,
		ChallengeTimeout:        300 * time.Millisecond,
		BandwidthProbesPerRound: 1,
	})

	started := time.Now()
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("MeasureBandwidth took %v to return after a deadline-exceeded probe; a partition must not hang the caller", elapsed)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for a probe that exceeded its deadline", result.ScoreBps, failingScoreBps)
	}
	if result.Unscored {
		t.Fatal("Unscored = true; capacity was declared, a deadline-exceeded probe must be a genuine failure")
	}
	if result.Reason == "" {
		t.Fatal("expected a non-empty failure reason")
	}
}

// TestMeasureBandwidthFailsWhenAgentPartitionsMidRound simulates a
// partition that starts partway through a multi-probe round (the Agent
// answers the first probe normally, then goes unreachable) rather than
// being down for the whole round -- the anti-gaming "one failed probe
// fails the whole round" property (see MeasureBandwidth's doc comment)
// must hold for a genuine mid-round partition exactly as it does for a
// tampered probe.
func TestMeasureBandwidthFailsWhenAgentPartitionsMidRound(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey:            agentPriv,
		declaredIngressMbps:   1,
		declaredEgressMbps:    1,
		failBandwidthFromCall: 2, // the first of 3 probes succeeds, then the partition begins
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClientWithProbes(t, harness, 3)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d when the Agent partitions mid-round", result.ScoreBps, failingScoreBps)
	}
	if result.Unscored {
		t.Fatal("Unscored = true; capacity was declared, a mid-round partition must be a genuine failure")
	}
	fake.mu.Lock()
	calls := fake.measureBandwidthCalls
	fake.mu.Unlock()
	if calls != 2 {
		t.Fatalf("measureBandwidthCalls = %d, want 2 (stops at the partitioned call, does not run probe 3)", calls)
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
//
// A non-positive declared figure means there is nothing to verify
// against. It used to return true here, which turned "we checked
// nothing" into a full-marks pass written to chain. MeasureBandwidth now
// classifies that case as unscored before this is reached, and this
// function refuses it too, so the auto-pass cannot come back through
// either door.
func TestPassesBandwidthToleranceRefusesAnUnverifiableDeclaredFigure(t *testing.T) {
	for _, declared := range []int32{0, -5} {
		// Even a wildly high measurement must not pass: the point is that
		// there is no claim to check it against, not that the link is slow.
		if passesBandwidthTolerance(10_000, declared) {
			t.Errorf("declared=%d: expected no pass when there is nothing to verify against", declared)
		}
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

// An undeclared capacity must produce an explicitly unscored result, not
// a pass. Scoring it as a pass wrote 10_000 basis points into consensus
// state on the strength of no verification at all, which is the false
// success ADR-011 exists to prevent -- and it was reachable simply by a
// provider never heartbeating its ResourceCapability.Bandwidth.
//
// Failing it instead would be the opposite error: punishing a provider
// for a gap in the Control Plane's own discovery data.
func TestMeasureBandwidthIsUnscoredWithoutADeclaredCapacity(t *testing.T) {
	cases := map[string]struct{ ingress, egress int32 }{
		"neither direction declared": {0, 0},
		"only ingress declared":      {1, 0},
		"only egress declared":       {0, 1},
		"negative figure":            {-1, 1},
	}
	for name, declared := range cases {
		t.Run(name, func(t *testing.T) {
			_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate agent key: %v", err)
			}
			harness := startTestAgentHarness(t, &fakeAgentServer{
				privateKey:          agentPriv,
				declaredIngressMbps: declared.ingress,
				declaredEgressMbps:  declared.egress,
			})
			defer harness.close()

			client := newChallengeClient(t, harness)
			result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
			if err != nil {
				t.Fatalf("MeasureBandwidth: %v", err)
			}
			if !result.Unscored {
				t.Fatalf("Unscored = false (ScoreBps=%d, reason=%q); an unverifiable measurement must not be scored",
					result.ScoreBps, result.Reason)
			}
			// Belt and braces: a caller that ignores Unscored must not
			// find a passing score sitting in the result either.
			if result.ScoreBps == passingScoreBps {
				t.Fatalf("ScoreBps = %d on an unscored result", result.ScoreBps)
			}
		})
	}
}

// A provider with no declared capacity must get Unscored even when its
// Agent's response also fails verification -- the two conditions are
// independent, and Unscored must win regardless of which one a given
// probe happens to hit. Before this, a failed probe returned a permanent
// failingScoreBps immediately, without ever reaching the declared-
// capacity check below it: exactly the case this test pins.
func TestMeasureBandwidthIsUnscoredEvenWhenAProbeAlsoFails(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey:            agentPriv,
		declaredIngressMbps:   0, // no declared capacity: nothing to verify against
		declaredEgressMbps:    0,
		tamperBandwidthOnCall: 1, // the very first probe also fails verification
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if !result.Unscored {
		t.Fatalf("Unscored = false (ScoreBps=%d, reason=%q); an undeclared provider must never get a permanent failing score just because a probe also failed",
			result.ScoreBps, result.Reason)
	}
	// Belt and braces, mirroring TestMeasureBandwidthIsUnscoredWithout-
	// ADeclaredCapacity: a caller that ignores Unscored must not find a
	// passing score sitting in the result either.
	if result.ScoreBps == passingScoreBps {
		t.Fatalf("ScoreBps = %d on an unscored result", result.ScoreBps)
	}
}

// ADR-025 §5's asymmetric-link case: a link that clears the tolerance in
// one direction and fails it in the other must score 0, not an averaged
// partial pass. The two directions are scored independently and the round
// fails if either does -- a provider that delivers its promised download
// while failing its promised upload has not delivered what it advertised.
func TestMeasureBandwidthFailsAnAsymmetricLinkInEitherDirection(t *testing.T) {
	// One direction declared at 1 Mbps (any loopback clears it), the other
	// at 100 Pbps (nothing clears it).
	cases := map[string]struct{ ingress, egress int32 }{
		"egress unattainable":  {1, 100_000_000},
		"ingress unattainable": {100_000_000, 1},
	}
	for name, declared := range cases {
		t.Run(name, func(t *testing.T) {
			_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate agent key: %v", err)
			}
			harness := startTestAgentHarness(t, &fakeAgentServer{
				privateKey:          agentPriv,
				declaredIngressMbps: declared.ingress,
				declaredEgressMbps:  declared.egress,
			})
			defer harness.close()

			client := newChallengeClient(t, harness)
			result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
			if err != nil {
				t.Fatalf("MeasureBandwidth: %v", err)
			}
			if result.Unscored {
				t.Fatalf("Unscored = true; both directions were declared, so this is judgeable (reason=%q)", result.Reason)
			}
			if result.ScoreBps != failingScoreBps {
				t.Fatalf("ScoreBps = %d, want %d: one failing direction must fail the round outright, never average to a partial pass (reason=%q)",
					result.ScoreBps, failingScoreBps, result.Reason)
			}
			// The Reason must still report both directions' figures, not
			// just the failing one -- proof the passing direction's
			// measurement was not silently dropped or corrupted by the
			// other direction's failure.
			if !strings.Contains(result.Reason, "ingress=") || !strings.Contains(result.Reason, "egress=") {
				t.Fatalf("Reason %q does not report both directions", result.Reason)
			}
		})
	}
}

// TestMeasureBandwidthPassesAsymmetricLinkWhenBothDirectionsClearTheirOwnThreshold
// is the pass-side complement to TestMeasureBandwidthFailsAnAsymmetric-
// LinkInEitherDirection: genuinely different (not extreme/unattainable)
// declared ingress and egress figures, both independently clearable by a
// real loopback link, must both independently pass -- proving the two
// thresholds are applied to their own direction and not, say, swapped or
// collapsed into a single shared check.
func TestMeasureBandwidthPassesAsymmetricLinkWhenBothDirectionsClearTheirOwnThreshold(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{
		privateKey: agentPriv,
		// Different figures in each direction -- any real loopback link
		// clears both, so a bug that applied the wrong threshold to the
		// wrong direction (or averaged them) would only be caught by a
		// case like TestMeasureBandwidthFailsAnAsymmetricLinkInEither-
		// Direction above; this case instead pins that two merely
		// *different* (not swapped-to-fail) declared figures still both
		// pass together.
		declaredIngressMbps: 1,
		declaredEgressMbps:  2,
	})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.Unscored {
		t.Fatalf("Unscored = true; both directions were declared (reason=%q)", result.Reason)
	}
	if result.ScoreBps != passingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d: both directions independently clear their own (different) threshold (reason=%q)", result.ScoreBps, passingScoreBps, result.Reason)
	}
}

// --- Congestion (issue #73): probes that succeed but are slow/degraded.
//
// The scoring itself stays the binary pass/fail ADR-015 §5 specifies --
// there is no partial credit in this design -- but the *measurement* that
// feeds that decision must reflect degradation proportionally (a slower
// probe produces a lower Mbps figure, not a crash or a hard-coded value),
// and the tolerance check must be what separates "slower but still
// acceptable" from "too slow," not an unrelated hard failure mode. The
// three tests below exercise that with fakeAgentServer's artificialLatency
// knob, which inflates a real measured round trip the same way a
// congested link would (see the knob's doc comment).

// TestMeasureBandwidthPassesDespiteElevatedLatencyWithinTolerance: a
// probe slowed down by injected latency still measures comfortably above
// a low declared figure -- congestion that stays within tolerance must
// not be treated as an automatic fail just because it is slower than an
// unloaded link would be.
func TestMeasureBandwidthPassesDespiteElevatedLatencyWithinTolerance(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey: agentPriv,
		// 10 Mbps (7 Mbps at the 70% threshold) stays clearable even in a
		// pessimistic worst case for this injected delay -- see the
		// congestion tests' shared reasoning in this file's PR description.
		declaredIngressMbps: 10,
		declaredEgressMbps:  10,
		artificialLatency:   400 * time.Millisecond,
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClientWithProbes(t, harness, 1)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.Unscored {
		t.Fatalf("Unscored = true; capacity was declared (reason=%q)", result.Reason)
	}
	if result.ScoreBps != passingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d: congestion that stays within tolerance must still pass (reason=%q)", result.ScoreBps, passingScoreBps, result.Reason)
	}
}

// TestMeasureBandwidthFailsWhenElevatedLatencyDropsBelowTolerance: the
// same injected delay against a declared figure the degraded link cannot
// plausibly clear -- congestion severe enough to breach the tolerance
// must still fail cleanly (a scored 0 with a reason), the same as any
// other failing measurement, not a different/special-cased outcome.
func TestMeasureBandwidthFailsWhenElevatedLatencyDropsBelowTolerance(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey: agentPriv,
		// 1000 Mbps (700 Mbps at the 70% threshold) is above what an 8MiB
		// probe can measure once >=400ms of the round trip is pure
		// injected delay, even in the most favorable (near-zero transfer
		// overhead) case: networkMs >= ~399ms split 50/50 by direction
		// caps each direction at roughly 67_108_864 bits / 199.5ms/1000 ~=
		// 336 Mbps, safely under the 700 Mbps threshold regardless of test
		// environment variance.
		declaredIngressMbps: 1000,
		declaredEgressMbps:  1000,
		artificialLatency:   400 * time.Millisecond,
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClientWithProbes(t, harness, 1)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.Unscored {
		t.Fatalf("Unscored = true; capacity was declared (reason=%q)", result.Reason)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d: congestion severe enough to breach tolerance must fail (reason=%q)", result.ScoreBps, failingScoreBps, result.Reason)
	}
}

// TestMeasureBandwidthRoundReflectsTheSlowestProbeAmongMultiple: only the
// middle of 3 probes is congested. ADR-025 §1's minimum-across-probes
// anti-gaming property (already pinned for tampered/failed probes by
// TestMeasureBandwidthFailsTheWholeRoundIfAnySingleProbeFails) must apply
// identically to a probe that is merely slow, not corrupt: two fast probes
// cannot average out one genuinely congested one.
func TestMeasureBandwidthRoundReflectsTheSlowestProbeAmongMultiple(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey: agentPriv,
		// Same reasoning as TestMeasureBandwidthFailsWhenElevatedLatency-
		// DropsBelowTolerance: 1000 Mbps is unreachable by the one
		// congested probe no matter how fast the other two are.
		declaredIngressMbps:     1000,
		declaredEgressMbps:      1000,
		artificialLatency:       400 * time.Millisecond,
		artificialLatencyOnCall: 2, // only the middle of 3 probes
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClientWithProbes(t, harness, 3)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d: one congested probe among two fast ones must still fail the round (reason=%q)", result.ScoreBps, failingScoreBps, result.Reason)
	}
	fake.mu.Lock()
	calls := fake.measureBandwidthCalls
	fake.mu.Unlock()
	if calls != 3 {
		t.Fatalf("measureBandwidthCalls = %d, want 3: unlike a failed/tampered probe, a merely slow one still completes and all 3 probes run", calls)
	}
}

// --- Spoofed/tampered results (issue #73).

// TestMeasureBandwidthRejectsImplausibleServerProcessingTime pins the
// bug fix in this PR: a correctly-signed response (the Agent has the
// real private key -- this is not a signature-tamper case, see
// TestMeasureBandwidthFailsOnTamperedSignature for that) that claims a
// server_processing_ms wildly exceeding the validator's own observed
// round trip must be rejected as physically implausible, not trusted at
// face value. Before the fix, estimateThroughputMbps's networkMs floor
// (see its doc comment) silently turned this into a near-zero network
// time and therefore an astronomically inflated -- and passing --
// throughput figure, letting a dishonest Agent manufacture a pass for a
// link that was never actually measured.
func TestMeasureBandwidthRejectsImplausibleServerProcessingTime(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	fake := &fakeAgentServer{
		privateKey: agentPriv,
		// Low enough that an honest probe would trivially pass -- so a
		// pass here can only be explained by the spoofed processing time,
		// not a genuinely fast link.
		declaredIngressMbps: 1,
		declaredEgressMbps:  1,
		// 60s claimed processing time, correctly signed, against a
		// loopback round trip that in reality takes a small fraction of a
		// second.
		spoofServerProcessingMs: 60_000,
	}
	harness := startTestAgentHarness(t, fake)
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.MeasureBandwidth(context.Background(), harness.providerID)
	if err != nil {
		t.Fatalf("MeasureBandwidth: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d: an implausible server_processing_ms must be rejected, not scored as a pass (reason=%q)", result.ScoreBps, failingScoreBps, result.Reason)
	}
	if result.Unscored {
		t.Fatal("Unscored = true; capacity was declared, this must be a genuine rejection, not an unscored gap")
	}
	if result.Reason == "" {
		t.Fatal("expected a non-empty failure reason")
	}
}
