package scheduler

import (
	"testing"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

func testRanker() *Ranker {
	return NewRanker(DefaultMaxReputationScore, DefaultDefaultReputationScore)
}

func TestRankExcludesMissingEndpointNilCapabilitiesAndInsufficientResources(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 2, RamMb: 1024, StorageGb: 10}
	candidates := []Candidate{
		{ProviderID: "no-endpoint", CPUAvailableCores: 8, RAMAvailableMB: 8192, StorageAvailableGB: 100},
		{ProviderID: "no-capabilities", AgentEndpoint: "https://a:1"}, // zero-value capabilities: everything insufficient
		{ProviderID: "low-cpu", AgentEndpoint: "https://b:1", CPUAvailableCores: 1, RAMAvailableMB: 8192, StorageAvailableGB: 100},
		{ProviderID: "low-ram", AgentEndpoint: "https://c:1", CPUAvailableCores: 8, RAMAvailableMB: 512, StorageAvailableGB: 100},
		{ProviderID: "low-storage", AgentEndpoint: "https://d:1", CPUAvailableCores: 8, RAMAvailableMB: 8192, StorageAvailableGB: 1},
		{ProviderID: "fits", AgentEndpoint: "https://e:1", CPUAvailableCores: 8, RAMAvailableMB: 8192, StorageAvailableGB: 100},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)

	if decision.Selected == nil || decision.Selected.ProviderID != "fits" {
		t.Fatalf("Selected = %+v, want fits", decision.Selected)
	}
	if len(decision.Ranked) != 1 {
		t.Fatalf("expected exactly one survivor, got %+v", decision.Ranked)
	}
	excludedIDs := map[string]bool{}
	for _, e := range decision.Excluded {
		excludedIDs[e.ProviderID] = true
		if e.Reason == "" {
			t.Fatalf("exclusion for %s has no reason", e.ProviderID)
		}
	}
	for _, want := range []string{"no-endpoint", "no-capabilities", "low-cpu", "low-ram", "low-storage"} {
		if !excludedIDs[want] {
			t.Fatalf("expected %s to be excluded, excluded=%v", want, decision.Excluded)
		}
	}
}

func TestRankIsDeterministicAcrossRepeatedCalls(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 512}
	candidates := []Candidate{
		{ProviderID: "b", AgentEndpoint: "https://b", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 800, Storage: 800, Network: 800, Availability: 800, Reliability: 800}},
		{ProviderID: "a", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 800, Storage: 800, Network: 800, Availability: 800, Reliability: 800}},
		{ProviderID: "c", AgentEndpoint: "https://c", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 800, Storage: 800, Network: 800, Availability: 800, Reliability: 800}},
	}
	ranker := testRanker()
	first := ranker.Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)
	for i := 0; i < 20; i++ {
		again := ranker.Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)
		if len(again.Ranked) != len(first.Ranked) {
			t.Fatalf("run %d: ranking length changed", i)
		}
		for j := range first.Ranked {
			if again.Ranked[j] != first.Ranked[j] {
				t.Fatalf("run %d: ranking order changed at %d: %+v vs %+v", i, j, again.Ranked[j], first.Ranked[j])
			}
		}
	}
	// All three candidates are identical except ProviderID, so equal
	// scores force the tie-break: lexicographic order, a < b < c.
	if len(first.Ranked) != 3 || first.Ranked[0].ProviderID != "a" || first.Ranked[1].ProviderID != "b" || first.Ranked[2].ProviderID != "c" {
		t.Fatalf("expected deterministic lexicographic tie-break, got %+v", first.Ranked)
	}
}

func TestRankPrefersHigherReputationAtEqualResourceFit(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 512}
	candidates := []Candidate{
		{ProviderID: "low-rep", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 100, Storage: 100, Network: 100, Availability: 100, Reliability: 100}},
		{ProviderID: "high-rep", AgentEndpoint: "https://b", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 900, Storage: 900, Network: 900, Availability: 900, Reliability: 900}},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)
	if decision.Selected == nil || decision.Selected.ProviderID != "high-rep" {
		t.Fatalf("Selected = %+v, want high-rep", decision.Selected)
	}
}

func TestRankTreatsUnknownReputationAsDefaultNotZero(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 512}
	candidates := []Candidate{
		// No on-chain record yet: must rank at the default score, not as
		// if it had proven itself worthless (Reputation left zero-value
		// but HasReputation is false).
		{ProviderID: "unscored", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: false},
		{ProviderID: "proven-bad", AgentEndpoint: "https://b", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{}},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)
	if decision.Selected == nil || decision.Selected.ProviderID != "unscored" {
		t.Fatalf("Selected = %+v, want unscored (default beats a proven-zero record)", decision.Selected)
	}
}

func TestRankEnforcesMinReputationConstraint(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 512}
	constraints := &sharedv1.WorkloadConstraints{MinReputation: 700} // 0..1000 scale, see ADR note in rank.go
	candidates := []Candidate{
		{ProviderID: "below", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 600, Storage: 600, Network: 600, Availability: 600, Reliability: 600}},
		{ProviderID: "above", AgentEndpoint: "https://b", CPUAvailableCores: 4, RAMAvailableMB: 4096, HasReputation: true, Reputation: ReputationVector{Compute: 800, Storage: 800, Network: 800, Availability: 800, Reliability: 800}},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, constraints, candidates)
	if len(decision.Ranked) != 1 || decision.Ranked[0].ProviderID != "above" {
		t.Fatalf("expected only 'above' to survive the min_reputation constraint, got %+v", decision.Ranked)
	}
	found := false
	for _, e := range decision.Excluded {
		if e.ProviderID == "below" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'below' to be excluded, got %+v", decision.Excluded)
	}
}

func TestRankReturnsNoSelectionWhenEverythingIsExcluded(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 100, RamMb: 100_000}
	candidates := []Candidate{
		{ProviderID: "too-small", AgentEndpoint: "https://a", CPUAvailableCores: 1, RAMAvailableMB: 512},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)
	if decision.Selected != nil {
		t.Fatalf("expected no selection, got %+v", decision.Selected)
	}
	if len(decision.Excluded) != 1 {
		t.Fatalf("expected the sole candidate excluded with a reason, got %+v", decision.Excluded)
	}
}

func TestRankHandlesUnspecifiedRequirementsGracefully(t *testing.T) {
	// A workload requesting zero storage must not be excluded for
	// "insufficient storage" against a provider reporting zero available.
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256, StorageGb: 0}
	candidates := []Candidate{
		{ProviderID: "no-storage-reported", AgentEndpoint: "https://a", CPUAvailableCores: 2, RAMAvailableMB: 1024, StorageAvailableGB: 0},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)
	if decision.Selected == nil {
		t.Fatalf("a zero storage requirement must not exclude a provider with zero storage reported: %+v", decision.Excluded)
	}
}

func TestFitBpsClampsAtFullMarksAndNeverExceeds(t *testing.T) {
	cases := []struct {
		available, required int64
		wantBps             uint32
		wantOK              bool
	}{
		{available: 0, required: 0, wantBps: 10_000, wantOK: true},
		{available: 10, required: 0, wantBps: 10_000, wantOK: true},
		{available: 5, required: 10, wantBps: 0, wantOK: false},
		{available: 10, required: 10, wantBps: 10_000, wantOK: true},
		{available: 20, required: 10, wantBps: 10_000, wantOK: true}, // extra headroom is not rewarded beyond 10_000
		{available: 5, required: 10, wantBps: 0, wantOK: false},
	}
	for _, c := range cases {
		bps, ok := fitBps(c.available, c.required)
		if bps != c.wantBps || ok != c.wantOK {
			t.Errorf("fitBps(%d, %d) = (%d, %v), want (%d, %v)", c.available, c.required, bps, ok, c.wantBps, c.wantOK)
		}
	}
}

func TestProfileWeightsSumToTenThousand(t *testing.T) {
	// The documentation on ProfileWeights promises this; a typo that
	// breaks it should fail the build, not silently skew every ranking.
	for profile, weights := range DefaultProfileWeights {
		if weights.ResourceBps+weights.ReputationBps != 10_000 {
			t.Errorf("profile %v: ResourceBps+ReputationBps = %d, want 10_000", profile, weights.ResourceBps+weights.ReputationBps)
		}
		dimensionSum := weights.ComputeBps + weights.StorageBps + weights.NetworkBps + weights.AvailabilityBps + weights.ReliabilityBps
		if dimensionSum != 10_000 {
			t.Errorf("profile %v: reputation dimension weights sum to %d, want 10_000", profile, dimensionSum)
		}
	}
	if fallbackWeights.ResourceBps+fallbackWeights.ReputationBps != 10_000 {
		t.Error("fallbackWeights.ResourceBps+ReputationBps != 10_000")
	}
	dimensionSum := fallbackWeights.ComputeBps + fallbackWeights.StorageBps + fallbackWeights.NetworkBps + fallbackWeights.AvailabilityBps + fallbackWeights.ReliabilityBps
	if dimensionSum != 10_000 {
		t.Error("fallbackWeights dimension weights do not sum to 10_000")
	}
}

func TestRankExcludesInsufficientBandwidthOnlyWhenRequested(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{
		Cpu: 1, RamMb: 512,
		Bandwidth: &sharedv1.Bandwidth{IngressMbps: 100, EgressMbps: 50},
	}
	candidates := []Candidate{
		{ProviderID: "no-bandwidth-declared", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096},
		{ProviderID: "insufficient-egress", AgentEndpoint: "https://b", CPUAvailableCores: 4, RAMAvailableMB: 4096, IngressTotalMbps: 200, EgressTotalMbps: 10},
		{ProviderID: "fits", AgentEndpoint: "https://c", CPUAvailableCores: 4, RAMAvailableMB: 4096, IngressTotalMbps: 200, EgressTotalMbps: 100},
	}
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, candidates)

	if decision.Selected == nil || decision.Selected.ProviderID != "fits" {
		t.Fatalf("Selected = %+v, want fits", decision.Selected)
	}
	excludedIDs := map[string]bool{}
	for _, e := range decision.Excluded {
		excludedIDs[e.ProviderID] = true
	}
	for _, want := range []string{"no-bandwidth-declared", "insufficient-egress"} {
		if !excludedIDs[want] {
			t.Fatalf("expected %s to be excluded for insufficient bandwidth, excluded=%v", want, decision.Excluded)
		}
	}
}

func TestRankIgnoresBandwidthEntirelyWhenNotRequested(t *testing.T) {
	// A workload with no bandwidth requirement must select the same
	// winner and produce the same score as before bandwidth existed --
	// bandwidth must never silently dilute cpu/ram/storage's weight in
	// the resource-fit average for workloads that don't care about it.
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 512}
	candidateWithoutBandwidth := Candidate{ProviderID: "a", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096}
	candidateWithZeroBandwidth := Candidate{ProviderID: "a", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096, IngressTotalMbps: 0, EgressTotalMbps: 0}

	withoutBandwidth := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, []Candidate{candidateWithoutBandwidth})
	withZeroBandwidth := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, requirements, nil, []Candidate{candidateWithZeroBandwidth})

	if withoutBandwidth.Selected == nil || withZeroBandwidth.Selected == nil {
		t.Fatalf("expected both to select, got %+v and %+v", withoutBandwidth.Selected, withZeroBandwidth.Selected)
	}
	if withoutBandwidth.Selected.ResourceFitBps != withZeroBandwidth.Selected.ResourceFitBps {
		t.Fatalf("ResourceFitBps differs by bandwidth alone: %d vs %d", withoutBandwidth.Selected.ResourceFitBps, withZeroBandwidth.Selected.ResourceFitBps)
	}
}

func TestRankUsesFallbackWeightsForAnUnknownProfile(t *testing.T) {
	requirements := &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 512}
	candidates := []Candidate{
		{ProviderID: "a", AgentEndpoint: "https://a", CPUAvailableCores: 4, RAMAvailableMB: 4096},
	}
	// WORKLOAD_PROFILE_UNSPECIFIED has no entry in DefaultProfileWeights.
	decision := testRanker().Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_UNSPECIFIED, requirements, nil, candidates)
	if decision.Selected == nil {
		t.Fatal("expected the fallback weights to still produce a valid score, not a panic or empty result")
	}
}
