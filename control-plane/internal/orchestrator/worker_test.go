package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/scheduler"
	"github.com/openinfra/network/internal/workloadapi"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

func testRanker() *scheduler.Ranker {
	return scheduler.NewRanker(scheduler.DefaultMaxReputationScore, scheduler.DefaultDefaultReputationScore)
}

func TestRankableCandidatesExcludesMissingEndpointAndSelectsBestFit(t *testing.T) {
	providers := []agentmanager.SchedulableProvider{
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "no-endpoint"}, Capabilities: &sharedv1.ResourceCapability{CpuAvailable: 8, RamAvailableMb: 8192}},
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "small", AgentEndpoint: "https://small:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuAvailable: 1, RamAvailableMb: 128}},
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "selected", AgentEndpoint: "https://selected:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuAvailable: 4, RamAvailableMb: 4096, CpuTotal: 4, RamTotalMb: 4096}},
	}
	worker := NewWorker(nil, nil, nil, nil, testRanker())
	candidates, capacities := worker.rankableCandidates(context.Background(), providers)
	decision := worker.ranker.Rank(sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, &sharedv1.ResourceRequirements{Cpu: 2, RamMb: 1024}, nil, candidates)
	if decision.Selected == nil {
		t.Fatal("expected a winning candidate")
	}
	if decision.Selected.ProviderID != "selected" {
		t.Fatalf("selected %q, want %q", decision.Selected.ProviderID, "selected")
	}
	if len(decision.Excluded) != 2 {
		t.Fatalf("expected both no-endpoint and small excluded, got %+v", decision.Excluded)
	}
	if capacities["selected"].TotalCPUMillicores != 4000 || capacities["selected"].TotalRAMMB != 4096 {
		t.Fatalf("unexpected capacity for selected provider: %+v", capacities["selected"])
	}
}

func TestRankableCandidatesWiresBandwidthCapacityThrough(t *testing.T) {
	providers := []agentmanager.SchedulableProvider{
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "with-bandwidth", AgentEndpoint: "https://a:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuTotal: 4, CpuAvailable: 4, RamTotalMb: 4096, RamAvailableMb: 4096, Bandwidth: &sharedv1.Bandwidth{IngressMbps: 200, EgressMbps: 100}}},
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "no-bandwidth-declared", AgentEndpoint: "https://b:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuTotal: 4, CpuAvailable: 4, RamTotalMb: 4096, RamAvailableMb: 4096}},
	}
	worker := NewWorker(nil, nil, nil, nil, testRanker())
	candidates, capacities := worker.rankableCandidates(context.Background(), providers)

	if capacities["with-bandwidth"].TotalIngressMbps != 200 || capacities["with-bandwidth"].TotalEgressMbps != 100 {
		t.Fatalf("unexpected bandwidth capacity: %+v", capacities["with-bandwidth"])
	}
	if capacities["no-bandwidth-declared"].TotalIngressMbps != 0 || capacities["no-bandwidth-declared"].TotalEgressMbps != 0 {
		t.Fatalf("expected zero bandwidth capacity for an undeclared provider: %+v", capacities["no-bandwidth-declared"])
	}
	var found bool
	for _, c := range candidates {
		if c.ProviderID == "with-bandwidth" {
			found = true
			if c.IngressTotalMbps != 200 || c.EgressTotalMbps != 100 {
				t.Fatalf("candidate bandwidth not wired through: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("expected the with-bandwidth candidate to be present")
	}
}

// TestRankableCandidatesWiresZoneThrough covers ADR-026 §4/§5: zone is
// extracted from ResourceCapability.Zone into Candidate.Zone alongside the
// existing CPU/RAM/storage/bandwidth fields, and an undeclared zone stays
// the empty string rather than some other sentinel.
func TestRankableCandidatesWiresZoneThrough(t *testing.T) {
	providers := []agentmanager.SchedulableProvider{
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "zoned", AgentEndpoint: "https://a:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuTotal: 4, CpuAvailable: 4, RamTotalMb: 4096, RamAvailableMb: 4096, Zone: "us-east"}},
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "unzoned", AgentEndpoint: "https://b:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuTotal: 4, CpuAvailable: 4, RamTotalMb: 4096, RamAvailableMb: 4096}},
	}
	worker := NewWorker(nil, nil, nil, nil, testRanker())
	candidates, _ := worker.rankableCandidates(context.Background(), providers)

	zones := map[string]string{}
	for _, c := range candidates {
		zones[c.ProviderID] = c.Zone
	}
	if zones["zoned"] != "us-east" {
		t.Fatalf("expected zoned candidate's Zone to be %q, got %q", "us-east", zones["zoned"])
	}
	if zones["unzoned"] != "" {
		t.Fatalf("expected unzoned candidate's Zone to be empty, got %q", zones["unzoned"])
	}
}

// TestRankableCandidatesAppliesWireGuardOverheadToCapacityLedgerOnlyWhenOverlayActive
// covers issue #115: AssignLease's persistent, atomic capacity ledger
// (workloadapi.ProviderCapacity) must reflect the same post-overhead
// throughput ceiling scoreOne already uses for single-candidate fit
// scoring, once a WireGuard overlay is actually configured on this
// worker -- otherwise two workloads that each individually clear both
// checks can jointly reserve more than the overlay can ever deliver (the
// exact scenario #114 fixed for scoring alone). scheduler.Candidate's own
// Ingress/EgressTotalMbps must stay raw regardless, since scoreOne applies
// the same adjustment itself when the ranker is overlay-enabled --
// double-applying it here would under-score every candidate.
func TestRankableCandidatesAppliesWireGuardOverheadToCapacityLedgerOnlyWhenOverlayActive(t *testing.T) {
	providers := []agentmanager.SchedulableProvider{
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "with-bandwidth", AgentEndpoint: "https://a:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuTotal: 4, CpuAvailable: 4, RamTotalMb: 4096, RamAvailableMb: 4096, Bandwidth: &sharedv1.Bandwidth{IngressMbps: 1000, EgressMbps: 1000}}},
	}

	withoutOverlay := NewWorker(nil, nil, nil, nil, testRanker())
	_, capacitiesNoOverlay := withoutOverlay.rankableCandidates(context.Background(), providers)
	if capacitiesNoOverlay["with-bandwidth"].TotalIngressMbps != 1000 || capacitiesNoOverlay["with-bandwidth"].TotalEgressMbps != 1000 {
		t.Fatalf("expected raw capacity with no overlay configured, got %+v", capacitiesNoOverlay["with-bandwidth"])
	}

	withOverlay := NewWorker(nil, nil, nil, nil, testRanker())
	withOverlay.SetOverlay(stubOverlay{})
	candidates, capacitiesWithOverlay := withOverlay.rankableCandidates(context.Background(), providers)
	// 1000 * (1500-60)/1500 = 960, matching scheduler.WireGuardEffectiveMbps.
	if capacitiesWithOverlay["with-bandwidth"].TotalIngressMbps != 960 || capacitiesWithOverlay["with-bandwidth"].TotalEgressMbps != 960 {
		t.Fatalf("expected overhead-adjusted capacity with overlay configured, got %+v", capacitiesWithOverlay["with-bandwidth"])
	}
	for _, c := range candidates {
		if c.ProviderID == "with-bandwidth" && (c.IngressTotalMbps != 1000 || c.EgressTotalMbps != 1000) {
			t.Fatalf("candidate bandwidth must stay raw so scoreOne doesn't double-adjust it: %+v", c)
		}
	}
}

// TestSetOverlaySyncsTheRankersWireGuardFlag pins that SetOverlay is the
// only place that needs calling: a caller that sets the overlay must never
// have to remember a second call to keep the ranker's own bandwidth
// fit-scoring in agreement with the capacity ledger SetOverlay now also
// adjusts (see SetOverlay's doc comment, issue #115).
func TestSetOverlaySyncsTheRankersWireGuardFlag(t *testing.T) {
	ranker := testRanker()
	worker := NewWorker(nil, nil, nil, nil, ranker)

	worker.SetOverlay(stubOverlay{})
	if !ranker.WireGuardOverlayEnabled {
		t.Fatal("SetOverlay(non-nil) must enable the ranker's WireGuardOverlayEnabled flag")
	}

	worker.SetOverlay(nil)
	if ranker.WireGuardOverlayEnabled {
		t.Fatal("SetOverlay(nil) must disable the ranker's WireGuardOverlayEnabled flag")
	}
}

func TestCanonicalResourceHashIsStable(t *testing.T) {
	first := canonicalResourceHash([]byte{1, 2, 3}, "image@sha256:abc")
	if first != canonicalResourceHash([]byte{1, 2, 3}, "image@sha256:abc") {
		t.Fatal("hash is not stable")
	}
	if first == canonicalResourceHash([]byte{1, 2, 3}, "other@sha256:abc") {
		t.Fatal("image is not covered by hash")
	}
}

func TestWorkerRecoversEveryPersistedBoundary(t *testing.T) {
	definition, err := proto.Marshal(&sharedv1.WorkloadDefinition{
		DurationSeconds: 60,
		Requirements:    &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := agentmanager.SchedulableProvider{
		RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052", PublicKey: make([]byte, 32)},
		Capabilities:       &sharedv1.ResourceCapability{CpuAvailable: 2, RamAvailableMb: 1024},
	}
	tests := []struct {
		state, expected string
	}{
		{"REQUESTED", "begin-scheduling"},
		{"SCHEDULING", "assign-lease"},
		{"LEASE_PENDING", "mark-leased"},
		{"LEASED", "mark-deploying"},
		{"DEPLOYING", "mark-running"},
		{"STOPPING", "mark-stopped"},
	}
	for _, test := range tests {
		t.Run(test.state, func(t *testing.T) {
			item := workloadapi.Workload{WorkloadID: "workload", State: test.state, Definition: definition, Image: "image@sha256:digest", ProviderID: "provider", LeaseID: "42", Version: 7}
			store := &recordingStore{item: item}
			worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, successfulDispatcher{}, testRanker())
			worker.workerID = "worker-under-test"
			if err := worker.processOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if store.action != test.expected {
				t.Fatalf("action %q, want %q", store.action, test.expected)
			}
			if store.claimWorker != worker.workerID || store.mutated.Version != item.Version || store.mutated.WorkerID != worker.workerID {
				t.Fatalf("claim identity/version not propagated: %+v", store.mutated)
			}
		})
	}
}

func TestWorkerReleasesClaimThroughCASRetry(t *testing.T) {
	item := workloadapi.Workload{WorkloadID: "workload", State: "SCHEDULING", Definition: []byte("invalid"), Version: 11}
	store := &recordingStore{item: item}
	worker := NewWorker(store, staticDirectory{}, successfulLeases{}, successfulDispatcher{}, testRanker())
	worker.workerID = "recovery-worker"
	if err := worker.processOne(context.Background()); err == nil {
		t.Fatal("invalid definition must fail")
	}
	if store.action != "retry" || store.mutated.Version != 11 || store.mutated.WorkerID != worker.workerID {
		t.Fatalf("retry did not retain the claimed CAS identity: %+v", store.mutated)
	}
}

func TestDeployRetryReconcilesStatusBeforeIdempotentReplay(t *testing.T) {
	definition, err := proto.Marshal(&sharedv1.WorkloadDefinition{Requirements: &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256}})
	if err != nil {
		t.Fatal(err)
	}
	item := workloadapi.Workload{WorkloadID: "workload", State: "DEPLOYING", Definition: definition, ProviderID: "provider", LeaseID: "42", Version: 4, AttemptCount: 1}
	store := &recordingStore{item: item}
	dispatcher := &reconcilingDispatcher{}
	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
	worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	if err := worker.processOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := dispatcher.calls; len(got) != 2 || got[0] != "status" || got[1] != "deploy" {
		t.Fatalf("calls = %v, want status before deploy", got)
	}
}

// TestDeployingCarriesReservedEgressMbpsIntoTheDeployRequest is ADR-025
// §3's control-plane-side wiring: DEPLOYING must carry the workload's
// declared Bandwidth.EgressMbps (WorkloadDefinition.Requirements,
// scheduling-side) through into DeployRequest.Limits.EgressMbps (agent-
// executor's tc-enforcement input) unchanged, and must degrade to 0 --
// "no reservation, no tc rule" -- when the workload declared no
// bandwidth requirement at all, never a hard failure.
func TestDeployingCarriesReservedEgressMbpsIntoTheDeployRequest(t *testing.T) {
	tests := []struct {
		name         string
		requirements *sharedv1.ResourceRequirements
		want         int32
	}{
		{"with bandwidth requirement", &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256, Bandwidth: &sharedv1.Bandwidth{EgressMbps: 75}}, 75},
		{"without bandwidth requirement", &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition, err := proto.Marshal(&sharedv1.WorkloadDefinition{Requirements: test.requirements})
			if err != nil {
				t.Fatal(err)
			}
			item := workloadapi.Workload{WorkloadID: "workload", State: "DEPLOYING", Definition: definition, ProviderID: "provider", LeaseID: "42", Version: 1}
			store := &recordingStore{item: item}
			provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "provider", AgentEndpoint: "https://agent:50052"}}
			dispatcher := &capturingDispatcher{}
			worker := NewWorker(store, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
			if err := worker.processOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if dispatcher.request == nil {
				t.Fatal("no DeployRequest captured")
			}
			if got := dispatcher.request.Limits.EgressMbps; got != test.want {
				t.Fatalf("EgressMbps = %d, want %d", got, test.want)
			}
		})
	}
}

// TestNoEligibleProviderErrorSurfacesDistinctReasons covers ADR-026 §3's
// error-messaging mitigation: the NO_CAPACITY error must surface the
// distinct exclusion reasons actually seen, not just a count -- a general
// fix, not zone-specific.
func TestNoEligibleProviderErrorSurfacesDistinctReasons(t *testing.T) {
	excluded := []scheduler.Exclusion{
		{ProviderID: "a", Reason: "insufficient CPU"},
		{ProviderID: "b", Reason: "insufficient CPU"},
		{ProviderID: "c", Reason: "below workload's minimum reputation constraint"},
	}
	err := noEligibleProviderError(excluded, nil, "")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "3 candidates excluded") {
		t.Fatalf("expected the exclusion count in the message, got %q", msg)
	}
	if !strings.Contains(msg, "insufficient CPU") || !strings.Contains(msg, "below workload's minimum reputation constraint") {
		t.Fatalf("expected both distinct reasons in the message, got %q", msg)
	}
	// "insufficient CPU" must appear exactly once despite two candidates
	// sharing it -- reasons are deduplicated, not merely concatenated.
	if strings.Count(msg, "insufficient CPU") != 1 {
		t.Fatalf("expected the reason deduplicated, got %q", msg)
	}
}

// TestNoEligibleProviderErrorBoundsDistinctReasons pins that an
// unreasonably large number of distinct reasons is capped, not printed in
// full, per maxDistinctExclusionReasons.
func TestNoEligibleProviderErrorBoundsDistinctReasons(t *testing.T) {
	var excluded []scheduler.Exclusion
	for i := 0; i < maxDistinctExclusionReasons+3; i++ {
		excluded = append(excluded, scheduler.Exclusion{ProviderID: fmt.Sprintf("p%d", i), Reason: fmt.Sprintf("reason-%d", i)})
	}
	msg := noEligibleProviderError(excluded, nil, "").Error()
	if !strings.Contains(msg, "and 3 more") {
		t.Fatalf("expected the overflow to be summarized as \"and 3 more\", got %q", msg)
	}
}

// TestNoEligibleProviderErrorBoundsZonesPresent is the zones-present
// list's own version of the test above: a large, zone-diverse candidate
// pool (the exact permissionless, free-form-zone scenario ADR-026
// targets) must not produce an unbounded "zones present: ..." list --
// found in review as a gap the reasons list above didn't have.
func TestNoEligibleProviderErrorBoundsZonesPresent(t *testing.T) {
	var excluded []scheduler.Exclusion
	var candidates []scheduler.Candidate
	for i := 0; i < maxDistinctExclusionReasons+3; i++ {
		providerID := fmt.Sprintf("p%d", i)
		excluded = append(excluded, scheduler.Exclusion{ProviderID: providerID, Reason: scheduler.ReasonZoneMismatch})
		candidates = append(candidates, scheduler.Candidate{ProviderID: providerID, Zone: fmt.Sprintf("zone-%d", i)})
	}
	msg := noEligibleProviderError(excluded, candidates, "nowhere").Error()
	if !strings.Contains(msg, "zones present:") {
		t.Fatalf("expected the zone-specific message, got %q", msg)
	}
	if !strings.Contains(msg, "and 3 more") {
		t.Fatalf("expected the zone overflow to be summarized as \"and 3 more\" (8 distinct zones, capped at %d), got %q", maxDistinctExclusionReasons, msg)
	}
}

// TestNoEligibleProviderErrorTruncatesZonesAlphabeticallyNotByIterationOrder
// pins a real bug found in review: truncating in first-seen (candidate-
// iteration) order and only then sorting the survivors can silently drop
// the one zone name a tenant actually needs to see, e.g. their own typo's
// intended target -- the sorted-looking output would hide it instead of
// revealing it. Deliberately iterates the excluded candidates in *reverse*
// alphabetical zone order, so a first-seen-then-sort implementation would
// keep "zone-h".."zone-d" and drop "zone-c".."zone-a" -- the opposite of
// what a correct dedupe-then-sort-then-truncate implementation keeps.
func TestNoEligibleProviderErrorTruncatesZonesAlphabeticallyNotByIterationOrder(t *testing.T) {
	var excluded []scheduler.Exclusion
	var candidates []scheduler.Candidate
	zonesInReverseIterationOrder := []string{"zone-h", "zone-g", "zone-f", "zone-e", "zone-d", "zone-c", "zone-b", "zone-a"}
	for i, zone := range zonesInReverseIterationOrder {
		providerID := fmt.Sprintf("p%d", i)
		excluded = append(excluded, scheduler.Exclusion{ProviderID: providerID, Reason: scheduler.ReasonZoneMismatch})
		candidates = append(candidates, scheduler.Candidate{ProviderID: providerID, Zone: zone})
	}
	msg := noEligibleProviderError(excluded, candidates, "nowhere").Error()
	if !strings.Contains(msg, "zones present: zone-a, zone-b, zone-c, zone-d, zone-e, and 3 more") {
		t.Fatalf("expected the alphabetically-first 5 zones regardless of candidate iteration order, got %q", msg)
	}
}

// TestNoEligibleProviderErrorSurfacesZonesPresentOnAllZoneMismatch covers
// ADR-026 §3's named example directly: when every exclusion is a zone
// mismatch, the message names the requested zone and the set of zones
// actually declared among the excluded candidates, deduplicated and
// sorted -- not just "zone mismatch" repeated with no further signal.
func TestNoEligibleProviderErrorSurfacesZonesPresentOnAllZoneMismatch(t *testing.T) {
	excluded := []scheduler.Exclusion{
		{ProviderID: "a", Reason: scheduler.ReasonZoneMismatch},
		{ProviderID: "b", Reason: scheduler.ReasonZoneMismatch},
		{ProviderID: "c", Reason: scheduler.ReasonZoneMismatch},
	}
	candidates := []scheduler.Candidate{
		{ProviderID: "a", Zone: "us-east"},
		{ProviderID: "b", Zone: "us-west"},
		{ProviderID: "c", Zone: "us-east"},
	}
	msg := noEligibleProviderError(excluded, candidates, "us-eas").Error()
	if !strings.Contains(msg, `requested zone "us-eas" matched none`) {
		t.Fatalf("expected the requested zone quoted in the message, got %q", msg)
	}
	if !strings.Contains(msg, "zones present: us-east, us-west") {
		t.Fatalf("expected the deduplicated, sorted set of declared zones, got %q", msg)
	}
}

// TestNoEligibleProviderErrorFallsBackWhenExclusionReasonsAreMixed pins
// that the zone-specific message only triggers when *every* exclusion is
// a zone mismatch -- a mixed set of reasons (some zone, some not) falls
// back to the general distinct-reasons summary instead.
func TestNoEligibleProviderErrorFallsBackWhenExclusionReasonsAreMixed(t *testing.T) {
	excluded := []scheduler.Exclusion{
		{ProviderID: "a", Reason: scheduler.ReasonZoneMismatch},
		{ProviderID: "b", Reason: "insufficient CPU"},
	}
	candidates := []scheduler.Candidate{
		{ProviderID: "a", Zone: "us-west"},
		{ProviderID: "b", Zone: "us-east"},
	}
	msg := noEligibleProviderError(excluded, candidates, "us-east").Error()
	if strings.Contains(msg, "zones present") {
		t.Fatalf("expected the general summary, not the zone-specific one, got %q", msg)
	}
	if !strings.Contains(msg, scheduler.ReasonZoneMismatch) || !strings.Contains(msg, "insufficient CPU") {
		t.Fatalf("expected both distinct reasons in the general summary, got %q", msg)
	}
}

type recordingStore struct {
	item                workloadapi.Workload
	action, claimWorker string
	mutated             workloadapi.Workload
}

func (s *recordingStore) ClaimNext(_ context.Context, workerID string, _ time.Duration) (workloadapi.Workload, error) {
	s.claimWorker = workerID
	s.item.WorkerID = workerID
	return s.item, nil
}
func (s *recordingStore) record(action string, item workloadapi.Workload) {
	s.action, s.mutated = action, item
}
func (s *recordingStore) BeginScheduling(_ context.Context, item workloadapi.Workload) error {
	s.record("begin-scheduling", item)
	return nil
}
func (s *recordingStore) AssignLease(_ context.Context, item workloadapi.Workload, _ string, _ [32]byte, _ workloadapi.ProviderCapacity) (uint64, error) {
	s.record("assign-lease", item)
	return 42, nil
}
func (s *recordingStore) MarkLeased(_ context.Context, item workloadapi.Workload, _ uint64) error {
	s.record("mark-leased", item)
	return nil
}
func (s *recordingStore) RetryLater(_ context.Context, item workloadapi.Workload, _, _ string, _ time.Duration) error {
	s.record("retry", item)
	return nil
}
func (s *recordingStore) MarkDeploying(_ context.Context, item workloadapi.Workload, _ uint64) error {
	s.record("mark-deploying", item)
	return nil
}
func (s *recordingStore) MarkRunning(_ context.Context, item workloadapi.Workload, _ string) error {
	s.record("mark-running", item)
	return nil
}
func (s *recordingStore) MarkStopped(_ context.Context, item workloadapi.Workload, _ uint64) error {
	s.record("mark-stopped", item)
	return nil
}

type staticDirectory []agentmanager.SchedulableProvider

func (d staticDirectory) ListSchedulableProviders(context.Context) ([]agentmanager.SchedulableProvider, error) {
	return d, nil
}

type successfulLeases struct{}

func (successfulLeases) EnsureLeaseActive(context.Context, uint64, [32]byte, [32]byte, uint32) (blockchainbridge.FinalizedLease, error) {
	return blockchainbridge.FinalizedLease{}, nil
}
func (successfulLeases) EnsureLeaseCompleted(context.Context, uint64) (blockchainbridge.FinalizedLease, error) {
	return blockchainbridge.FinalizedLease{}, nil
}

type successfulDispatcher struct{}

func (successfulDispatcher) DeployAndConfirm(context.Context, agentmanager.RegisteredProvider, *agentv1.DeployRequest) (string, error) {
	return "container", nil
}
func (successfulDispatcher) StopAndConfirm(context.Context, agentmanager.RegisteredProvider, string) error {
	return nil
}

// capturingDispatcher records the last DeployRequest it received so a
// test can assert on Limits without needing a real Agent.
type capturingDispatcher struct{ request *agentv1.DeployRequest }

func (d *capturingDispatcher) DeployAndConfirm(_ context.Context, _ agentmanager.RegisteredProvider, req *agentv1.DeployRequest) (string, error) {
	d.request = req
	return "container", nil
}
func (d *capturingDispatcher) StopAndConfirm(context.Context, agentmanager.RegisteredProvider, string) error {
	return nil
}

type reconcilingDispatcher struct{ calls []string }

func (d *reconcilingDispatcher) GetRunningWorkload(context.Context, agentmanager.RegisteredProvider, string) (bool, error) {
	d.calls = append(d.calls, "status")
	return true, nil
}
func (d *reconcilingDispatcher) DeployAndConfirm(context.Context, agentmanager.RegisteredProvider, *agentv1.DeployRequest) (string, error) {
	d.calls = append(d.calls, "deploy")
	return "persisted-container", nil
}
func (d *reconcilingDispatcher) StopAndConfirm(context.Context, agentmanager.RegisteredProvider, string) error {
	return nil
}

// stubOverlay is a no-op OverlayManager: worker.overlay only needs to be
// non-nil for the tests that exercise "is the WireGuard overlay configured
// for this deployment" (see SetOverlay's doc comment) -- none of them
// actually call Attach/Revoke.
type stubOverlay struct{}

func (stubOverlay) Attach(context.Context, string, string, string, time.Time) error { return nil }
func (stubOverlay) Revoke(context.Context, string) error                            { return nil }
