package orchestrator

import (
	"context"
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
