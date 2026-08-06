package orchestrator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/scheduler"
	"github.com/openinfra/network/internal/workloadapi"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

// ReputationSource reads a provider's on-chain reputation vector by its
// raw 32-byte account (not the sha256-derived provider_id used in
// Postgres/dashboard). Optional: SetReputationSource may be left unset,
// in which case every candidate ranks with the ranker's default
// reputation score -- degraded (no signal), never a hard failure, since
// a chain RPC hiccup must not stall scheduling.
type ReputationSource interface {
	LatestReputationVector(ctx context.Context, provider [32]byte) (blockchainbridge.ReputationVector, bool, error)
}

type PersistentStore interface {
	ClaimNext(context.Context, string, time.Duration) (workloadapi.Workload, error)
	BeginScheduling(context.Context, workloadapi.Workload) error
	AssignLease(context.Context, workloadapi.Workload, string, [32]byte, workloadapi.ProviderCapacity) (uint64, error)
	MarkLeased(context.Context, workloadapi.Workload, uint64) error
	RetryLater(context.Context, workloadapi.Workload, string, string, time.Duration) error
	MarkDeploying(context.Context, workloadapi.Workload, uint64) error
	MarkRunning(context.Context, workloadapi.Workload, string) error
	MarkStopped(context.Context, workloadapi.Workload, uint64) error
}
type ProviderDirectory interface {
	ListSchedulableProviders(context.Context) ([]agentmanager.SchedulableProvider, error)
}
type LeaseRegistrar interface {
	EnsureLeaseActive(context.Context, uint64, [32]byte, [32]byte, uint32) (blockchainbridge.FinalizedLease, error)
	EnsureLeaseCompleted(context.Context, uint64) (blockchainbridge.FinalizedLease, error)
}
type AgentDispatcher interface {
	DeployAndConfirm(context.Context, agentmanager.RegisteredProvider, *agentv1.DeployRequest) (string, error)
	StopAndConfirm(context.Context, agentmanager.RegisteredProvider, string) error
}

// DeploymentReconciler queries authoritative Agent state before replaying a
// deployment whose previous response may have been lost.
type DeploymentReconciler interface {
	GetRunningWorkload(context.Context, agentmanager.RegisteredProvider, string) (bool, error)
}

// OverlayManager is invoked only after the chain lease has been finalized and
// the Agent has confirmed the workload container. Implementations must make
// Attach/Revoke idempotent and must not persist private key material.
type OverlayManager interface {
	Attach(context.Context, string, string, string, time.Time) error
	Revoke(context.Context, string) error
}

type Worker struct {
	store               PersistentStore
	directory           ProviderDirectory
	leases              LeaseRegistrar
	dispatcher          AgentDispatcher
	overlay             OverlayManager
	ranker              *scheduler.Ranker
	reputation          ReputationSource
	interval, blockTime time.Duration
	workerID            string
	claimDuration       time.Duration
}

// NewWorker's ranker is required, not a setter-configured optional like
// overlay/reputation: there is no reasonable degraded mode for "how do we
// rank providers at all" the way there is for "we have no live reputation
// signal" or "no WireGuard overlay in this environment".
func NewWorker(store PersistentStore, directory ProviderDirectory, leases LeaseRegistrar, dispatcher AgentDispatcher, ranker *scheduler.Ranker) *Worker {
	return &Worker{store: store, directory: directory, leases: leases, dispatcher: dispatcher, ranker: ranker, interval: time.Second, blockTime: 3 * time.Second, workerID: uuid.NewString(), claimDuration: 2 * time.Minute}
}

// SetOverlay enables the optional WireGuard overlay. It is intentionally a
// setter to keep existing worker tests and deployments that lack CAP_NET_ADMIN
// fully functional; production deployments configure it explicitly.
func (w *Worker) SetOverlay(overlay OverlayManager) { w.overlay = overlay }

// SetReputationSource enables real on-chain reputation-aware ranking. See
// ReputationSource's doc comment for the degraded-mode behavior when unset.
func (w *Worker) SetReputationSource(reputation ReputationSource) { w.reputation = reputation }
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if err := w.processOne(ctx); err != nil && !errors.Is(err, workloadapi.ErrNotFound) && !errors.Is(err, context.Canceled) {
			slog.Error("workload orchestration step failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (w *Worker) processOne(ctx context.Context) error {
	item, err := w.store.ClaimNext(ctx, w.workerID, w.claimDuration)
	if err != nil {
		return err
	}
	switch item.State {
	case "REQUESTED":
		return w.store.BeginScheduling(ctx, item)
	case "SCHEDULING":
		definition, err := decodeDefinition(item.Definition)
		if err != nil {
			return w.retry(ctx, item, "INVALID_DEFINITION", err)
		}
		providers, err := w.directory.ListSchedulableProviders(ctx)
		if err != nil {
			return w.retry(ctx, item, "DIRECTORY_UNAVAILABLE", err)
		}
		candidates, capacities := w.rankableCandidates(ctx, providers)
		decision := w.ranker.Rank(definition.Profile, definition.Requirements, definition.Constraints, candidates)
		if decision.Selected == nil {
			return w.retry(ctx, item, "NO_CAPACITY", fmt.Errorf("no eligible provider (%d candidates excluded)", len(decision.Excluded)))
		}
		_, err = w.store.AssignLease(ctx, item, decision.Selected.ProviderID, canonicalResourceHash(item.Definition, item.Image), capacities[decision.Selected.ProviderID])
		if errors.Is(err, workloadapi.ErrCapacityExceeded) || errors.Is(err, workloadapi.ErrConflict) {
			// The ranking snapshot is now known-stale (either this
			// provider filled up between ranking and commit, or another
			// worker won a concurrent race for the same row/provider).
			// Retry promptly rather than waiting out the claim lease --
			// a fresh ranking pass may pick a different provider, or the
			// same one if it was just a transient race.
			return w.retry(ctx, item, "NO_CAPACITY", err)
		}
		return err
	case "LEASE_PENDING":
		leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse persisted lease id: %w", err)
		}
		providerKey, err := w.providerKey(ctx, item.ProviderID)
		if err != nil {
			return w.retry(ctx, item, "PROVIDER_UNAVAILABLE", err)
		}
		definition, err := decodeDefinition(item.Definition)
		if err != nil {
			return err
		}
		duration := uint32((time.Duration(definition.DurationSeconds)*time.Second + w.blockTime - 1) / w.blockTime)
		leaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := w.leases.EnsureLeaseActive(leaseCtx, leaseID, providerKey, item.ResourceHash, duration); err != nil {
			return w.retry(ctx, item, "LEASE_NOT_FINALIZED", err)
		}
		return w.store.MarkLeased(ctx, item, leaseID)
	case "LEASED":
		leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
		if err != nil {
			return err
		}
		return w.store.MarkDeploying(ctx, item, leaseID)
	case "DEPLOYING":
		provider, err := w.provider(ctx, item.ProviderID)
		if err != nil {
			return w.retry(ctx, item, "PROVIDER_UNAVAILABLE", err)
		}
		definition, err := decodeDefinition(item.Definition)
		if err != nil {
			return err
		}
		// A retry means the preceding Deploy result may have been lost. Query
		// Agent state first; Deploy itself remains idempotent and returns the
		// persisted container id when reconciliation finds an existing workload.
		if reconciler, ok := w.dispatcher.(DeploymentReconciler); ok && item.AttemptCount > 0 {
			statusCtx, statusCancel := context.WithTimeout(ctx, 10*time.Second)
			_, statusErr := reconciler.GetRunningWorkload(statusCtx, provider.RegisteredProvider, item.WorkloadID)
			statusCancel()
			if statusErr != nil {
				return w.retry(ctx, item, "AGENT_STATUS_UNKNOWN", statusErr)
			}
		}
		request := &agentv1.DeployRequest{WorkloadId: item.WorkloadID, LeaseId: item.LeaseID, Image: item.Image, Limits: &agentv1.ResourceLimits{CpuCores: definition.Requirements.Cpu, MemoryMb: definition.Requirements.RamMb}}
		deployCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
		containerID, err := w.dispatcher.DeployAndConfirm(deployCtx, provider.RegisteredProvider, request)
		if err != nil {
			return w.retry(ctx, item, "AGENT_DEPLOY_FAILED", err)
		}
		if w.overlay != nil {
			definitionExpiry := time.Now().UTC().Add(time.Duration(definition.DurationSeconds) * time.Second)
			if err := w.overlay.Attach(ctx, item.WorkloadID, item.LeaseID, containerID, definitionExpiry); err != nil {
				// Do not expose a running workload with a partially attached
				// network. Stop is best effort; the worker retries this state.
				_ = w.dispatcher.StopAndConfirm(ctx, provider.RegisteredProvider, item.WorkloadID)
				return w.retry(ctx, item, "OVERLAY_ATTACH_FAILED", err)
			}
		}
		return w.store.MarkRunning(ctx, item, containerID)
	case "STOPPING":
		leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
		if err != nil {
			return err
		}
		provider, err := w.provider(ctx, item.ProviderID)
		if err != nil {
			return w.retry(ctx, item, "PROVIDER_UNAVAILABLE", err)
		}
		stopCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := w.dispatcher.StopAndConfirm(stopCtx, provider.RegisteredProvider, item.WorkloadID); err != nil {
			return w.retry(ctx, item, "AGENT_STOP_FAILED", err)
		}
		if w.overlay != nil {
			if err := w.overlay.Revoke(ctx, item.WorkloadID); err != nil {
				return w.retry(ctx, item, "OVERLAY_REVOKE_FAILED", err)
			}
		}
		chainCtx, chainCancel := context.WithTimeout(ctx, 30*time.Second)
		defer chainCancel()
		if _, err := w.leases.EnsureLeaseCompleted(chainCtx, leaseID); err != nil {
			return w.retry(ctx, item, "LEASE_COMPLETION_NOT_FINALIZED", err)
		}
		return w.store.MarkStopped(ctx, item, leaseID)
	default:
		return nil
	}
}
func (w *Worker) retry(ctx context.Context, item workloadapi.Workload, code string, cause error) error {
	if err := w.store.RetryLater(ctx, item, code, cause.Error(), 5*time.Second); err != nil {
		return err
	}
	return cause
}
func (w *Worker) providerKey(ctx context.Context, id string) ([32]byte, error) {
	provider, err := w.provider(ctx, id)
	if err != nil {
		return [32]byte{}, err
	}
	if len(provider.PublicKey) != 32 {
		return [32]byte{}, errors.New("provider public key is invalid")
	}
	var key [32]byte
	copy(key[:], provider.PublicKey)
	return key, nil
}
func (w *Worker) provider(ctx context.Context, id string) (agentmanager.SchedulableProvider, error) {
	providers, err := w.directory.ListSchedulableProviders(ctx)
	if err != nil {
		return agentmanager.SchedulableProvider{}, err
	}
	for _, p := range providers {
		if p.ProviderID == id {
			return p, nil
		}
	}
	return agentmanager.SchedulableProvider{}, errors.New("selected provider is no longer active with a fresh heartbeat")
}

// rankableCandidates converts live directory entries into scheduler.Candidate
// (best-effort, live-data-driven ranking input) and a parallel map of
// ProviderCapacity (each provider's declared total, the hard ceiling
// AssignLease's atomic check enforces against -- see its doc comment in
// workloadapi/postgres.go). Reputation is fetched per candidate when
// w.reputation is configured; a read failure or missing record degrades
// that one candidate to the ranker's default score rather than excluding
// it or failing the whole scheduling attempt.
func (w *Worker) rankableCandidates(ctx context.Context, providers []agentmanager.SchedulableProvider) ([]scheduler.Candidate, map[string]workloadapi.ProviderCapacity) {
	candidates := make([]scheduler.Candidate, 0, len(providers))
	capacities := make(map[string]workloadapi.ProviderCapacity, len(providers))
	for _, p := range providers {
		candidate := scheduler.Candidate{ProviderID: p.ProviderID, AgentEndpoint: p.AgentEndpoint}
		if c := p.Capabilities; c != nil {
			candidate.CPUAvailableCores, candidate.CPUTotalCores = c.CpuAvailable, c.CpuTotal
			candidate.RAMAvailableMB, candidate.RAMTotalMB = c.RamAvailableMb, c.RamTotalMb
			candidate.StorageAvailableGB, candidate.StorageTotalGB = c.StorageAvailableGb, c.StorageTotalGb
			capacities[p.ProviderID] = workloadapi.ProviderCapacity{
				TotalCPUMillicores: workloadapi.CPUCoresToMillicores(c.CpuTotal),
				TotalRAMMB:         c.RamTotalMb,
				TotalStorageGB:     c.StorageTotalGb,
			}
		}
		if w.reputation != nil && len(p.PublicKey) == 32 {
			var key [32]byte
			copy(key[:], p.PublicKey)
			if vector, found, err := w.reputation.LatestReputationVector(ctx, key); err == nil {
				candidate.Reputation = scheduler.ReputationVector{
					Compute: vector.Compute, Storage: vector.Storage, Network: vector.Network,
					Availability: vector.Availability, Reliability: vector.Reliability,
				}
				candidate.HasReputation = found
			} else {
				slog.Warn("reputation read failed; ranking with default score", "provider_id", p.ProviderID, "error", err)
			}
		}
		candidates = append(candidates, candidate)
	}
	return candidates, capacities
}
func decodeDefinition(encoded []byte) (*sharedv1.WorkloadDefinition, error) {
	var definition sharedv1.WorkloadDefinition
	if err := proto.Unmarshal(encoded, &definition); err != nil {
		return nil, err
	}
	return &definition, nil
}
func canonicalResourceHash(definition []byte, image string) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("openinfra-resource-v1\x00"))
	hash.Write(definition)
	hash.Write([]byte{0})
	hash.Write([]byte(image))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
