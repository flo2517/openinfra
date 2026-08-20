package orchestrator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
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
//
// This also flips w.ranker.WireGuardOverlayEnabled, rather than leaving that
// as a second call callers must remember to make alongside this one. Before
// this, "is the overlay active" was two independently-set booleans
// (w.overlay != nil here, Ranker.WireGuardOverlayEnabled there) kept in
// agreement only by main.go happening to call both setters in the same
// if-block -- a future second call site that configured the overlay without
// discovering and calling both would silently desync single-candidate
// fit-scoring from the aggregate capacity ledger (see rankableCandidates'
// own doc comment), reintroducing the exact overcommit issue #115 fixed.
// Worker already holds the same *scheduler.Ranker passed into it via
// NewWorker, so there is no reason for the two to disagree.
func (w *Worker) SetOverlay(overlay OverlayManager) {
	w.overlay = overlay
	w.ranker.SetWireGuardOverlayEnabled(overlay != nil)
}

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
			return w.retry(ctx, item, "NO_CAPACITY", noEligibleProviderError(decision.Excluded, candidates, definition.Constraints.GetRequiredZone()))
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
		request := &agentv1.DeployRequest{WorkloadId: item.WorkloadID, LeaseId: item.LeaseID, Image: item.Image, Limits: &agentv1.ResourceLimits{CpuCores: definition.Requirements.Cpu, MemoryMb: definition.Requirements.RamMb, EgressMbps: workloadEgressMbps(definition)}}
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
//
// candidate.IngressTotalMbps/EgressTotalMbps stay raw: scoreOne itself
// applies scheduler.WireGuardEffectiveMbps when ranker.WireGuardOverlayEnabled
// is set, so adjusting them here too would double-discount a single
// candidate's fit score. capacities' TotalIngressMbps/TotalEgressMbps are
// different -- they seed the *persistent* ledger AssignLease checks
// cumulative reservations against across every workload already assigned
// to a provider, and until this fix they were never adjusted at all. w.overlay
// != nil is the same "is the overlay active for this deployment" signal
// main.go already flips ranker.WireGuardOverlayEnabled from (see
// Worker.SetOverlay's doc comment), so reusing it here keeps both halves of
// WireGuard-overhead accounting -- single-candidate fit-scoring and the
// aggregate capacity ledger -- in agreement (issue #115).
func (w *Worker) rankableCandidates(ctx context.Context, providers []agentmanager.SchedulableProvider) ([]scheduler.Candidate, map[string]workloadapi.ProviderCapacity) {
	candidates := make([]scheduler.Candidate, 0, len(providers))
	capacities := make(map[string]workloadapi.ProviderCapacity, len(providers))
	for _, p := range providers {
		candidate := scheduler.Candidate{ProviderID: p.ProviderID, AgentEndpoint: p.AgentEndpoint}
		if c := p.Capabilities; c != nil {
			candidate.CPUAvailableCores, candidate.CPUTotalCores = c.CpuAvailable, c.CpuTotal
			candidate.RAMAvailableMB, candidate.RAMTotalMB = c.RamAvailableMb, c.RamTotalMb
			candidate.StorageAvailableGB, candidate.StorageTotalGB = c.StorageAvailableGb, c.StorageTotalGb
			candidate.Zone = c.Zone
			var ingressMbps, egressMbps int64
			if c.Bandwidth != nil {
				ingressMbps, egressMbps = int64(c.Bandwidth.IngressMbps), int64(c.Bandwidth.EgressMbps)
			}
			candidate.IngressTotalMbps, candidate.EgressTotalMbps = ingressMbps, egressMbps
			capacityIngressMbps, capacityEgressMbps := ingressMbps, egressMbps
			if w.overlay != nil {
				capacityIngressMbps = scheduler.WireGuardEffectiveMbps(ingressMbps)
				capacityEgressMbps = scheduler.WireGuardEffectiveMbps(egressMbps)
			}
			capacities[p.ProviderID] = workloadapi.ProviderCapacity{
				TotalCPUMillicores: workloadapi.CPUCoresToMillicores(c.CpuTotal),
				TotalRAMMB:         c.RamTotalMb,
				TotalStorageGB:     c.StorageTotalGb,
				TotalIngressMbps:   capacityIngressMbps,
				TotalEgressMbps:    capacityEgressMbps,
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

// maxDistinctExclusionReasons bounds how many distinct exclusion reasons
// noEligibleProviderError lists, so a NO_CAPACITY error over a large
// candidate pool stays readable instead of growing one line per reason
// ever observed.
const maxDistinctExclusionReasons = 5

// noEligibleProviderError builds the NO_CAPACITY error surfaced when
// scheduler.Rank selects no candidate. Before ADR-026 this only reported
// the *count* of excluded candidates, discarding
// scheduler.Decision.Excluded[i].Reason entirely -- a general gap, not
// specific to zone, that predates this ADR (see its §3/"Consequences").
// This surfaces the distinct reasons actually seen instead (deduplicated,
// bounded by maxDistinctExclusionReasons, in first-seen order so the
// message is deterministic for a given ranking pass), and, specifically,
// when every exclusion is a zone mismatch, the set of zones actually
// declared among the excluded candidates -- e.g. `requested zone "us-eas"
// matched none; zones present: us-east, us-west, eu-central` -- which
// directly answers "why did my zone request fail" without a
// Control-Plane-owned zone allowlist (ADR-026 §3).
func noEligibleProviderError(excluded []scheduler.Exclusion, candidates []scheduler.Candidate, requiredZone string) error {
	if len(excluded) == 0 {
		return fmt.Errorf("no eligible provider (0 candidates excluded)")
	}

	rawReasons := make([]string, 0, len(excluded))
	allZoneMismatch := true
	for _, e := range excluded {
		if e.Reason != scheduler.ReasonZoneMismatch {
			allZoneMismatch = false
		}
		rawReasons = append(rawReasons, e.Reason)
	}
	reasons, truncatedReasons := dedupeOrderedBounded(rawReasons, maxDistinctExclusionReasons)

	if allZoneMismatch && requiredZone != "" {
		zonesByProvider := make(map[string]string, len(candidates))
		for _, c := range candidates {
			zonesByProvider[c.ProviderID] = c.Zone
		}
		rawZones := make([]string, 0, len(excluded))
		for _, e := range excluded {
			if zone := zonesByProvider[e.ProviderID]; zone != "" {
				rawZones = append(rawZones, zone)
			}
		}
		// Deduplicated and sorted *before* bounding, deliberately in that
		// order: bounding first-seen order (as reasons does just above)
		// would let an arbitrary subset of zones survive truncation --
		// found in review as a real bug, since the whole point of this
		// message is letting a tenant spot their own typo by checking
		// whether the zone they expect appears in the list, and
		// provider-iteration order has no relationship to which zone
		// that is. Sorting first, then truncating, guarantees the
		// truncated list is always the alphabetically-first N distinct
		// zones -- deterministic and complete for any zone whose name
		// sorts within the bound, not an arbitrary sample.
		allZones := dedupeOrdered(rawZones)
		sort.Strings(allZones)
		zones, truncatedZones := allZones, 0
		if len(allZones) > maxDistinctExclusionReasons {
			zones, truncatedZones = allZones[:maxDistinctExclusionReasons], len(allZones)-maxDistinctExclusionReasons
		}
		if len(zones) == 0 {
			return fmt.Errorf("no eligible provider: %d candidates excluded — requested zone %q matched none; no excluded candidate declared a zone",
				len(excluded), requiredZone)
		}
		return fmt.Errorf("no eligible provider: %d candidates excluded — requested zone %q matched none; zones present: %s",
			len(excluded), requiredZone, joinWithOverflow(zones, truncatedZones))
	}

	return fmt.Errorf("no eligible provider: %d candidates excluded — reasons: %s",
		len(excluded), joinWithOverflow(reasons, truncatedReasons))
}

// joinWithOverflow renders a bounded, deduplicated list for an error
// message, appending ", and N more" when the caller's dedupeOrderedBounded
// call truncated it. Shared by noEligibleProviderError's two list-shaped
// branches (reasons, zones present) so the "and N more" phrasing can only
// ever say one thing, not drift between near-identical hand-written
// fmt.Errorf branches -- found in review as exactly that risk (up to 5
// near-duplicate format strings differing only in this suffix).
func joinWithOverflow(items []string, truncatedBy int) string {
	joined := strings.Join(items, ", ")
	if truncatedBy > 0 {
		return fmt.Sprintf("%s, and %d more", joined, truncatedBy)
	}
	return joined
}

// dedupeOrderedBounded deduplicates items in first-seen order, then caps
// the result at max distinct values, returning how many *additional*
// distinct values existed beyond the cap (0 if none -- a caller building
// an "and N more" suffix needs that count, not just the truncated slice's
// length). Shared by noEligibleProviderError's two dedup passes (exclusion
// reasons, and -- separately -- zones present among zone-mismatch
// exclusions) so both get identical bounding/ordering behavior from one
// place instead of two hand-rolled seen-map loops that could silently
// drift apart (e.g. a future change to how "seen" is normalized, applied
// to only one of the two).
func dedupeOrderedBounded(items []string, max int) (values []string, truncatedBy int) {
	values = dedupeOrdered(items)
	if len(values) <= max {
		return values, 0
	}
	return values[:max], len(values) - max
}

// dedupeOrdered deduplicates items in first-seen order, unbounded. The
// building block dedupeOrderedBounded truncates after; callers that need
// a different order applied before truncation (e.g. sorted, not
// first-seen -- see the zones-present list in noEligibleProviderError)
// call this directly instead, so the property they actually want
// truncated by is decided before any values are thrown away, not after.
func dedupeOrdered(items []string) []string {
	seen := make(map[string]bool, len(items))
	var values []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			values = append(values, item)
		}
	}
	return values
}

// workloadEgressMbps is the workload's *reserved* egress rate (ADR-025
// §3), carried into DeployRequest.Limits alongside cpu_cores/memory_mb so
// agent-executor can apply a host-side `tc` ceiling at container start.
// definition.Requirements.Bandwidth is optional (nil means the workload
// declared no bandwidth requirement, per ResourceRequirements' own doc
// comment) -- that degrades to 0, agent-executor's own "no reservation,
// no `tc` rule" convention, not a zero-cap that would stall the workload.
func workloadEgressMbps(definition *sharedv1.WorkloadDefinition) int32 {
	if definition.Requirements == nil || definition.Requirements.Bandwidth == nil {
		return 0
	}
	return definition.Requirements.Bandwidth.EgressMbps
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
