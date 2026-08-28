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
	"github.com/openinfra/network/internal/openstackapi/cinder"
	"github.com/openinfra/network/internal/openstackapi/neutron"
	"github.com/openinfra/network/internal/scheduler"
	"github.com/openinfra/network/internal/workloadapi"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	// MarkFailed is retry's terminal counterpart, used once RetryPolicy's
	// MaxAttempts is reached: see PostgresRepository.MarkFailed's doc
	// comment (issue #138).
	MarkFailed(context.Context, workloadapi.Workload, string, string) error
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

// VolumeAttachments is the subset of internal/openstackapi/cinder's
// Repository this package needs: which Cinder volumes are currently
// attached to a given workload, read at DEPLOYING dispatch time so
// DeployRequest.volumes (agent.proto's VolumeAttachment, ADR-034 §7) is
// actually populated -- see that field's own doc comment, which
// describes exactly this call site. Before this fix (issue #26 security
// review), no code called it at all: attach reported 200 OK and the
// volume's row flipped to 'in-use', but nothing was ever mounted into
// any container on any real deploy, making agent-executor's fully
// implemented, unit-tested mount logic dead code in production.
//
// Optional, set via SetVolumeAttachments: a nil value (the zero
// *Worker's default, and every existing test/deployment that predates
// this field) degrades DEPLOYING dispatch to "no volumes" exactly as
// before this fix -- never a hard failure, since a workload with no
// attached volumes must still deploy normally.
type VolumeAttachments interface {
	ListAttachedForWorkload(ctx context.Context, workloadID string) ([]cinder.Volume, error)
}

// OverlayManager is invoked only after the chain lease has been finalized and
// the Agent has confirmed the workload container. Implementations must make
// Attach/Revoke idempotent and must not persist private key material.
type OverlayManager interface {
	Attach(context.Context, string, string, string, time.Time) error
	Revoke(context.Context, string) error
}

// OverlayAttacherWithAllowedIPs is an optional capability of OverlayManager
// -- *wireguard.Manager implements it, but the interface is checked via a
// type assertion (the same optional-capability pattern
// DeploymentReconciler above already uses for w.dispatcher) rather than
// added to OverlayManager itself, so an OverlayManager test fake
// implementing only Attach/Revoke is unaffected. ADR-035 §1: when a
// workload is bound to a Neutron port, its IPAM-reserved fixed_ip
// replaces wireguard.Manager.Attach's own overlayAddress(0)
// placeholder-derived AllowedIPs -- see AttachWithAllowedIPs's own doc
// comment for the full reasoning.
type OverlayAttacherWithAllowedIPs interface {
	AttachWithAllowedIPs(ctx context.Context, workloadID, leaseID, containerID string, expiresAt time.Time, allowedIPs []string) error
}

// SecurityGroupResolver is internal/openstackapi/neutron's
// PortSecurityResolver read surface (ADR-035 §3, issue #170) --
// resolved at DEPLOYING dispatch time from whichever Neutron port (if
// any) is currently bound to the workload being deployed, matching
// VolumeAttachments' identical "resolve current attachment state at
// dispatch time" shape immediately above.
//
// Optional, set via SetSecurityGroupResolver: a nil value (the zero
// *Worker's default, and every existing test/deployment that predates
// ADR-035) degrades DEPLOYING dispatch to "no security context, no
// AllowedIPs override" exactly as before this fix -- never a hard
// failure, matching VolumeAttachments' own degraded-mode precedent.
type SecurityGroupResolver interface {
	ResolveForWorkload(ctx context.Context, workloadID string) (rules []neutron.SecurityGroupRule, fixedIP string, hasPort bool, err error)
}

type Worker struct {
	store               PersistentStore
	directory           ProviderDirectory
	leases              LeaseRegistrar
	dispatcher          AgentDispatcher
	overlay             OverlayManager
	ranker              *scheduler.Ranker
	reputation          ReputationSource
	volumes             VolumeAttachments
	securityGroups      SecurityGroupResolver
	interval, blockTime time.Duration
	workerID            string
	claimDuration       time.Duration
	retryPolicy         RetryPolicy
}

// RetryPolicy bounds how many times retry() re-queues a workload in its
// current non-terminal state before giving up and marking it FAILED
// instead, and how the delay between attempts grows. Mirrors
// providerjoin.ReconcilerConfig's MaxAttempts/BaseBackoff/MaxBackoff shape
// deliberately -- same idiom already established there for exactly this
// "bounded retry with capped exponential backoff, then an explicit
// terminal state" problem (issue #138).
//
// AttemptCount (and so the cap) is cumulative across a workload's whole
// lifecycle, not reset per lifecycle state: workloadapi's schema has
// always tracked it that way (no Mark* transition resets it), and
// dashboard's operator alerting already reads it as a lifetime count (see
// dashboard.operatorRetryExhaustionThreshold). Preserving that meaning
// here, rather than introducing a second, differently-scoped counter,
// keeps attempt_count meaning one thing everywhere it's read.
type RetryPolicy struct {
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

// DefaultRetryPolicy matches providerjoin.DefaultReconcilerConfig's retry
// shape exactly (same base/cap/attempt budget), so the two subsystems that
// already use this idiom agree on what "give up" means in practice: up to
// ~30 minutes of doubling backoff (5s, 10s, ..., capped at 10m) across 10
// attempts before a workload is declared FAILED.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 10, BaseBackoff: 5 * time.Second, MaxBackoff: 10 * time.Minute}
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	defaults := DefaultRetryPolicy()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaults.MaxAttempts
	}
	if p.BaseBackoff <= 0 {
		p.BaseBackoff = defaults.BaseBackoff
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = defaults.MaxBackoff
	}
	return p
}

// NewWorker's ranker is required, not a setter-configured optional like
// overlay/reputation: there is no reasonable degraded mode for "how do we
// rank providers at all" the way there is for "we have no live reputation
// signal" or "no WireGuard overlay in this environment".
func NewWorker(store PersistentStore, directory ProviderDirectory, leases LeaseRegistrar, dispatcher AgentDispatcher, ranker *scheduler.Ranker) *Worker {
	return &Worker{store: store, directory: directory, leases: leases, dispatcher: dispatcher, ranker: ranker, interval: time.Second, blockTime: 3 * time.Second, workerID: uuid.NewString(), claimDuration: 2 * time.Minute, retryPolicy: DefaultRetryPolicy()}
}

// SetRetryPolicy overrides the default RetryPolicy. A setter, like
// SetOverlay/SetReputationSource, so production wiring and tests can tune
// it (e.g. a small MaxAttempts to exercise exhaustion without a real
// backoff wait) without widening NewWorker's already-five-argument
// signature.
func (w *Worker) SetRetryPolicy(policy RetryPolicy) { w.retryPolicy = policy.withDefaults() }

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

// SetVolumeAttachments enables populating DeployRequest.volumes at
// DEPLOYING dispatch time from cinder_volumes rows currently attached to
// the workload being deployed. See VolumeAttachments' own doc comment
// for the degraded-mode behavior when left unset.
func (w *Worker) SetVolumeAttachments(volumes VolumeAttachments) { w.volumes = volumes }

// SetSecurityGroupResolver enables populating DeployRequest.security_context
// (and, when the resolved port carries a fixed_ip, overriding the
// WireGuard overlay's AllowedIPs) at DEPLOYING dispatch time. See
// SecurityGroupResolver's own doc comment for the degraded-mode behavior
// when left unset.
func (w *Worker) SetSecurityGroupResolver(resolver SecurityGroupResolver) {
	w.securityGroups = resolver
}
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
		// ADR-028 §3: the wall-clock lease term the Agent must locally
		// enforce if it becomes disconnected from the Control Plane.
		// Computed once, here, from the exact duration_seconds this
		// workload's on-chain lease was created with (the same value
		// LEASE_PENDING above already converted to a block count) --
		// reused verbatim for the WireGuard overlay's own expiry below,
		// so the two "when does this workload's authorization end"
		// values can never independently drift.
		definitionExpiry := time.Now().UTC().Add(time.Duration(definition.DurationSeconds) * time.Second)
		request := &agentv1.DeployRequest{WorkloadId: item.WorkloadID, LeaseId: item.LeaseID, Image: item.Image, Limits: &agentv1.ResourceLimits{CpuCores: definition.Requirements.Cpu, MemoryMb: definition.Requirements.RamMb, EgressMbps: workloadEgressMbps(definition)}, LeaseEnd: timestamppb.New(definitionExpiry)}
		// ADR-033 §9 / issues #166/#168: a VM-flavored workload carries its
		// qcow2 reference via a sibling VmSpec message, not `Image` (which
		// the Agent's Docker path would otherwise misinterpret as an OCI
		// reference) -- validateSubmission (workloadapi/service.go) already
		// enforced Image is an https:// URL and VmImageSha256 is a valid
		// digest for exactly this case, and the scheduler already refused
		// to rank a provider lacking virtualization_capable (rank.go's
		// ReasonVmIncapable) before this state was ever reached.
		if definition.GetConstraints().GetRequiresVm() {
			request.Runtime = agentv1.Runtime_RUNTIME_VM
			request.Image = ""
			request.Vm = &agentv1.VmSpec{VmImageUrl: item.Image, VmImageSha256: item.VmImageSha256}
		}
		// ADR-034 §7 / issue #26 security review: populate
		// DeployRequest.volumes from whatever Cinder volumes are
		// currently attached to this workload. Meaningful only for a
		// RUNTIME_CONTAINER workload (agent-executor's vm::VmExecutor
		// ignores this field entirely, matching Runtime/VmSpec's own
		// "ignored for a VM-flavored request" precedent above) but
		// populated unconditionally here anyway -- simpler than
		// branching on runtime, and harmless for a VM request since
		// the Agent-side VM path never reads it.
		if w.volumes != nil {
			attached, err := w.volumes.ListAttachedForWorkload(ctx, item.WorkloadID)
			if err != nil {
				return w.retry(ctx, item, "VOLUME_LOOKUP_FAILED", err)
			}
			for _, volume := range attached {
				request.Volumes = append(request.Volumes, &agentv1.VolumeAttachment{
					VolumeId:  volume.VolumeID,
					MountPath: derefOrEmpty(volume.MountPath),
					ReadOnly:  volume.ReadOnly,
				})
			}
		}
		// ADR-035 §3 / issue #170: populate DeployRequest.security_context
		// from whatever Neutron port (if any) is currently bound to this
		// workload_id -- and, if that port carries an IPAM-reserved
		// fixed_ip (ADR-035 §1), remember it so the WireGuard attach call
		// below can override AllowedIPs. boundFixedIP stays empty for
		// every workload with no bound port, which keeps the overlay
		// attach call below on its exact existing path.
		var boundFixedIP string
		if w.securityGroups != nil {
			rules, fixedIP, hasPort, err := w.securityGroups.ResolveForWorkload(ctx, item.WorkloadID)
			if err != nil {
				return w.retry(ctx, item, "SECURITY_GROUP_LOOKUP_FAILED", err)
			}
			if hasPort {
				request.SecurityContext = &agentv1.PortSecurityContext{Rules: securityGroupRuleProtos(rules)}
				boundFixedIP = fixedIP
			}
		}
		deployCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
		containerID, err := w.dispatcher.DeployAndConfirm(deployCtx, provider.RegisteredProvider, request)
		if err != nil {
			return w.retry(ctx, item, "AGENT_DEPLOY_FAILED", err)
		}
		if w.overlay != nil {
			// ADR-035 §1: a bound port's fixed_ip takes the place of
			// Attach's own overlayAddress(0) placeholder -- always a
			// single /32, matching ADR-010's unchanged one-address-per-
			// peer model exactly (ADR-035 §3: "AllowedIPs continues to be
			// programmed to exactly the port's single fixed_ip... the
			// ceiling is structurally outside and above anything a
			// security-group rule can express"). Exactly one of Attach/
			// AttachWithAllowedIPs is called -- never both: Allocate is a
			// no-op for a workload_id that already has a peer (see its
			// own doc comment), so calling the plain, placeholder-using
			// Attach first would permanently shadow a fixed_ip override
			// attempted afterward.
			var attachErr error
			if attacher, ok := w.overlay.(OverlayAttacherWithAllowedIPs); ok && boundFixedIP != "" {
				attachErr = attacher.AttachWithAllowedIPs(ctx, item.WorkloadID, item.LeaseID, containerID, definitionExpiry, []string{boundFixedIP + "/32"})
			} else {
				attachErr = w.overlay.Attach(ctx, item.WorkloadID, item.LeaseID, containerID, definitionExpiry)
			}
			if attachErr != nil {
				// Do not expose a running workload with a partially attached
				// network. Stop is best effort; the worker retries this state.
				_ = w.dispatcher.StopAndConfirm(ctx, provider.RegisteredProvider, item.WorkloadID)
				return w.retry(ctx, item, "OVERLAY_ATTACH_FAILED", attachErr)
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

// retry re-queues item for another attempt, unless doing so would exceed
// w.retryPolicy.MaxAttempts -- in which case it gives up and marks the
// workload FAILED instead of re-queuing it forever against what may be a
// permanently dead provider (issue #138). item.AttemptCount is the count
// *before* this attempt, so attempt below is the number this call itself
// represents; the cap check and the backoff calculation both use it
// consistently with RetryLater/MarkFailed, which each independently
// increment the persisted attempt_count by exactly one.
func (w *Worker) retry(ctx context.Context, item workloadapi.Workload, code string, cause error) error {
	attempt := item.AttemptCount + 1
	if attempt >= w.retryPolicy.MaxAttempts {
		terminal := fmt.Errorf("giving up after %d attempts (%s): %w", attempt, code, cause)
		if err := w.store.MarkFailed(ctx, item, code, terminal.Error()); err != nil {
			return err
		}
		return terminal
	}
	if err := w.store.RetryLater(ctx, item, code, cause.Error(), w.backoffFor(attempt)); err != nil {
		return err
	}
	return cause
}

// backoffFor returns w.retryPolicy.BaseBackoff doubled per additional
// attempt, capped at MaxBackoff. attempt is always >= 1. Same
// doubling-with-cap shape as providerjoin.Reconciler.backoffFor, kept as
// a separate copy rather than a shared helper: the two live in different
// packages with no natural common import, and the logic is five lines of
// plain arithmetic, not worth a cross-package dependency to deduplicate.
func (w *Worker) backoffFor(attempt int) time.Duration {
	const maxShift = 16 // 2^16 * BaseBackoff already exceeds any sane MaxBackoff
	shift := attempt - 1
	if shift > maxShift {
		shift = maxShift
	}
	backoff := w.retryPolicy.BaseBackoff
	for i := 0; i < shift; i++ {
		backoff *= 2
		if backoff <= 0 || backoff > w.retryPolicy.MaxBackoff {
			return w.retryPolicy.MaxBackoff
		}
	}
	if backoff > w.retryPolicy.MaxBackoff {
		return w.retryPolicy.MaxBackoff
	}
	return backoff
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
			// ADR-033 §7 / issue #166: flows straight through from the
			// Agent's own fail-closed KVM probe (agent-inventory's
			// kvm.rs) -- no separate persistence layer needed, since
			// ResourceCapability is already carried whole through the
			// Redis-cached heartbeat payload (see agentmanager.Directory)
			// exactly like every other capability field here.
			candidate.VirtualizationCapable = c.VirtualizationCapable
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

// securityGroupRuleProtos converts neutron.SecurityGroupRule (Go-side,
// *int32 for an unset port range) into agent.proto's SecurityGroupRule
// (wire-side, -1 for an unset port range) -- agent.proto's own doc
// comment on SecurityGroupRule.port_range_min/max is the documented
// contract this mirrors. An empty/nil rules produces an empty (never
// nil-in-meaning) slice, matching PortSecurityContext.rules' own
// "presence of the wrapper message, not this field, is the fail-closed
// signal" convention (DeployRequest.security_context's doc comment).
func securityGroupRuleProtos(rules []neutron.SecurityGroupRule) []*agentv1.SecurityGroupRule {
	protos := make([]*agentv1.SecurityGroupRule, 0, len(rules))
	for _, rule := range rules {
		protos = append(protos, &agentv1.SecurityGroupRule{
			Direction:      rule.Direction,
			Protocol:       rule.Protocol,
			PortRangeMin:   int32PtrOrSentinel(rule.PortRangeMin),
			PortRangeMax:   int32PtrOrSentinel(rule.PortRangeMax),
			RemoteIpPrefix: rule.RemoteIPPrefix,
		})
	}
	return protos
}

func int32PtrOrSentinel(value *int32) int32 {
	if value == nil {
		return -1
	}
	return *value
}

// derefOrEmpty reads a possibly-nil string pointer -- cinder.Volume.
// MountPath is nil whenever a volume is not attached, but
// VolumeAttachments.ListAttachedForWorkload only ever returns rows that
// are 'in-use' (see its own doc comment), which the cinder_volumes
// migration's own CHECK constraint guarantees always have a non-nil
// mount_path -- this is defensive, not a real expected-nil case.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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
