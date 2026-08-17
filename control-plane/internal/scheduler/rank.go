// Package scheduler ranks schedulable providers for a workload
// deterministically: same inputs always produce the same ordering, on any
// machine, so a placement decision can be replayed and audited (issue
// #11). All ranking arithmetic is integer basis points (0..10_000); no
// float ever participates in a score comparison, even though some inputs
// (CPU cores, from ResourceCapability on the wire) arrive as float32 --
// they are converted to integer millicores at the boundary, the same
// conversion workloadapi.CPUCoresToMillicores already uses for capacity
// reservation, before any ranking math touches them.
package scheduler

import (
	"sort"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// ReputationVector mirrors pallet-reputation's on-chain vector exactly:
// u32 scores on a 0..MaxReputationScore scale, never a float. The wire
// protocol's *sharedv1.ReputationVector (float32 fields) is a legacy/
// display format; this is the scheduler's native type, populated from a
// real chain read (see blockchainbridge.ReputationVector).
type ReputationVector struct {
	Compute, Storage, Network, Availability, Reliability uint32
}

// ProfileWeights are fixed-point basis-point weights applied to one
// workload profile's score. ResourceBps and ReputationBps must sum to
// 10_000; ComputeBps..ReliabilityBps (the weights within the reputation
// vector) must also sum to 10_000. Documented per profile below rather
// than tuned at runtime, so a placement decision's weights are always the
// ones committed to source control.
type ProfileWeights struct {
	ResourceBps   uint32
	ReputationBps uint32

	ComputeBps      uint32
	StorageBps      uint32
	NetworkBps      uint32
	AvailabilityBps uint32
	ReliabilityBps  uint32
}

// DefaultProfileWeights: each profile leans on resource fit and its named
// dimension, with Availability always present since a provider that is
// unreachable is worthless regardless of profile. Chosen to be legible
// and easy to argue with, not derived from measurement -- there is no
// placement history yet to tune against.
var DefaultProfileWeights = map[sharedv1.WorkloadProfile]ProfileWeights{
	sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE: {
		ResourceBps: 6000, ReputationBps: 4000,
		ComputeBps: 5000, StorageBps: 500, NetworkBps: 500, AvailabilityBps: 3000, ReliabilityBps: 1000,
	},
	sharedv1.WorkloadProfile_WORKLOAD_PROFILE_MEMORY_INTENSIVE: {
		ResourceBps: 6000, ReputationBps: 4000,
		ComputeBps: 2000, StorageBps: 1000, NetworkBps: 500, AvailabilityBps: 3500, ReliabilityBps: 3000,
	},
	sharedv1.WorkloadProfile_WORKLOAD_PROFILE_STORAGE_INTENSIVE: {
		ResourceBps: 6000, ReputationBps: 4000,
		ComputeBps: 500, StorageBps: 5000, NetworkBps: 500, AvailabilityBps: 3000, ReliabilityBps: 1000,
	},
	sharedv1.WorkloadProfile_WORKLOAD_PROFILE_LATENCY_SENSITIVE: {
		ResourceBps: 5000, ReputationBps: 5000,
		ComputeBps: 1000, StorageBps: 500, NetworkBps: 5000, AvailabilityBps: 2500, ReliabilityBps: 1000,
	},
}

// WireGuardOverheadBytes is the per-packet cost a lease-gated WireGuard
// overlay adds on top of a standard Ethernet MTU: a 20-byte outer IPv4
// header + an 8-byte UDP header + WireGuard's own 32-byte header = 60
// bytes (see docs/adr/015-bandwidth-throughput-measurement.md's
// "Consequences" section and issue #73). IPv6's larger address fields push
// this higher, but nothing on the wire today tells the scheduler whether a
// given workload's traffic will be IPv4 or IPv6, so this uses the IPv4
// figure as a documented, conservative approximation rather than inventing
// a worst case.
//
// DefaultOverlayMTUBytes is the standard Ethernet MTU the overhead is taken
// out of. Together the two model the *fraction* of a link's raw capacity
// that survives encapsulation, (mtu-overhead)/mtu -- never an invented
// absolute "available bandwidth" figure, matching the honest-signal
// philosophy documented on Candidate above.
const (
	WireGuardOverheadBytes = 60
	DefaultOverlayMTUBytes = 1500
)

// DefaultMaxReputationScore and DefaultDefaultReputationScore match
// blockchain/runtime/src/lib.rs's MaxReputation/DefaultReputation
// parameter_types! as of ADR-011. Passed explicitly at NewRanker's call
// site rather than hard-coded inside it, so a future runtime parameter
// change is one grep away from being caught here instead of silently
// making every ranking pass wrong.
const (
	DefaultMaxReputationScore     = 1000
	DefaultDefaultReputationScore = 500
)

// fallbackWeights applies when a profile has no entry above (defensively
// -- callers upstream already reject WORKLOAD_PROFILE_UNSPECIFIED, but a
// future profile value added to the enum without a matching entry here
// must still rank sanely, not divide by an unweighted zero).
var fallbackWeights = ProfileWeights{
	ResourceBps: 5000, ReputationBps: 5000,
	ComputeBps: 2000, StorageBps: 2000, NetworkBps: 2000, AvailabilityBps: 2500, ReliabilityBps: 1500,
}

// Candidate is everything the ranker needs about one schedulable
// provider. Callers (worker.go) build this from agentmanager's live
// heartbeat data plus a chain-sourced reputation read.
type Candidate struct {
	ProviderID    string
	AgentEndpoint string

	CPUAvailableCores, CPUTotalCores   float32
	RAMAvailableMB, RAMTotalMB         int64
	StorageAvailableGB, StorageTotalGB int64
	// IngressTotalMbps/EgressTotalMbps are the provider's declared
	// bandwidth capacity (0 if not operator-configured; see agent-core's
	// AgentSettings). Unlike CPU/RAM/storage there is no live "available"
	// bandwidth signal on the wire (ResourceCapability.Bandwidth carries
	// only a declared ceiling, not a currently-in-use figure), so fit
	// scoring uses the total as its own "available" -- an honest
	// reflection of what the system actually knows, not an invented
	// live-usage number.
	IngressTotalMbps, EgressTotalMbps int64

	// Reputation is ignored (treated as DefaultReputationScore in every
	// dimension, matching pallet-reputation's own default_vector) when
	// HasReputation is false -- a provider with no on-chain record yet is
	// not the same as one with a proven-bad one, so it must not be
	// scored as zero.
	Reputation    ReputationVector
	HasReputation bool
}

// Score is one candidate's fully-computed, auditable result.
type Score struct {
	ProviderID                    string
	TotalBps                      uint32
	ResourceFitBps, ReputationBps uint32
}

// Exclusion explains why a candidate never became a Score. Reason is a
// stable, human-readable string safe to log or return to an operator --
// never a certificate, key, or endpoint.
type Exclusion struct {
	ProviderID string
	Reason     string
}

// Decision is the full, explainable result of one ranking pass: enough to
// reconstruct why a specific provider won, and why every other candidate
// did not (issue #11's "explain placement decisions" criterion).
type Decision struct {
	Selected *Score
	Ranked   []Score // all scored candidates, best first, ties broken by ProviderID
	Excluded []Exclusion
}

// Ranker holds the (small, fixed) configuration ranking needs beyond the
// per-call inputs.
type Ranker struct {
	Weights                map[sharedv1.WorkloadProfile]ProfileWeights
	MaxReputationScore     uint32
	DefaultReputationScore uint32

	// WireGuardOverlayEnabled mirrors orchestrator.Worker's own overlay
	// on/off state (see Worker.SetOverlay's doc comment): today the overlay
	// is an all-or-nothing, deployment-wide setting -- every DEPLOYING
	// workload gets OverlayManager.Attach called when the worker has one
	// configured, there is no per-workload opt-out yet. That is exactly the
	// same condition this field gates, so it is not an approximation of a
	// per-workload signal, it *is* the signal, until one exists.
	WireGuardOverlayEnabled bool
}

// NewRanker returns a Ranker using DefaultProfileWeights and the same
// MaxReputation/DefaultReputation the runtime uses
// (blockchain/runtime/src/lib.rs: MaxReputation=1000, DefaultReputation=500)
// -- kept as constructor parameters rather than hard-coded constants
// because if the runtime's parameter_types! ever change, this must be
// updated to match, and a constructor argument makes that dependency
// visible at every call site instead of silently drifting.
func NewRanker(maxReputationScore, defaultReputationScore uint32) *Ranker {
	return &Ranker{Weights: DefaultProfileWeights, MaxReputationScore: maxReputationScore, DefaultReputationScore: defaultReputationScore}
}

// SetWireGuardOverlayEnabled turns on WireGuard overhead accounting in
// bandwidth fit-scoring (see scoreOne). It is a setter, not a constructor
// argument, for the same reason Worker.SetOverlay is one: it keeps every
// ranker constructed today (tests, and any deployment without
// WIREGUARD_INTERFACE set) behaving exactly as before -- callers must
// opt in explicitly once the overlay is actually configured.
func (r *Ranker) SetWireGuardOverlayEnabled(enabled bool) { r.WireGuardOverlayEnabled = enabled }

// Rank scores every candidate against requirements/constraints for
// profile, excluding anything stale, incompatible, or insufficient
// (staleness/liveness is expected to already be filtered by the caller's
// provider directory -- ListSchedulableProviders -- but a missing
// endpoint or nil-equivalent capability is re-checked defensively here
// since this package must not trust its caller blindly).
func (r *Ranker) Rank(
	profile sharedv1.WorkloadProfile,
	requirements *sharedv1.ResourceRequirements,
	constraints *sharedv1.WorkloadConstraints,
	candidates []Candidate,
) Decision {
	weights, ok := r.Weights[profile]
	if !ok {
		weights = fallbackWeights
	}

	var decision Decision
	for _, candidate := range candidates {
		score, excluded, reason := r.scoreOne(weights, requirements, constraints, candidate)
		if excluded {
			decision.Excluded = append(decision.Excluded, Exclusion{ProviderID: candidate.ProviderID, Reason: reason})
			continue
		}
		decision.Ranked = append(decision.Ranked, score)
	}

	sort.Slice(decision.Ranked, func(i, j int) bool {
		if decision.Ranked[i].TotalBps != decision.Ranked[j].TotalBps {
			return decision.Ranked[i].TotalBps > decision.Ranked[j].TotalBps
		}
		// Deterministic tie-break: lexicographic ProviderID. Not a
		// meaningful preference by itself, but it must be *some* total
		// order so two runs over the same input never disagree.
		return decision.Ranked[i].ProviderID < decision.Ranked[j].ProviderID
	})
	if len(decision.Ranked) > 0 {
		selected := decision.Ranked[0]
		decision.Selected = &selected
	}
	return decision
}

func (r *Ranker) scoreOne(
	weights ProfileWeights,
	requirements *sharedv1.ResourceRequirements,
	constraints *sharedv1.WorkloadConstraints,
	candidate Candidate,
) (score Score, excluded bool, reason string) {
	if candidate.AgentEndpoint == "" {
		return Score{}, true, "no advertised agent endpoint"
	}
	if requirements == nil {
		return Score{}, true, "workload has no resource requirements"
	}

	cpuFitBps, ok := fitBps(cpuMillicores(candidate.CPUAvailableCores), cpuMillicores(requirements.Cpu))
	if !ok {
		return Score{}, true, "insufficient CPU"
	}
	ramFitBps, ok := fitBps(candidate.RAMAvailableMB, requirements.RamMb)
	if !ok {
		return Score{}, true, "insufficient RAM"
	}
	storageFitBps, ok := fitBps(candidate.StorageAvailableGB, requirements.StorageGb)
	if !ok {
		return Score{}, true, "insufficient storage"
	}
	// Bandwidth only enters the average when the workload actually
	// requested it: requirements.Bandwidth is a new, optional field that
	// no existing caller populates yet, so unconditionally folding a
	// trivial "always satisfied" 10_000 term into every score (diluting
	// the divisor from 3 to 4 for workloads that never asked for
	// bandwidth) would silently change every other profile's scoring.
	resourceFitCount := uint32(3)
	var bandwidthFitBps uint32
	if bandwidth := requirements.Bandwidth; bandwidth != nil && (bandwidth.IngressMbps > 0 || bandwidth.EgressMbps > 0) {
		// The declared interface total is the raw, unencapsulated figure
		// (see Candidate's doc comment). When this workload's traffic will
		// actually transit the WireGuard overlay, only the post-overhead
		// fraction of that total is usable, so fit-scoring must compare the
		// requirement against the *effective* figure, not the raw one --
		// otherwise a provider whose raw capacity just barely covers the
		// requirement would be scored as fitting when the workload will, in
		// practice, never see that much throughput.
		ingressAvailable, egressAvailable := candidate.IngressTotalMbps, candidate.EgressTotalMbps
		if r.WireGuardOverlayEnabled {
			ingressAvailable = wireGuardEffectiveMbps(ingressAvailable)
			egressAvailable = wireGuardEffectiveMbps(egressAvailable)
		}
		ingressFitBps, ok := fitBps(ingressAvailable, int64(bandwidth.IngressMbps))
		if !ok {
			return Score{}, true, "insufficient ingress bandwidth"
		}
		egressFitBps, ok := fitBps(egressAvailable, int64(bandwidth.EgressMbps))
		if !ok {
			return Score{}, true, "insufficient egress bandwidth"
		}
		bandwidthFitBps = (ingressFitBps + egressFitBps) / 2
		resourceFitCount++
	}
	resourceFitBps := (cpuFitBps + ramFitBps + storageFitBps + bandwidthFitBps) / resourceFitCount

	reputation := candidate.Reputation
	if !candidate.HasReputation {
		reputation = ReputationVector{
			Compute: r.DefaultReputationScore, Storage: r.DefaultReputationScore, Network: r.DefaultReputationScore,
			Availability: r.DefaultReputationScore, Reliability: r.DefaultReputationScore,
		}
	}
	reputationBps := weightedReputationBps(weights, reputation, r.MaxReputationScore)

	if constraints != nil && constraints.MinReputation > 0 {
		// Documented convention: min_reputation is on the same
		// 0..MaxReputationScore scale as the on-chain vector (matching
		// DefaultReputation/MaxReputation in blockchain/runtime), not
		// 0..1 -- there is no other established convention for this
		// field anywhere else in the codebase to defer to.
		if globalBps(reputation, r.MaxReputationScore) < uint32(constraints.MinReputation)*10_000/r.MaxReputationScore {
			return Score{}, true, "below workload's minimum reputation constraint"
		}
	}
	// constraints.MaxLatencyMs and constraints.MaxPrice are accepted but
	// not enforced: this system has no latency measurement or pricing
	// signal anywhere yet (no caller populates either), and inventing a
	// number to compare against would be worse than the honest gap. They
	// are wired through the constructor and this comment specifically so
	// the next person adding either signal has one place to look.

	totalBps := (resourceFitBps*weights.ResourceBps + reputationBps*weights.ReputationBps) / 10_000
	return Score{
		ProviderID:     candidate.ProviderID,
		TotalBps:       totalBps,
		ResourceFitBps: resourceFitBps,
		ReputationBps:  reputationBps,
	}, false, ""
}

// weightedReputationBps folds the vector's five dimensions into one
// basis-point score (0..10_000) for this profile's weights, then
// globalBps folds them unweighted (equal parts) for the min_reputation
// constraint check -- deliberately not the same formula, since a
// constraint is a floor on general standing, not on fitness for this one
// profile.
func weightedReputationBps(weights ProfileWeights, vector ReputationVector, maxScore uint32) uint32 {
	if maxScore == 0 {
		return 0
	}
	// weights.* sum to 10_000 and each vector.* is in [0, maxScore], so
	// sum's maximum is 10_000*maxScore; dividing by maxScore scales the
	// result back to a plain 0..10_000 basis-point score.
	sum := uint64(weights.ComputeBps)*uint64(vector.Compute) +
		uint64(weights.StorageBps)*uint64(vector.Storage) +
		uint64(weights.NetworkBps)*uint64(vector.Network) +
		uint64(weights.AvailabilityBps)*uint64(vector.Availability) +
		uint64(weights.ReliabilityBps)*uint64(vector.Reliability)
	return uint32(sum / uint64(maxScore))
}

func globalBps(vector ReputationVector, maxScore uint32) uint32 {
	if maxScore == 0 {
		return 0
	}
	average := (uint64(vector.Compute) + uint64(vector.Storage) + uint64(vector.Network) + uint64(vector.Availability) + uint64(vector.Reliability)) / 5
	return uint32(average * 10_000 / uint64(maxScore))
}

// fitBps returns how well available covers required, clamped to
// 10_000 (i.e. covering the requirement fully or more scores the same as
// covering it exactly -- extra headroom beyond what was asked for is not
// rewarded). ok is false when required > 0 and available cannot cover it;
// a zero requirement is always satisfied and scores full marks.
func fitBps(available, required int64) (bps uint32, ok bool) {
	if required <= 0 {
		return 10_000, true
	}
	if available < required {
		return 0, false
	}
	ratio := available * 10_000 / required
	if ratio > 10_000 {
		ratio = 10_000
	}
	return uint32(ratio), true
}

// wireGuardEffectiveMbps scales a declared raw-interface bandwidth figure
// down by WireGuard's fixed per-packet overhead, expressed as the fraction
// of a standard MTU that survives encapsulation:
// effective = total * (mtu - overhead) / mtu. Integer division mirrors the
// rest of this file's basis-point arithmetic -- no float, and the same
// input always produces the same output on any machine. A non-positive
// input (0, or a value that should never occur in practice) is returned
// unchanged rather than risking a negative or divide-by-zero result.
func wireGuardEffectiveMbps(totalMbps int64) int64 {
	if totalMbps <= 0 {
		return totalMbps
	}
	return totalMbps * (DefaultOverlayMTUBytes - WireGuardOverheadBytes) / DefaultOverlayMTUBytes
}

// cpuMillicores converts a float32 core count (as received on the wire in
// ResourceCapability/ResourceRequirements) to integer millicores, the
// same conversion workloadapi.CPUCoresToMillicores performs for capacity
// reservation, so a CPU comparison never depends on float precision.
func cpuMillicores(cores float32) int64 {
	if cores < 0 {
		return 0
	}
	return int64(cores*1000 + 0.5)
}
