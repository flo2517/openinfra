package providerjoin

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
)

// maxWorkloadBandwidthEntriesPerHeartbeat is the Control Plane's own
// ceiling on workload_bandwidth (ADR-025 §2: "Bounded by the Agent's own
// max_workloads setting; the Control Plane enforces its own ceiling
// regardless"). agent-core's own default max_workloads is 8; this is set
// generously above any plausible single-Agent deployment rather than
// mirrored exactly, so a legitimate Agent with a higher configured
// ceiling is never rejected by a Control Plane that doesn't know its
// local config -- only a payload that is wildly out of proportion (a bug
// or an abuse attempt, not a real fleet) is refused.
const maxWorkloadBandwidthEntriesPerHeartbeat = 256

// BandwidthUsageStore persists the latest cumulative bandwidth counters
// reported for each of a provider's workloads (ADR-025 §2). Implemented
// by PostgresBandwidthUsageStore; a memory fake backs the Service tests.
type BandwidthUsageStore interface {
	RecordUsage(ctx context.Context, providerID string, entries []*controlplanev1.WorkloadBandwidthUsage) error
}

// SetBandwidthUsageStore enables persisting workload_bandwidth entries
// on every heartbeat. Like SetValidatorSource/SetWorkloadService, it may
// be left unset -- see recordBandwidthUsage's doc comment for the
// degraded-mode behavior when unset or when a write fails.
func (s *Service) SetBandwidthUsageStore(store BandwidthUsageStore) { s.bandwidthUsage = store }

// recordBandwidthUsage persists this heartbeat's workload_bandwidth
// entries, called only after ReportHeartbeat has already verified the
// Ed25519 signature over the whole payload -- WorkloadBandwidthUsage has
// no signature field of its own (see its proto doc comment): it rides
// inside HeartbeatSigningPayload, so the one heartbeat signature already
// authenticates these entries too.
//
// An unset store, an empty entry list, or a write failure all degrade to
// a no-op (logged at warn on an actual failure) rather than failing the
// heartbeat -- liveness (ReportHeartbeat's core job) must not depend on
// this secondary telemetry path, and ADR-025 §2 is explicit that this
// data is not billing-grade. Per-workload counter-decrease discarding
// happens inside the store itself (PostgresBandwidthUsageStore), not
// here: this method's only job is "hand the verified entries to the
// store, don't let it take the heartbeat down."
func (s *Service) recordBandwidthUsage(ctx context.Context, providerID string, entries []*controlplanev1.WorkloadBandwidthUsage) {
	if s.bandwidthUsage == nil || len(entries) == 0 {
		return
	}
	if err := s.bandwidthUsage.RecordUsage(ctx, providerID, entries); err != nil {
		slog.Warn("workload bandwidth usage not recorded for this heartbeat", "provider_id", providerID, "error", err)
	}
}

// validateWorkloadBandwidth checks the structural shape of each
// workload_bandwidth entry ADR-025 §2 adds to the heartbeat payload.
// This is independent of, and runs before, the per-workload
// counter-decrease discarding the store applies once persisting: a
// malformed entry (missing/invalid fields) fails the whole heartbeat the
// same way a malformed top-level field already does elsewhere in
// validateHeartbeat, while a well-formed but suspicious entry (a counter
// that decreased) is discarded, not rejected -- see recordBandwidthUsage.
func validateWorkloadBandwidth(entries []*controlplanev1.WorkloadBandwidthUsage) error {
	if len(entries) > maxWorkloadBandwidthEntriesPerHeartbeat {
		return errors.New("workload_bandwidth exceeds the maximum entries per heartbeat")
	}
	for _, entry := range entries {
		if entry == nil {
			return errors.New("workload_bandwidth entries must not be nil")
		}
		if _, err := uuid.Parse(entry.WorkloadId); err != nil {
			return errors.New("workload_bandwidth[].workload_id must be a UUID")
		}
		if err := entry.WindowStartedAt.CheckValid(); err != nil {
			return errors.New("workload_bandwidth[].window_started_at must be a valid timestamp")
		}
	}
	return nil
}
