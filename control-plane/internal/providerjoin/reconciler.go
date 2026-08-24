package providerjoin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"time"

	"github.com/openinfra/network/internal/blockchainbridge"
)

// PendingChainRegistration is one row of the provider_chain_registrations
// outbox that still needs an on-chain registration attempt.
type PendingChainRegistration struct {
	ProviderID   string
	PublicKey    []byte
	AttemptCount int
}

// ChainRegistrationStore lets the Reconciler discover and update outbox rows
// independent of any Agent CompleteJoin call. Implemented by
// *PostgresRepository.
type ChainRegistrationStore interface {
	// DueChainRegistrations returns up to limit providers whose chain
	// registration is READY or RETRY and due (next_attempt_at unset or in
	// the past), oldest first.
	DueChainRegistrations(ctx context.Context, limit int) ([]PendingChainRegistration, error)
	// RecordChainRegistrationFailure increments the attempt counter and
	// either schedules the next retry (state RETRY, nextAttemptAt) or, when
	// terminal is true, marks the registration FAILED so it stops being
	// picked up -- an explicit terminal state rather than a silent hang.
	RecordChainRegistrationFailure(ctx context.Context, providerID string, attemptErr error, nextAttemptAt time.Time, terminal bool) error
}

// Activator is the subset of Repository the Reconciler needs to finalize a
// successful on-chain registration; *PostgresRepository satisfies this via
// its existing ActivateProvider (the same method CompleteJoin's inline path
// already uses).
type Activator interface {
	ActivateProvider(ctx context.Context, providerID string, finalization ChainFinalization) (Completion, error)
}

// ReconcilerConfig bounds the Reconciler's polling cadence, batch size, and
// retry backoff.
type ReconcilerConfig struct {
	Interval    time.Duration
	BatchSize   int
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

// DefaultReconcilerConfig returns production-sane bounds: poll every 15s,
// up to 20 providers per pass, exponential backoff from 5s capped at 10m,
// and a registration is declared FAILED (terminal) after 10 attempts.
func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{
		Interval:    15 * time.Second,
		BatchSize:   20,
		MaxAttempts: 10,
		BaseBackoff: 5 * time.Second,
		MaxBackoff:  10 * time.Minute,
	}
}

func (c ReconcilerConfig) withDefaults() ReconcilerConfig {
	defaults := DefaultReconcilerConfig()
	if c.Interval <= 0 {
		c.Interval = defaults.Interval
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaults.BatchSize
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = defaults.MaxAttempts
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = defaults.BaseBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = defaults.MaxBackoff
	}
	return c
}

// Reconciler autonomously drives provider_chain_registrations rows left in
// READY or RETRY to FINALIZED (via the same idempotent EnsureActive/
// ActivateProvider path CompleteJoin uses) or, after MaxAttempts, to an
// explicit FAILED state. It exists so Provider Join recovers after a
// Control Plane or chain restart without depending on the Agent retrying
// CompleteJoin (issue #10): the outbox row is already committed
// transactionally alongside the provider record in CompleteJoin, so a crash
// between that commit and a successful chain registration leaves work for
// the Reconciler to pick up on its own schedule.
type Reconciler struct {
	store     ChainRegistrationStore
	activator Activator
	registrar ProviderRegistrar
	now       func() time.Time
	cfg       ReconcilerConfig
}

func NewReconciler(store ChainRegistrationStore, activator Activator, registrar ProviderRegistrar, cfg ReconcilerConfig) *Reconciler {
	return &Reconciler{
		store:     store,
		activator: activator,
		registrar: registrar,
		now:       time.Now,
		cfg:       cfg.withDefaults(),
	}
}

// Run polls on cfg.Interval until ctx is cancelled. Intended to be started
// as `go reconciler.Run(ctx)` alongside the gRPC/HTTP servers.
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		r.ReconcileOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ReconcileOnce processes a single due batch and returns without waiting on
// the ticker -- exported so tests (and any future manual-trigger endpoint)
// can drive reconciliation deterministically.
func (r *Reconciler) ReconcileOnce(ctx context.Context) {
	due, err := r.store.DueChainRegistrations(ctx, r.cfg.BatchSize)
	if err != nil {
		slog.Error("reconciler: failed to list due chain registrations", "error", err)
		return
	}
	for _, registration := range due {
		if ctx.Err() != nil {
			return
		}
		r.reconcileOne(ctx, registration)
	}
}

func (r *Reconciler) reconcileOne(ctx context.Context, registration PendingChainRegistration) {
	if r.registrar == nil {
		return
	}
	if len(registration.PublicKey) != ed25519.PublicKeySize {
		// Malformed stored data: retrying can never fix a wrong-length key.
		r.fail(ctx, registration.ProviderID, errors.New("stored public key has an unexpected length"), registration.AttemptCount+1, true)
		return
	}
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], registration.PublicKey)

	extrinsicHash, blockHash, blockNumber, err := r.registrar.EnsureActive(ctx, publicKey)
	if err != nil {
		nextAttemptNumber := registration.AttemptCount + 1
		r.fail(ctx, registration.ProviderID, err, nextAttemptNumber, nextAttemptNumber >= r.cfg.MaxAttempts)
		return
	}
	if _, err := r.activator.ActivateProvider(ctx, registration.ProviderID, ChainFinalization{
		ExtrinsicHash:        extrinsicHash,
		FinalizedBlockHash:   blockHash,
		FinalizedBlockNumber: blockNumber,
	}); err != nil {
		slog.Error("reconciler: on-chain registration succeeded but activation failed",
			"provider_id", registration.ProviderID, "error", err)
	}
}

func (r *Reconciler) fail(ctx context.Context, providerID string, attemptErr error, attemptNumber int, terminal bool) {
	slog.Error("reconciler: chain registration attempt failed", "provider_id", providerID, "error", attemptErr, "attempt", attemptNumber, "terminal", terminal)
	backoff := r.backoffFor(attemptNumber)
	// Issue #141: a "1012: Transaction is temporarily banned" rejection
	// means the pool already has this exact extrinsic (EnsureActive's
	// nonce is derived from *finalized* state, which cannot advance while
	// the banned transaction is itself what's blocking finalization) on a
	// cooldown -- confirmed live, repeatedly, in this session: retrying on
	// the normal exponential schedule's early, short intervals just
	// resubmits the byte-for-byte identical extrinsic and re-triggers the
	// same ban. Jump straight to MaxBackoff instead of ramping up to it,
	// so the retry is much more likely to land after the pool's cooldown
	// has actually expired. This is not the full fix -- letting a retry
	// actually displace a stuck entry (rather than just outwaiting it)
	// needs a runtime-level tip mechanism and its own ADR, tracked
	// separately, not this bounded, ADR-free improvement.
	if blockchainbridge.IsTemporarilyBanned(attemptErr) && backoff < r.cfg.MaxBackoff {
		backoff = r.cfg.MaxBackoff
	}
	nextAttemptAt := r.now().UTC().Add(backoff)
	if recErr := r.store.RecordChainRegistrationFailure(ctx, providerID, attemptErr, nextAttemptAt, terminal); recErr != nil {
		slog.Error("reconciler: failed to record chain registration attempt", "provider_id", providerID, "error", recErr)
	}
}

// backoffFor returns the base backoff doubled per additional attempt,
// capped at MaxBackoff. attempt is always >= 1.
func (r *Reconciler) backoffFor(attempt int) time.Duration {
	const maxShift = 16 // 2^16 * BaseBackoff already exceeds any sane MaxBackoff
	shift := attempt - 1
	if shift > maxShift {
		shift = maxShift
	}
	backoff := r.cfg.BaseBackoff
	for i := 0; i < shift; i++ {
		backoff *= 2
		if backoff <= 0 || backoff > r.cfg.MaxBackoff {
			return r.cfg.MaxBackoff
		}
	}
	if backoff > r.cfg.MaxBackoff {
		return r.cfg.MaxBackoff
	}
	return backoff
}
