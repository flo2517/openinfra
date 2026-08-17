package networkvalidator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/openinfra/network/internal/blockchainbridge"
)

// DefaultPollInterval polls the finalized head roughly once per block.
// This runtime's block time is ~3s (MinimumPeriod=1500ms,
// SlotDuration=MinimumPeriodTimesTwo -- blockchain/runtime/src/lib.rs);
// polling faster than that wastes RPC calls without seeing new state
// sooner, polling much slower delays noticing a new round or a newly
// registered provider. Unlike Registrar's ~500ms pollInterval (built for
// tight "wait for this exact state transition" loops around a single
// extrinsic), this loop's poll cadence only needs to keep up with block
// production, not react within a fraction of a block.
const DefaultPollInterval = 3 * time.Second

// DefaultCloseAttemptDelay is how long this validator waits after
// submitting its own evidence before making its first close_round
// attempt for that (provider, round, dimension). This validator has no
// visibility into how many *other* committee members have submitted
// (reading Evidence's submission count is explicitly out of scope for
// this slice -- see the package doc comment on CloseRound in
// blockchainbridge), so this delay is a blunt, generous guess at "other
// committee members' own polling loops have probably had a chance to
// submit by now," not a quorum check. 30s is ten poll intervals at the
// default cadence.
const DefaultCloseAttemptDelay = 30 * time.Second

// DefaultCloseAttemptRetryInterval and DefaultMaxCloseAttempts bound how
// hard this validator retries close_round for one key before giving up.
// Most attempts before quorum is reached will legitimately dispatch-fail
// with QuorumNotReached (an RPC-accepted, dispatch-rejected outcome this
// validator cannot directly observe -- see CloseRound's doc comment) --
// this is expected, not a bug, and is why retries are bounded rather than
// either infinite or single-shot.
const (
	DefaultCloseAttemptRetryInterval = 20 * time.Second
	DefaultMaxCloseAttempts          = 5
)

// DefaultUnscoredRetryInterval bounds how often this validator re-attempts
// a challenge that came back Unscored (see ChallengeResult.Unscored --
// today, exclusively the Network dimension without a declared bandwidth
// figure to compare against). The missing input is the provider's next
// capability-bearing heartbeat reaching the dashboard; retrying faster
// than that cadence cannot possibly see it sooner, so this backs off
// instead of re-running a full MeasureBandwidth probe round (real mTLS
// traffic, several MiB each way) on every PollInterval tick for as long
// as the round stays open. 20s mirrors DefaultCloseAttemptRetryInterval:
// both are "nothing relevant changes faster than this" bounds, not a
// precisely tuned value.
const DefaultUnscoredRetryInterval = 20 * time.Second

// LoopConfig configures Run. Chain and Registrar are required; the rest
// have documented defaults applied by NewLoopConfig / Run when zero.
type LoopConfig struct {
	Chain      *blockchainbridge.RPCClient
	Registrar  *blockchainbridge.Registrar
	Challenger *ChallengeClient

	RoundLength         RoundLength
	TargetCommitteeSize uint32
	PollInterval        time.Duration

	CloseAttemptDelay         time.Duration
	CloseAttemptRetryInterval time.Duration
	MaxCloseAttempts          int
	UnscoredRetryInterval     time.Duration

	Logger *slog.Logger
}

func (cfg *LoopConfig) applyDefaults() {
	if cfg.TargetCommitteeSize == 0 {
		cfg.TargetCommitteeSize = blockchainbridge.NetworkValidatorTargetCommitteeSize
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.CloseAttemptDelay == 0 {
		cfg.CloseAttemptDelay = DefaultCloseAttemptDelay
	}
	if cfg.CloseAttemptRetryInterval == 0 {
		cfg.CloseAttemptRetryInterval = DefaultCloseAttemptRetryInterval
	}
	if cfg.MaxCloseAttempts == 0 {
		cfg.MaxCloseAttempts = DefaultMaxCloseAttempts
	}
	if cfg.UnscoredRetryInterval == 0 {
		cfg.UnscoredRetryInterval = DefaultUnscoredRetryInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
}

// pendingClose tracks one (provider, round, dimension) this process has
// evidenced and is periodically attempting to close.
type pendingClose struct {
	evidencedAt time.Time
	lastAttempt time.Time
	attempts    int
}

// Run polls the finalized head on cfg.PollInterval until ctx is
// cancelled, driving the full ADR-013 §4 challenge loop each tick:
// derive the current round, enumerate registered providers, compute this
// validator's local assignment for each (no chain call needed beyond the
// active-validator-set read), challenge and submit evidence for anything
// newly assigned, and periodically attempt to close rounds this process
// itself evidenced. Returns only on ctx cancellation (with ctx.Err()) or
// a setup-level failure; a single tick's transient error (an RPC hiccup,
// one unreachable Agent) is logged and the loop continues -- one bad
// tick must not stop the daemon, matching this whole feature's
// "auditable, self-healing" design (see the package doc comment and
// CloseRound's).
func Run(ctx context.Context, cfg LoopConfig) error {
	if cfg.Chain == nil || cfg.Registrar == nil || cfg.Challenger == nil {
		return errors.New("networkvalidator.Run requires Chain, Registrar, and Challenger")
	}
	cfg.applyDefaults()

	self := cfg.Registrar.Account()
	// done is intentionally in-memory only and never persisted: a process
	// restart re-attempting evidence it already submitted just fails
	// harmlessly on-chain via submit_evidence's own DuplicateSubmission
	// check (see the pallet source) -- the same accepted, self-healing
	// gap slice 3's in-memory-only allowlist tracking already established
	// for this feature, not a new corner cut here.
	done := make(map[roundKey]bool)
	pending := make(map[roundKey]*pendingClose)
	// lastUnscored tracks, per key, the last time a challenge for it came
	// back Unscored -- same in-memory-only, never-persisted lifetime as
	// done/pending (see their comment above): a process restart just
	// means one extra unbacked-off attempt, not a correctness problem.
	lastUnscored := make(map[roundKey]time.Time)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if err := tick(ctx, cfg, self, done, pending, lastUnscored); err != nil {
			cfg.Logger.Error("networkvalidator: tick failed", "error", err)
		}
	}
}

func tick(ctx context.Context, cfg LoopConfig, self [32]byte, done map[roundKey]bool, pending map[roundKey]*pendingClose, lastUnscored map[roundKey]time.Time) error {
	head, err := cfg.Chain.FinalizedHead(ctx)
	if err != nil {
		return err
	}
	header, err := cfg.Chain.HeaderAt(ctx, head)
	if err != nil {
		return err
	}
	blockNumber, err := header.BlockNumber()
	if err != nil {
		return err
	}
	round := cfg.RoundLength.Round(blockNumber)

	activeValidators, err := cfg.Chain.ActiveNetworkValidators(ctx, head)
	if err != nil {
		return err
	}
	providers, err := cfg.Chain.FinalizedProviderAccounts(ctx)
	if err != nil {
		return err
	}

	assignments := AssignedWork(self, providers, round, activeValidators, cfg.TargetCommitteeSize, done)
	for _, key := range assignments {
		challengeAndSubmit(ctx, cfg, key, done, pending, lastUnscored)
	}

	attemptPendingCloses(ctx, cfg, pending)
	return nil
}

func challengeAndSubmit(ctx context.Context, cfg LoopConfig, key roundKey, done map[roundKey]bool, pending map[roundKey]*pendingClose, lastUnscored map[roundKey]time.Time) {
	providerID := providerIDHex(key.provider)
	logger := cfg.Logger.With("provider_id", providerID, "round", key.round, "dimension", key.dimension.String())

	// Only ever populated by this same function's Unscored branch below,
	// so a hit here means the last attempt for this exact key came back
	// Unscored -- back off rather than re-running a full challenge (for
	// Network, a real multi-MiB probe round) before the backoff window
	// has passed. Not marked done, so this key keeps being reassigned by
	// AssignedWork every tick; this check is what keeps that from turning
	// into unbounded, unbacked-off retries (see DefaultUnscoredRetryInterval).
	if last, ok := lastUnscored[key]; ok && time.Since(last) < cfg.UnscoredRetryInterval {
		return
	}

	logger.Info("networkvalidator: assigned, challenging")

	// ADR-015: the Network dimension's evidence changes from a generic
	// SolveChallenge liveness/correctness check to a real MeasureBandwidth
	// throughput probe -- run instead of, not in addition to,
	// Challenge()'s SolveChallenge call. Every other dimension is
	// unchanged.
	var result ChallengeResult
	var err error
	if key.dimension == blockchainbridge.DimensionNetwork {
		result, err = cfg.Challenger.MeasureBandwidth(ctx, providerID)
	} else {
		result, err = cfg.Challenger.Challenge(ctx, providerID, key.dimension)
	}
	if err != nil {
		// Discovery/setup could not even be attempted (e.g. dashboard
		// unreachable) -- do not mark done, so a later tick this same
		// round can retry.
		logger.Warn("networkvalidator: could not attempt challenge, will retry next tick", "error", err)
		return
	}
	if result.Unscored {
		// Judged nothing, so submit nothing. Writing either verdict would
		// put a claim into consensus state that no measurement supports
		// (see ChallengeResult.Unscored). Not marked done, so a later
		// tick retries once the missing input -- currently only the
		// provider's declared capacity, which arrives with its next
		// heartbeat -- is available. lastUnscored is what bounds "a later
		// tick" to no sooner than UnscoredRetryInterval, above.
		lastUnscored[key] = time.Now()
		logger.Warn("networkvalidator: challenge unscored, submitting nothing", "reason", result.Reason)
		return
	}
	logger.Info("networkvalidator: challenge scored", "score_bps", result.ScoreBps, "reason", result.Reason)

	if err := cfg.Registrar.SubmitEvidence(ctx, key.provider, key.round, key.dimension, result.ScoreBps, result.SampleCount, result.PayloadHash); err != nil {
		// An RPC-level failure (network, nonce, unsupported runtime
		// version) -- distinct from a dispatch-level rejection, which
		// this call cannot observe (see SubmitDirect/CloseRound doc
		// comments). Do not mark done: retry next tick.
		logger.Error("networkvalidator: submit_evidence RPC failed, will retry next tick", "error", err)
		return
	}
	logger.Info("networkvalidator: evidence submitted")
	done[key] = true
	pending[key] = &pendingClose{evidencedAt: time.Now()}
}

func attemptPendingCloses(ctx context.Context, cfg LoopConfig, pending map[roundKey]*pendingClose) {
	now := time.Now()
	for key, state := range pending {
		if now.Sub(state.evidencedAt) < cfg.CloseAttemptDelay {
			continue
		}
		if state.attempts > 0 && now.Sub(state.lastAttempt) < cfg.CloseAttemptRetryInterval {
			continue
		}
		logger := cfg.Logger.With("provider_id", providerIDHex(key.provider), "round", key.round, "dimension", key.dimension.String())
		err := cfg.Registrar.CloseRound(ctx, key.provider, key.round, key.dimension)
		state.attempts++
		state.lastAttempt = now
		if err != nil {
			// Expected and common: most attempts before quorum will
			// legitimately fail dispatch (QuorumNotReached), which this
			// RPC call cannot distinguish from any other failure -- see
			// CloseRound's doc comment. Logged at Info, not Error/Warn,
			// specifically because "not ready yet" is the normal case,
			// not a fault.
			logger.Info("networkvalidator: close_round attempt did not succeed at the RPC level (may also fail dispatch if quorum isn't reached yet)", "attempt", state.attempts, "error", err)
		} else {
			logger.Info("networkvalidator: close_round submitted (dispatch outcome, e.g. QuorumNotReached, is not visible via RPC)", "attempt", state.attempts)
		}
		if state.attempts >= cfg.MaxCloseAttempts {
			logger.Info("networkvalidator: giving up on close_round for this round after bounded retries", "attempts", state.attempts)
			delete(pending, key)
		}
	}
}

// providerIDHex derives the sha256-hex provider_id string from a raw
// on-chain AccountId, matching internal/providerjoin/service.go's
// derivation exactly (providerDigest := sha256.Sum256(challenge.PublicKey);
// ProviderID: hex.EncodeToString(providerDigest[:])) -- this codebase's
// AccountId *is* the raw Ed25519 public key (see e.g.
// blockchainbridge.Registrar.account), so hashing the account bytes
// directly reproduces the same identifier providerjoin computed from the
// same public key at join time.
func providerIDHex(account [32]byte) string {
	digest := sha256.Sum256(account[:])
	return hex.EncodeToString(digest[:])
}
