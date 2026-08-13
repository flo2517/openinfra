package dashboard

import (
	"context"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/openinfra/network/internal/blockchainbridge"
)

// validatorOpenRoundLookback bounds how far back this endpoint scans for
// rounds that have not closed. Unlike validatorScores' history window
// (which wants a readable run of *closed* rounds), an open round is only
// interesting while it can still close, and a round far behind the head
// that never reached quorum is a stuck round, not a queue entry. Four
// rounds shows the current one plus enough history to make "this
// dimension has been stuck for three rounds" visible without turning the
// scan into a long sequence of round trips.
const validatorOpenRoundLookback = 3

// validatorHealthMaxAccounts bounds how many active validators this
// endpoint reads records for. The runtime's MaxNetworkValidators is 256,
// and each record is its own point read, so an unbounded loop here would
// be up to 256 sequential-ish RPC calls behind a single unauthenticated
// HTTP request. Callers get Truncated=true rather than a silently short
// list when the active set exceeds this.
const validatorHealthMaxAccounts = 64

// validatorHealthReadConcurrency bounds the in-flight record reads.
const validatorHealthReadConcurrency = 8

// ValidatorSubmission is one committee member's evidence for an open
// round: the integer claim plus the payload hash that addresses the full
// evidence off-chain (ADR-011 §3). No payload is served here, and none
// exists on-chain to serve.
type ValidatorSubmission struct {
	Validator   string `json:"validator"`
	ScoreBps    uint16 `json:"score_bps"`
	SampleCount uint32 `json:"sample_count"`
	PayloadHash string `json:"payload_hash"`
}

// OpenRound is one (round, dimension) pair that has not closed yet: who
// was assigned, who has answered, and whether the answers received are
// enough for close_round to succeed.
type OpenRound struct {
	Round uint64 `json:"round"`
	// Committee is recomputed from *today's* active validator set, so
	// for an older round whose set has since changed it is an
	// approximation of who was assigned at submission time -- see
	// CommitteeStale.
	Committee   []string              `json:"committee"`
	Submissions []ValidatorSubmission `json:"submissions"`
	// AwaitingResponse is the committee members with no submission yet:
	// the actual "challenge queue" for this round.
	AwaitingResponse []string `json:"awaiting_response"`
	// CommitteeStale is true when a submission came from an account that
	// is not in the recomputed committee, which can only mean the active
	// set changed since that submission landed. It is a signal that
	// Committee/AwaitingResponse should be read as indicative, not
	// authoritative, for this round -- the chain enforced assignment
	// against the set as it was.
	CommitteeStale bool   `json:"committee_stale,omitempty"`
	QuorumRequired uint32 `json:"quorum_required"`
	QuorumReached  bool   `json:"quorum_reached"`
}

// DimensionOpenRounds is one dimension's slice of ValidatorRounds.
type DimensionOpenRounds struct {
	Dimension string      `json:"dimension"`
	Rounds    []OpenRound `json:"rounds"`
}

// ValidatorRounds is GET /api/v1/validator/rounds/{provider_id}'s
// response body: the in-flight side of the challenge protocol, the
// counterpart to validator-scores' closed-round history.
type ValidatorRounds struct {
	ProviderID      string                `json:"provider_id"`
	CurrentRound    uint64                `json:"current_round"`
	ActiveValidator int                   `json:"active_validators"`
	Dimensions      []DimensionOpenRounds `json:"dimensions"`
	Partial         bool                  `json:"partial,omitempty"`
}

// validatorRounds serves #76's "challenge queue, evidence, quorum, weight
// submissions" validator view. Public tier, like validator-scores
// (ADR-016 §2): every field here is already-public on-chain state --
// assignment is publicly computable by design (ADR-011 §1), and each
// submission is an attributable, signed extrinsic anyone with a chain
// connection can read. Rate-limited on the same footing.
func (s *Server) validatorRounds(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "validator-rounds") {
		return
	}
	account, ok := s.providerOnChainAccount(ctx, w, r.PathValue("provider_id"))
	if !ok {
		return
	}
	currentRound, ok := s.currentValidatorRound(ctx, w)
	if !ok {
		return
	}

	result := ValidatorRounds{
		ProviderID:   r.PathValue("provider_id"),
		CurrentRound: currentRound,
		Dimensions:   make([]DimensionOpenRounds, len(validatorScoreDimensions)),
	}

	// The active set is read once and reused for every committee
	// computation: it is the same input for all of them, and re-reading
	// it per round would also risk two rounds in one response being
	// computed against different sets.
	activeValidators, err := s.chain.LatestActiveNetworkValidators(ctx)
	if err != nil {
		// Committee/AwaitingResponse are unavailable without it, but the
		// submissions themselves still are -- degrade to a partial answer
		// rather than failing the whole view, matching how loadOverview
		// treats a failed chain read.
		result.Partial = true
		activeValidators = nil
	}
	result.ActiveValidator = len(activeValidators)

	var partial sync.Mutex
	var wg sync.WaitGroup
	for index, dimension := range validatorScoreDimensions {
		wg.Add(1)
		go func(index int, dimension blockchainbridge.ScoreDimension) {
			defer wg.Done()
			rounds, sawError := s.dimensionOpenRounds(ctx, account, currentRound, dimension, activeValidators)
			result.Dimensions[index] = rounds
			if sawError {
				partial.Lock()
				result.Partial = true
				partial.Unlock()
			}
		}(index, dimension)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) dimensionOpenRounds(ctx context.Context, account [32]byte, currentRound uint64, dimension blockchainbridge.ScoreDimension, activeValidators [][32]byte) (DimensionOpenRounds, bool) {
	open := DimensionOpenRounds{Dimension: dimension.String(), Rounds: []OpenRound{}}
	sawError := false
	for offset := uint64(0); offset <= validatorOpenRoundLookback && offset <= currentRound; offset++ {
		round := currentRound - offset

		// Evidence is read before Rounds because close_round *removes*
		// the Evidence entry when it aggregates (see the pallet's
		// "raw submissions are no longer needed" comment), so a
		// non-empty read already proves the round is open and the
		// second read can be skipped. Only an empty read is ambiguous
		// -- open with nobody having answered yet, versus closed.
		submissions, err := s.chain.FinalizedEvidence(ctx, account, round, dimension)
		if err != nil {
			sawError = true
			continue
		}
		if len(submissions) == 0 {
			_, closed, err := s.chain.FinalizedRoundResult(ctx, account, round, dimension)
			if err != nil {
				sawError = true
				continue
			}
			if closed {
				continue
			}
		}
		entry := buildOpenRound(account, round, submissions, activeValidators)
		if !openRoundIsInformative(entry) {
			continue
		}
		open.Rounds = append(open.Rounds, entry)
	}
	return open, sawError
}

// openRoundIsInformative rejects a round where nobody has answered *and*
// nobody was asked. Every round in the lookback window is technically
// "open" until it closes, so with an empty active validator set a
// provider's response would otherwise list every round of every dimension
// as an open queue entry -- verified against the dev chain, where that is
// 20 identical empty rows. Nothing can be assigned or closed without an
// active set, so those rows describe an inert protocol as a backlog.
//
// A round is kept as soon as it has either a submission (someone answered)
// or a committee (someone owes an answer, including the stuck-round case
// where the committee has answered nothing for several rounds). The
// active-set size is reported separately on the response, so "no open
// rounds" and "no validators at all" stay distinguishable.
func openRoundIsInformative(entry OpenRound) bool {
	return len(entry.Submissions) > 0 || len(entry.Committee) > 0
}

// buildOpenRound joins the submissions actually on-chain with the
// committee that assignment says should have produced them.
func buildOpenRound(account [32]byte, round uint64, submissions []blockchainbridge.Submission, activeValidators [][32]byte) OpenRound {
	entry := OpenRound{
		Round:            round,
		Committee:        []string{},
		Submissions:      make([]ValidatorSubmission, 0, len(submissions)),
		AwaitingResponse: []string{},
		QuorumRequired:   blockchainbridge.NetworkValidatorMinQuorum,
		QuorumReached:    uint32(len(submissions)) >= blockchainbridge.NetworkValidatorMinQuorum,
	}

	submitted := make(map[[32]byte]bool, len(submissions))
	for _, submission := range submissions {
		submitted[submission.Validator] = true
		entry.Submissions = append(entry.Submissions, ValidatorSubmission{
			Validator:   accountHex(submission.Validator),
			ScoreBps:    submission.ScoreBps,
			SampleCount: submission.SampleCount,
			PayloadHash: "0x" + hex.EncodeToString(submission.PayloadHash[:]),
		})
	}

	if len(activeValidators) == 0 {
		return entry
	}
	assigned := make(map[[32]byte]bool)
	for _, member := range blockchainbridge.Committee(account, round, activeValidators, blockchainbridge.NetworkValidatorTargetCommitteeSize) {
		assigned[member] = true
		entry.Committee = append(entry.Committee, accountHex(member))
		if !submitted[member] {
			entry.AwaitingResponse = append(entry.AwaitingResponse, accountHex(member))
		}
	}
	for validator := range submitted {
		if !assigned[validator] {
			entry.CommitteeStale = true
			break
		}
	}
	return entry
}

// ValidatorHealth is one Network Validator's on-chain lifecycle state.
type ValidatorHealth struct {
	Validator string `json:"validator"`
	// Status is ACTIVE/SUSPENDED/EXITING, or empty with Found=false when
	// the account is in ActiveValidatorSet but has no Validators record
	// -- an inconsistency the pallet is written to prevent, so surfacing
	// it as a visible gap beats rendering it as a healthy validator.
	Status string `json:"status,omitempty"`
	Found  bool   `json:"found"`
	// AvailableAt is only meaningful for EXITING.
	AvailableAt  uint32 `json:"available_at_block,omitempty"`
	Stake        uint64 `json:"stake,omitempty"`
	RegisteredAt uint32 `json:"registered_at_block,omitempty"`
	// Unavailable marks a record whose read failed, so a client can tell
	// "no record on-chain" (Found=false) from "we could not ask".
	Unavailable bool `json:"unavailable,omitempty"`
}

// ValidatorSet is GET /api/v1/validator/health's response body.
type ValidatorSet struct {
	ActiveCount int               `json:"active_count"`
	MinQuorum   uint32            `json:"min_quorum"`
	Committee   uint32            `json:"target_committee_size"`
	Validators  []ValidatorHealth `json:"validators"`
	// Truncated is true when the active set is larger than this endpoint
	// reads records for.
	Truncated bool `json:"truncated,omitempty"`
	Partial   bool `json:"partial,omitempty"`
}

// validatorHealth serves #76's "validator health" view: who is in the
// active set and what the chain says about each one. Public tier for the
// same reason as validatorRounds -- ActiveValidatorSet and Validators are
// both public storage, and /api/v1/overview already publishes the active
// set's accounts.
func (s *Server) validatorHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "validator-health") {
		return
	}

	accounts, err := s.chain.LatestActiveNetworkValidators(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "blockchain status unavailable"})
		return
	}

	result := ValidatorSet{
		ActiveCount: len(accounts),
		MinQuorum:   blockchainbridge.NetworkValidatorMinQuorum,
		Committee:   blockchainbridge.NetworkValidatorTargetCommitteeSize,
		Validators:  []ValidatorHealth{},
	}
	if len(accounts) > validatorHealthMaxAccounts {
		result.Truncated = true
		accounts = accounts[:validatorHealthMaxAccounts]
	}
	result.Validators = make([]ValidatorHealth, len(accounts))

	var partial sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, validatorHealthReadConcurrency)
	for index, account := range accounts {
		wg.Add(1)
		go func(index int, account [32]byte) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			health := ValidatorHealth{Validator: accountHex(account)}
			record, found, err := s.chain.FinalizedValidatorRecord(ctx, account)
			switch {
			case err != nil:
				health.Unavailable = true
				partial.Lock()
				result.Partial = true
				partial.Unlock()
			case found:
				health.Found = true
				health.Status = record.Status.String()
				health.Stake = record.Stake
				health.RegisteredAt = record.RegisteredAt
				health.AvailableAt = record.AvailableAt
			}
			result.Validators[index] = health
		}(index, account)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, result)
}

// accountHex renders a 32-byte AccountId in full, unlike /api/v1/overview's
// abbreviated rendering: these views exist for a validator to find its own
// account and for an operator to match a submission to a validator, and a
// 12-character prefix cannot do either reliably.
func accountHex(account [32]byte) string {
	return "0x" + hex.EncodeToString(account[:])
}
