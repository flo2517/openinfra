package dashboard

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/networkvalidator"
)

// validatorScoreDimensions is every ScoreDimension pallet-network-validator
// defines, in the pallet's own declaration order -- iterated over rather
// than discovered, since ScoreDimension's variant set only ever changes
// with a pallet upgrade, the same assumption ParseScoreDimension already
// makes.
var validatorScoreDimensions = []blockchainbridge.ScoreDimension{
	blockchainbridge.DimensionCompute,
	blockchainbridge.DimensionStorage,
	blockchainbridge.DimensionNetwork,
	blockchainbridge.DimensionAvailability,
	blockchainbridge.DimensionReliability,
}

// validatorScoreLookbackRounds bounds how far back, per dimension, this
// endpoint scans for closed rounds before giving up -- Rounds is an
// OptionQuery NMap with no enumeration RPC available under this node's
// --rpc-methods=safe allowlist (see FinalizedProviderAccounts's doc
// comment on state_getKeysPaged vs state_getPairs for the same
// constraint), so a per-round point read is the only read shape
// available and each one is a real network round trip. 12 rounds is
// enough to show a handful of closed rounds' worth of history even for a
// dimension that only closes sporadically, while keeping the worst case
// (every round in the window open) at a bounded, human-noticeable-but-
// not-alarming number of sequential reads per dimension.
const validatorScoreLookbackRounds = 12

// validatorScoreMaxEntriesPerDimension caps how many closed rounds are
// returned once found, so a dimension that has closed every round in the
// lookback window doesn't return an unbounded (from the caller's
// perspective) payload.
const validatorScoreMaxEntriesPerDimension = 8

// RoundScore is one closed round's outcome for a single dimension,
// shaped for direct display -- see #76's "validator score history...
// without false success" acceptance criterion, which is why Confidence
// is precomputed here rather than left for the client to derive from
// Submissions/CommitteeTarget (a client that forgets to divide would
// otherwise render a thin, low-confidence round exactly like a
// well-attested one).
type RoundScore struct {
	Round            uint64 `json:"round"`
	ScoreBps         uint16 `json:"score_bps"`
	PreviousScoreBps uint16 `json:"previous_score_bps"`
	Submissions      uint32 `json:"submissions"`
	CommitteeTarget  uint32 `json:"committee_target"`
	ConfidenceBps    uint32 `json:"confidence_bps"`
	ClosedAt         uint32 `json:"closed_at_block"`
	Status           string `json:"status"`
}

// DimensionScoreHistory is one dimension's slice of ValidatorScores.
type DimensionScoreHistory struct {
	Dimension string       `json:"dimension"`
	Rounds    []RoundScore `json:"rounds"`
}

// ValidatorScores is GET /api/v1/validator-scores/{provider_id}'s
// response body: the provider's recent Network Validator challenge
// outcomes, one history per dimension. CurrentRound is included so a
// client can tell "this dimension has never closed a round" (empty
// Rounds) apart from "this dimension has closed rounds, but none in the
// scanned window" -- both render as an empty list otherwise.
type ValidatorScores struct {
	ProviderID   string                  `json:"provider_id"`
	CurrentRound uint64                  `json:"current_round"`
	Dimensions   []DimensionScoreHistory `json:"dimensions"`
	Partial      bool                    `json:"partial,omitempty"`
}

// validatorScores is #76's validator-facing dashboard view: per-dimension
// challenge-round history for one provider, read live from
// pallet-network-validator's Rounds NMap (see
// internal/blockchainbridge/roundresult.go). Deliberately unauthenticated
// and rate-limited like agentEndpoint -- the underlying reputation
// figures this summarizes are already public (ProviderReputationVector
// renders in /api/v1/overview), so this is a narrower, per-provider,
// per-round view of the same public on-chain state, not a new trust
// boundary.
func (s *Server) validatorScores(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "validator-scores") {
		return
	}
	providerID := r.PathValue("provider_id")
	if providerID == "" || len(providerID) > maxProviderIDLength {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id is required and bounded"})
		return
	}

	var publicKey []byte
	err := s.pool.QueryRow(ctx, `SELECT public_key FROM providers WHERE provider_id=$1`, providerID).Scan(&publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider lookup unavailable"})
		return
	}
	if len(publicKey) != ed25519.PublicKeySize {
		// Same defensive check loadOverview applies before treating a
		// provider's public_key as a 32-byte AccountId -- a corrupt or
		// pre-migration row should not crash this endpoint.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider has no usable on-chain identity"})
		return
	}
	var account [32]byte
	copy(account[:], publicKey)

	head, err := s.chain.FinalizedHead(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "blockchain status unavailable"})
		return
	}
	header, err := s.chain.HeaderAt(ctx, head)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "blockchain status unavailable"})
		return
	}
	finalizedBlockNumber, err := header.BlockNumber()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "blockchain status unavailable"})
		return
	}
	currentRound := networkvalidator.RoundLength(networkvalidator.DefaultRoundLengthBlocks).Round(finalizedBlockNumber)

	result := ValidatorScores{
		ProviderID:   providerID,
		CurrentRound: currentRound,
		Dimensions:   make([]DimensionScoreHistory, len(validatorScoreDimensions)),
	}

	// One dimension's lookback scan is a sequence of independent
	// point reads, so the 5 dimensions run concurrently -- otherwise
	// this endpoint's worst case is 5 * validatorScoreLookbackRounds
	// sequential RPC round trips.
	var partial sync.Mutex
	var wg sync.WaitGroup
	for index, dimension := range validatorScoreDimensions {
		wg.Add(1)
		go func(index int, dimension blockchainbridge.ScoreDimension) {
			defer wg.Done()
			history, sawError := s.dimensionScoreHistory(ctx, account, currentRound, dimension)
			result.Dimensions[index] = history
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

func (s *Server) dimensionScoreHistory(ctx context.Context, account [32]byte, currentRound uint64, dimension blockchainbridge.ScoreDimension) (DimensionScoreHistory, bool) {
	history := DimensionScoreHistory{Dimension: dimension.String(), Rounds: []RoundScore{}}
	sawError := false
	for offset := uint64(0); offset <= validatorScoreLookbackRounds && offset <= currentRound; offset++ {
		if len(history.Rounds) >= validatorScoreMaxEntriesPerDimension {
			break
		}
		round := currentRound - offset
		result, found, err := s.chain.FinalizedRoundResult(ctx, account, round, dimension)
		if err != nil {
			sawError = true
			continue
		}
		if !found {
			continue
		}
		history.Rounds = append(history.Rounds, RoundScore{
			Round:            round,
			ScoreBps:         result.ScoreBps,
			PreviousScoreBps: result.PreviousScoreBps,
			Submissions:      result.Submissions,
			CommitteeTarget:  result.CommitteeTarget,
			ConfidenceBps:    result.ConfidenceBps(),
			ClosedAt:         result.ClosedAt,
			Status:           result.Status.String(),
		})
	}
	return history, sawError
}
