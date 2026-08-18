package dashboard

import (
	"context"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// ProviderEarnings is a provider's Reward Point balance from
// pallet-rewards. Available separates "the chain answered" from "we could
// not ask": pallet-rewards declares RewardBalances with ValueQuery, so a
// provider that has never been credited has no storage entry and reads
// back as a legitimate 0. Rendering a failed read as 0 would tell a
// provider it has earned nothing, which is a different and much worse
// claim than "unknown".
type ProviderEarnings struct {
	Available    bool   `json:"available"`
	RewardPoints uint64 `json:"reward_points"`
}

// ProviderProof is the provider's most recent availability proof from
// pallet-availability. Two distinct negatives, deliberately not collapsed:
// Available=false means the read failed, Found=false means the read
// succeeded and this provider has simply never submitted a proof (normal
// for a freshly joined provider).
type ProviderProof struct {
	Available         bool   `json:"available"`
	Found             bool   `json:"found"`
	Sequence          uint64 `json:"sequence,omitempty"`
	ObservedAtBlock   uint32 `json:"observed_at_block,omitempty"`
	SuccessfulSamples uint32 `json:"successful_samples,omitempty"`
	TotalSamples      uint32 `json:"total_samples,omitempty"`
	AvailabilityBps   uint16 `json:"availability_bps,omitempty"`
	PayloadHash       string `json:"payload_hash,omitempty"`
}

// ProviderOnChain is GET /api/v1/provider/{provider_id}/onchain's response
// body: the two provider-view items from #14 that had no data path at all
// until now (earnings and proofs), read at one pinned block so they
// describe the same chain state rather than two moments a round trip
// apart.
type ProviderOnChain struct {
	ProviderID     string           `json:"provider_id"`
	GeneratedAt    string           `json:"generated_at"`
	FinalizedBlock string           `json:"finalized_block_hash"`
	Earnings       ProviderEarnings `json:"earnings"`
	Proof          ProviderProof    `json:"proof"`
	// Partial is true when either read failed, so a client can warn once
	// rather than having to notice a false Available on each section.
	Partial bool `json:"partial"`
}

// providerOnChain serves a provider's Reward Point balance and latest
// availability proof.
//
// Ungated, like /api/v1/validator-scores/{provider_id} and the reputation
// and offer figures already on the public overview: every value here is
// finalized consensus state that anyone can read straight off the node's
// RPC. Gating it would protect nothing while implying a confidentiality
// the chain does not provide. It is rate-limited, because each call is
// real chain I/O.
func (s *Server) providerOnChain(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "provider-onchain") {
		return
	}
	providerID := r.PathValue("provider_id")
	account, ok := s.providerOnChainAccount(ctx, w, providerID)
	if !ok {
		return
	}

	// One head for both reads: earnings and the latest proof shown side
	// by side should be the same block's view, not two.
	head, err := s.chain.FinalizedHead(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "blockchain status unavailable"})
		return
	}

	result := ProviderOnChain{
		ProviderID:     providerID,
		GeneratedAt:    s.now().UTC().Format(time.RFC3339),
		FinalizedBlock: head,
	}

	// Two independent point reads against the same block: run them
	// concurrently rather than paying both round trips in sequence, the
	// same shape validatorScores uses for its per-dimension scans.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		points, err := s.chain.ProviderRewardPoints(ctx, account, head)
		if err != nil {
			return
		}
		result.Earnings = ProviderEarnings{Available: true, RewardPoints: points}
	}()
	go func() {
		defer wg.Done()
		summary, found, err := s.chain.ProviderLatestProof(ctx, account, head)
		if err != nil {
			return
		}
		proof := ProviderProof{Available: true, Found: found}
		if found {
			proof.Sequence = summary.Sequence
			proof.ObservedAtBlock = summary.ObservedAt
			proof.SuccessfulSamples = summary.SuccessfulSamples
			proof.TotalSamples = summary.TotalSamples
			proof.AvailabilityBps = summary.AvailabilityBps
			proof.PayloadHash = hex.EncodeToString(summary.PayloadHash[:])
		}
		result.Proof = proof
	}()
	wg.Wait()

	// The proof's signature is deliberately not surfaced. pallet-
	// availability verified it at submission; re-publishing it here would
	// invite a second, divergent verification path against a different
	// key source, and the payload hash is what actually identifies which
	// measurement was attested.
	result.Partial = !result.Earnings.Available || !result.Proof.Available

	writeJSON(w, http.StatusOK, result)
}
