package dashboard

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// maxProviderIDLength bounds the path parameter against an oversized
// value before it ever reaches a query -- provider_id is a lowercase
// hex sha256 digest (64 characters) in every real caller, so this is a
// generous ceiling, not a tight fit.
const maxProviderIDLength = 128

// agentEndpoint is ADR-013 slice 2: an independently operated Network
// Validator has no on-chain way to learn a provider's Agent network
// address (pallet-provider-registry stores only owner/public_key/status,
// never an endpoint) -- this is the missing piece. Deliberately
// unauthenticated: the same data already renders in the public
// /api/v1/overview provider list, so this is not a new trust boundary,
// only a narrower, single-provider lookup shaped for a validator's
// challenge loop. Rate-limited by caller IP like the auth endpoints,
// since -- unlike /api/v1/overview -- callers can probe it once per
// provider_id guess.
func (s *Server) agentEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "agent-endpoint") {
		return
	}
	providerID := r.PathValue("provider_id")
	if providerID == "" || len(providerID) > maxProviderIDLength {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id is required and bounded"})
		return
	}
	var endpoint string
	var publicKey []byte
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(agent_endpoint,''), public_key FROM providers WHERE provider_id=$1`, providerID).Scan(&endpoint, &publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider lookup unavailable"})
		return
	}
	if endpoint == "" {
		// A provider that joined before migration 000003, or whose Agent
		// never advertised an endpoint -- distinct from "doesn't exist"
		// but equally unreachable, so the same 404 applies.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider has no advertised agent endpoint"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"agent_endpoint": endpoint, "public_key": hex.EncodeToString(publicKey)})
}
