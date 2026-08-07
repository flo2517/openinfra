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
	response := agentEndpointResponse{AgentEndpoint: endpoint, PublicKey: hex.EncodeToString(publicKey)}
	if ingressMbps, egressMbps, ok := s.declaredBandwidth(ctx, providerID); ok {
		response.BandwidthIngressMbps = ingressMbps
		response.BandwidthEgressMbps = egressMbps
	}
	writeJSON(w, http.StatusOK, response)
}

// agentEndpointResponse is GET /api/v1/agent-endpoint/{provider_id}'s
// response shape. The bandwidth fields are ADR-015 §5's "the provider's
// own declared ResourceCapability.Bandwidth," added for the Network
// Validator's MeasureBandwidth probe to score against -- omitempty (and
// therefore simply absent, not zero-valued) when declaredBandwidth has
// no fresh capability data for this provider, so a caller can tell
// "nothing to compare against yet" apart from "provider declared 0
// Mbps" (see networkvalidator.AgentEndpoint's doc comment for how the
// caller-side type handles that same distinction).
type agentEndpointResponse struct {
	AgentEndpoint        string `json:"agent_endpoint"`
	PublicKey            string `json:"public_key"`
	BandwidthIngressMbps int32  `json:"bandwidth_ingress_mbps,omitempty"`
	BandwidthEgressMbps  int32  `json:"bandwidth_egress_mbps,omitempty"`
}

// declaredBandwidth reads a provider's most recently heartbeated declared
// bandwidth capacity (ResourceCapability.Bandwidth) from the same Redis
// heartbeat cache the overview endpoint's per-provider capability display
// already reads (openinfra:heartbeat:<provider_id>, decoded via the same
// structHeartbeat this package already uses) -- ADR-015 §5 calls for
// reading "the same live directory data the scheduler already uses," and
// agentmanager's live provider directory (what the scheduler reads) is
// itself backed by this identical heartbeat cache (see
// internal/agentmanager/directory.go's heartbeatKeyPrefix). Deliberately
// does not check the cache entry's TTL/freshness the way the overview
// endpoint's liveness display does: a declared capacity is closer to a
// slow-changing configuration value than a liveness signal, so serving a
// slightly stale declared figure is an acceptable simplification here,
// not a correctness bug -- ok is false only when there is no cached
// capability data to read at all.
func (s *Server) declaredBandwidth(ctx context.Context, providerID string) (ingressMbps, egressMbps int32, ok bool) {
	if s.redis == nil {
		return 0, 0, false
	}
	key := "openinfra:heartbeat:" + providerID
	values, err := s.redis.HMGet(ctx, key, "payload").Result()
	if err != nil || len(values) != 1 || values[0] == nil {
		return 0, 0, false
	}
	payloadBytes, isString := values[0].(string)
	if !isString {
		return 0, 0, false
	}
	var payload structHeartbeat
	if err := payload.Unmarshal([]byte(payloadBytes)); err != nil || payload.ProviderID != providerID {
		return 0, 0, false
	}
	if payload.Capabilities == nil || payload.Capabilities.Bandwidth == nil {
		return 0, 0, false
	}
	return payload.Capabilities.Bandwidth.IngressMbps, payload.Capabilities.Bandwidth.EgressMbps, true
}
