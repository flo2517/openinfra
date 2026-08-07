package networkvalidator

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// endpointLookupTimeout bounds the dashboard HTTP round trip. This is a
// discovery step, not the challenge itself -- kept short so one
// unreachable dashboard doesn't stall an entire polling tick.
const endpointLookupTimeout = 5 * time.Second

// AgentEndpoint is the dashboard's ADR-013 §2
// GET /api/v1/agent-endpoint/{provider_id} response, decoded.
type AgentEndpoint struct {
	AgentEndpoint string
	PublicKey     ed25519.PublicKey
}

// EndpointResolver looks up a provider's Agent network address and
// identity key through the Control Plane dashboard's unauthenticated,
// rate-limited discovery endpoint (internal/dashboard/agentendpoint.go).
// This is the piece ADR-013's Context section identifies as previously
// missing entirely: pallet-provider-registry stores no endpoint, so an
// independently operated validator has no other way to learn it.
type EndpointResolver struct {
	baseURL string
	http    *http.Client
}

// NewEndpointResolver validates baseURL once at construction (an http/
// https URL with a host) rather than on every lookup.
func NewEndpointResolver(baseURL string) (*EndpointResolver, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse dashboard base URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("dashboard base URL %q must be an absolute http(s) URL", baseURL)
	}
	return &EndpointResolver{baseURL: parsed.String(), http: &http.Client{Timeout: endpointLookupTimeout}}, nil
}

// Resolve fetches {agent_endpoint, public_key} for providerID (the
// lowercase-hex sha256(public_key) identifier used throughout this
// codebase -- see internal/providerjoin/service.go's ProviderID
// derivation, which this matches exactly: not invented separately here).
// A 404 (unknown provider, or a provider with no advertised endpoint --
// the dashboard endpoint does not distinguish the two, see its own doc
// comment) is reported as a plain error; callers in the challenge loop
// should treat it as "cannot challenge this provider this tick" rather
// than a fatal condition.
func (resolver *EndpointResolver) Resolve(ctx context.Context, providerID string) (AgentEndpoint, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, endpointLookupTimeout)
	defer cancel()
	target := resolver.baseURL + "/api/v1/agent-endpoint/" + url.PathEscape(providerID)
	request, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, target, nil)
	if err != nil {
		return AgentEndpoint{}, fmt.Errorf("build agent-endpoint request: %w", err)
	}
	response, err := resolver.http.Do(request)
	if err != nil {
		return AgentEndpoint{}, fmt.Errorf("call agent-endpoint discovery: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return AgentEndpoint{}, fmt.Errorf("read agent-endpoint response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return AgentEndpoint{}, fmt.Errorf("agent-endpoint discovery for provider %s returned HTTP %d: %s", providerID, response.StatusCode, body)
	}
	var decoded struct {
		AgentEndpoint string `json:"agent_endpoint"`
		PublicKey     string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return AgentEndpoint{}, fmt.Errorf("decode agent-endpoint response: %w", err)
	}
	publicKey, err := hex.DecodeString(decoded.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return AgentEndpoint{}, fmt.Errorf("agent-endpoint discovery for provider %s returned an invalid public key", providerID)
	}
	if decoded.AgentEndpoint == "" {
		return AgentEndpoint{}, fmt.Errorf("agent-endpoint discovery for provider %s returned an empty endpoint", providerID)
	}
	return AgentEndpoint{AgentEndpoint: decoded.AgentEndpoint, PublicKey: publicKey}, nil
}
