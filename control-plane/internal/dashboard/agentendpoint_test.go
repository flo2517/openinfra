package dashboard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

func TestAgentEndpointReturnsTheAdvertisedEndpointAndKey(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	handler := server.Handler()

	publicKey := make([]byte, 32)
	publicKey[0] = 0xAB
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at, agent_endpoint)
		VALUES ('provider-with-endpoint', $1, '1', 'test', $2, 2, now(), 'https://agent.example.invalid:50052')`,
		publicKey, []byte{},
	); err != nil {
		t.Fatal(err)
	}

	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/agent-endpoint/provider-with-endpoint", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		AgentEndpoint string `json:"agent_endpoint"`
		PublicKey     string `json:"public_key"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.AgentEndpoint != "https://agent.example.invalid:50052" {
		t.Fatalf("agent_endpoint = %q", response.AgentEndpoint)
	}
	if response.PublicKey != hex.EncodeToString(publicKey) {
		t.Fatalf("public_key = %q, want %q", response.PublicKey, hex.EncodeToString(publicKey))
	}
}

func TestAgentEndpointReturnsNotFoundForAnUnknownProvider(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()
	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/agent-endpoint/never-registered", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestAgentEndpointReturnsNotFoundWhenNoEndpointWasEverAdvertised(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	handler := server.Handler()
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at)
		VALUES ('provider-without-endpoint', $1, '1', 'test', $2, 2, now())`,
		make([]byte, 32), []byte{},
	); err != nil {
		t.Fatal(err)
	}
	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/agent-endpoint/provider-without-endpoint", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", recorder.Code, recorder.Body.String())
	}
}

// Without a configured Redis client (this test's server, like most of
// this package's, is built with a nil one -- see newAuthTestServer),
// declaredBandwidth must degrade to "nothing to report" rather than
// panicking on a nil-interface method call, and the response must simply
// omit the bandwidth fields (they're omitempty), not zero-value them.
func TestAgentEndpointOmitsBandwidthFieldsWithoutARedisClient(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	handler := server.Handler()

	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at, agent_endpoint)
		VALUES ('provider-no-redis', $1, '1', 'test', $2, 2, now(), 'https://agent.example.invalid:50052')`,
		make([]byte, 32), []byte{},
	); err != nil {
		t.Fatal(err)
	}

	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/agent-endpoint/provider-no-redis", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if _, present := decoded["bandwidth_ingress_mbps"]; present {
		t.Fatalf("expected no bandwidth_ingress_mbps field without a Redis client, got %v", decoded)
	}
	if _, present := decoded["bandwidth_egress_mbps"]; present {
		t.Fatalf("expected no bandwidth_egress_mbps field without a Redis client, got %v", decoded)
	}
}

// With a real Redis-backed heartbeat cache entry present (ADR-015 §5's
// "the same live directory data the scheduler already uses"), the
// agent-endpoint response must surface the provider's declared
// ingress/egress bandwidth -- MeasureBandwidth's tolerance check
// (control-plane/internal/networkvalidator) depends on this field
// actually being populated, not just present-but-zero.
func TestAgentEndpointIncludesDeclaredBandwidthFromTheHeartbeatCache(t *testing.T) {
	redisURL := os.Getenv("OPENINFRA_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("OPENINFRA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })

	ctx, server, pool := newAuthTestServer(t)
	server.redis = client
	handler := server.Handler()

	const providerID = "provider-with-declared-bandwidth"
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at, agent_endpoint)
		VALUES ($1, $2, '1', 'test', $3, 2, now(), 'https://agent.example.invalid:50052')`,
		providerID, make([]byte, 32), []byte{},
	); err != nil {
		t.Fatal(err)
	}

	payload := &heartbeatPayload{
		ProviderId: providerID,
		Capabilities: &sharedv1.ResourceCapability{
			Bandwidth: &sharedv1.Bandwidth{IngressMbps: 750, EgressMbps: 400},
		},
	}
	encoded, err := proto.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	heartbeatKey := "openinfra:heartbeat:" + providerID
	if err := client.HSet(ctx, heartbeatKey, "payload", encoded).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Del(context.Background(), heartbeatKey).Err() })

	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/agent-endpoint/"+providerID, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		BandwidthIngressMbps int32 `json:"bandwidth_ingress_mbps"`
		BandwidthEgressMbps  int32 `json:"bandwidth_egress_mbps"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.BandwidthIngressMbps != 750 {
		t.Fatalf("bandwidth_ingress_mbps = %d, want 750", response.BandwidthIngressMbps)
	}
	if response.BandwidthEgressMbps != 400 {
		t.Fatalf("bandwidth_egress_mbps = %d, want 400", response.BandwidthEgressMbps)
	}
}

func TestAgentEndpointRejectsAnOversizedProviderID(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()
	oversized := make([]byte, 200)
	for i := range oversized {
		oversized[i] = 'a'
	}
	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/agent-endpoint/"+string(oversized), nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}
