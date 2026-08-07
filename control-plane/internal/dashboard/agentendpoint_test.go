package dashboard

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
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
