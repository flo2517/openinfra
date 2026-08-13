package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/walletlogin"
	"github.com/openinfra/network/migrations"
)

// newValidatorScoresTestServer is newAuthTestServer's sibling: it also
// needs a real chain client, since validatorScores (unlike the auth
// endpoints) reads pallet-network-validator directly. Gated on both
// Postgres and Substrate integration environment variables -- this test
// is skipped, not failed, when either is absent, matching every other
// live-chain test in this codebase.
func newValidatorScoresTestServer(t *testing.T) (context.Context, *Server, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	rpcURL := os.Getenv("OPENINFRA_TEST_SUBSTRATE_RPC_URL")
	if rpcURL == "" {
		t.Skip("OPENINFRA_TEST_SUBSTRATE_RPC_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "dashboard_validator_scores_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)) })

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}

	chain, err := blockchainbridge.NewRPCClient(rpcURL, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	users := userauth.NewPostgresRepository(pool)
	wallet := walletlogin.NewService(walletlogin.NewPostgresRepository(pool), users)
	server := New(pool, nil, chain, wallet, users, nil) // nil redis/limiter: unused by this endpoint under test
	return ctx, server, pool
}

func TestValidatorScoresReturnsNotFoundForAnUnknownProvider(t *testing.T) {
	_, server, _ := newValidatorScoresTestServer(t)
	handler := server.Handler()
	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/validator-scores/never-registered", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestValidatorScoresRejectsAnOversizedProviderID(t *testing.T) {
	_, server, _ := newValidatorScoresTestServer(t)
	handler := server.Handler()
	oversized := strings.Repeat("a", 200)
	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/validator-scores/"+oversized, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

// TestValidatorScoresReturnsEveryDimensionWithEmptyHistoryAgainstALiveChain
// proves the whole read path -- provider lookup, finalized-head read,
// round derivation, and a concurrent per-dimension NMap scan -- against a
// real running chain. As documented throughout this session, the local
// dev chain's wasm predates pallet-network-validator, so no round can
// genuinely have closed; this test pins the resulting shape (every
// dimension present, each with an empty Rounds list, Partial false since
// "not found" is not an error) rather than a real score, which is still
// the overwhelmingly common response shape for a provider a validator
// hasn't scored yet.
func TestValidatorScoresReturnsEveryDimensionWithEmptyHistoryAgainstALiveChain(t *testing.T) {
	ctx, server, pool := newValidatorScoresTestServer(t)
	handler := server.Handler()

	publicKey := make([]byte, 32)
	publicKey[0] = 0xCD
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at)
		VALUES ('provider-under-test', $1, '1', 'test', $2, 2, now())`,
		publicKey, []byte{},
	); err != nil {
		t.Fatal(err)
	}

	recorder := doJSON(t, handler, http.MethodGet, "/api/v1/validator-scores/provider-under-test", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response ValidatorScores
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ProviderID != "provider-under-test" {
		t.Fatalf("provider_id = %q", response.ProviderID)
	}
	if response.Partial {
		t.Fatal("a round genuinely not found should not mark the response partial")
	}
	if len(response.Dimensions) != len(validatorScoreDimensions) {
		t.Fatalf("dimensions = %d, want %d", len(response.Dimensions), len(validatorScoreDimensions))
	}
	seen := make(map[string]bool, len(response.Dimensions))
	for _, dimension := range response.Dimensions {
		seen[dimension.Dimension] = true
		if len(dimension.Rounds) != 0 {
			t.Fatalf("dimension %s: expected no closed rounds against this chain, got %+v", dimension.Dimension, dimension.Rounds)
		}
	}
	for _, want := range validatorScoreDimensions {
		if !seen[want.String()] {
			t.Fatalf("missing dimension %s in response", want.String())
		}
	}
}

// The len(publicKey) != ed25519.PublicKeySize branch in validatorScores is
// defense in depth, not independently testable through a real insert: the
// providers table's own CHECK (octet_length(public_key) = 32) constraint
// (migrations/000001_provider_join.sql) already makes a short key
// unreachable at this layer -- the identical situation as loadOverview's
// matching check in dashboard.go.
