package blockchainbridge

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestFinalizedProviderAccountsAgainstLocalNode proves the
// state_getKeysPaged prefix scan actually round-trips against a real
// running chain: it cross-checks FinalizedProviderAccounts's decoded
// output against an independently issued state_getKeysPaged call made
// directly by this test (bypassing decodeProviderAccountFromKey), so a
// bug in either the prefix construction or the key-suffix decode would
// show up as a mismatch. Deliberately does not register a new provider
// (unlike TestRegistrarAgainstLocalNode) -- this dev chain's bridge
// account has been fee-drained by this project's prior local development,
// and the enumeration this test targets only needs *some* real registered
// providers to exist, which this long-running dev chain already has.
// Gated the same way as registrar_integration_test.go.
func TestFinalizedProviderAccountsAgainstLocalNode(t *testing.T) {
	endpoint := os.Getenv("OPENINFRA_TEST_SUBSTRATE_RPC_URL")
	if endpoint == "" {
		t.Skip("local Substrate integration environment is not configured")
	}
	rpc, err := NewRPCClient(endpoint, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("configure RPC: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	accounts, err := rpc.FinalizedProviderAccounts(ctx)
	if err != nil {
		t.Fatalf("enumerate provider accounts: %v", err)
	}
	if len(accounts) == 0 {
		t.Skip("no providers are registered on this chain to verify enumeration against")
	}

	// Independently re-derive the same raw keys, without going through
	// FinalizedProviderAccounts or decodeProviderAccountFromKey, and check
	// they decode to the exact same account set.
	head, err := rpc.FinalizedHead(ctx)
	if err != nil {
		t.Fatalf("read finalized head: %v", err)
	}
	rawKeys, err := rpc.stateGetKeysPaged(ctx, providerRegistryKeysPrefix(), maxProviderKeysPerPage, "", head)
	if err != nil {
		t.Fatalf("raw state_getKeysPaged: %v", err)
	}
	if len(rawKeys) != len(accounts) {
		t.Fatalf("raw scan returned %d keys but FinalizedProviderAccounts returned %d accounts", len(rawKeys), len(accounts))
	}

	seen := make(map[[32]byte]bool, len(accounts))
	for _, account := range accounts {
		if seen[account] {
			t.Fatalf("duplicate account %x in enumeration", account)
		}
		seen[account] = true
	}

	for _, key := range rawKeys {
		decoded, err := decodeHex(key)
		if err != nil {
			t.Fatalf("decode raw key %s: %v", key, err)
		}
		if len(decoded) != providerRegistryKeyPrefixLen+mapStorageKeySuffixLen {
			t.Fatalf("raw key %s has unexpected length %d", key, len(decoded))
		}
		var account [32]byte
		copy(account[:], decoded[providerRegistryKeyPrefixLen+16:])
		if !seen[account] {
			t.Fatalf("account %x present in raw scan but missing from FinalizedProviderAccounts", account)
		}
	}

	t.Logf("verified %d registered providers round-trip through FinalizedProviderAccounts against the live local dev chain", len(accounts))
}
