// Command controlplane-admin is operator tooling for privileged actions
// that need the Control Plane's own credentials rather than an ordinary
// user's or validator's:
//
//   - User/API-key management (issue #12): there is deliberately no
//     self-service user registration RPC (that would be a much larger
//     surface -- verification, abuse prevention -- out of scope for a
//     tenancy MVP), so creating a user and issuing their first API key is
//     a local/offline Postgres operation. The raw API key is printed
//     exactly once, to stdout, and never persisted anywhere (only its
//     SHA-256 hash lives in Postgres) -- copy it immediately; there is no
//     way to recover it later, only to revoke it and issue a new one.
//   - grant-role (ADR-016 §4, issue #76): the only way a user becomes a
//     dashboard operator (or is demoted back to tenant). Same trust
//     boundary as create-user/issue-key -- there is no self-service way
//     for a user to grant themselves elevated dashboard access.
//   - resolve-dispute (ADR-013 slice 5, issue #78): pallet-network-
//     validator's resolve_dispute extrinsic is SuspensionOrigin-gated
//     (EnsureRoot in this runtime) -- only the Control Plane's own
//     bridge/sudo account can call it, the same governance trust
//     boundary provider registration's EnsureActive already uses. This is
//     why it lives here and not in cmd/networkvalidator, which
//     deliberately only ever signs with an ordinary validator's own
//     account.
//   - revoke-provider (ADR-027 §4, issue #13): the only way a provider's
//     status becomes REVOKED -- immediate scheduling exclusion (the
//     existing providers.status = ACTIVE scheduling filter, no new
//     mechanism) plus, within one internal/pki.Reconciler sweep interval,
//     rejected mTLS connectivity. Same break-glass trust boundary as
//     grant-role: there is no self-service or automated way for a
//     provider to be revoked or to un-revoke itself.
//   - fund-account (local dev bootstrap only): the Control Plane's own
//     bridge/sudo account is the sole account endowed at genesis
//     (blockchain/node/src/chain_spec.rs); a freshly generated Network
//     Validator signing key starts at zero balance and cannot satisfy
//     register_validator's stake reservation without first receiving a
//     transfer from that endowed account. Used by
//     deployments/scripts/bootstrap-network-validators.sh, never by
//     cmd/networkvalidator itself, which deliberately only ever signs
//     with an ordinary validator's own account.
//
// Each subcommand only connects to the credential store it actually
// needs -- user/API-key/role commands never touch the chain,
// resolve-dispute and fund-account never touch Postgres.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/providerjoin"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "controlplane-admin:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	ctx := context.Background()

	switch args[0] {
	case "create-user", "issue-key", "revoke-key", "grant-role":
		return runUserCommand(ctx, args)
	case "revoke-provider":
		return runRevokeProvider(ctx, args)
	case "resolve-dispute":
		return runResolveDispute(ctx, args)
	case "fund-account":
		return runFundAccount(ctx, args)
	default:
		return usageError()
	}
}

// runRevokeProvider is ADR-027 §4's break-glass revocation path -- see the
// package doc comment. A direct Postgres write, the same operational
// shape as create-user/issue-key/revoke-key/grant-role above: an offline
// operation requiring this binary's own DATABASE_URL access, never a
// self-service RPC.
func runRevokeProvider(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: controlplane-admin revoke-provider <provider-id>")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		return fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	repository := providerjoin.NewPostgresRepository(pool)
	if err := repository.RevokeProvider(ctx, args[1]); err != nil {
		return fmt.Errorf("revoke provider: %w", err)
	}
	fmt.Printf("provider %s is now REVOKED -- excluded from scheduling immediately, mTLS connectivity cut within one revocation-reconciliation interval\n", args[1])
	return nil
}

func runUserCommand(ctx context.Context, args []string) error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		return fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	repository := userauth.NewPostgresRepository(pool)

	switch args[0] {
	case "create-user":
		if len(args) != 2 {
			return errors.New("usage: controlplane-admin create-user <display-name>")
		}
		return createUser(ctx, repository, args[1])
	case "issue-key":
		if len(args) != 2 {
			return errors.New("usage: controlplane-admin issue-key <user-id>")
		}
		return issueKey(ctx, repository, args[1])
	case "revoke-key":
		if len(args) != 2 {
			return errors.New("usage: controlplane-admin revoke-key <key-id>")
		}
		if err := repository.RevokeAPIKey(ctx, args[1]); err != nil {
			return fmt.Errorf("revoke key: %w", err)
		}
		fmt.Println("revoked")
		return nil
	case "grant-role":
		if len(args) != 3 {
			return errors.New("usage: controlplane-admin grant-role <user-id> <tenant|operator_readonly|operator_admin>")
		}
		return grantRole(ctx, repository, args[1], args[2])
	}
	return usageError()
}

func createUser(ctx context.Context, repository *userauth.PostgresRepository, displayName string) error {
	user, err := repository.CreateUser(ctx, displayName)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	fmt.Println("user_id:", user.UserID)
	return issueKey(ctx, repository, user.UserID)
}

func issueKey(ctx context.Context, repository *userauth.PostgresRepository, userID string) error {
	key, err := repository.CreateAPIKey(ctx, userID)
	if err != nil {
		return fmt.Errorf("create API key: %w", err)
	}
	fmt.Println("key_id:", key.KeyID)
	fmt.Println("api_key:", key.Raw, "  (shown once -- store it now; only its hash is kept)")
	return nil
}

// grantRole is ADR-016 §4's break-glass grant path: the only way a user
// becomes (or stops being) a dashboard operator. Deliberately the same
// operational shape as create-user/issue-key/revoke-key -- an offline
// Postgres write requiring this binary's own DATABASE_URL access, not a
// self-service RPC a logged-in user could call on themselves or anyone
// else.
func grantRole(ctx context.Context, repository *userauth.PostgresRepository, userID, role string) error {
	if !userauth.ValidRole(role) {
		return fmt.Errorf("%q must be exactly %q, %q, or %q", role, userauth.RoleTenant, userauth.RoleOperatorReadOnly, userauth.RoleOperatorAdmin)
	}
	if err := repository.SetRole(ctx, userID, role); err != nil {
		return fmt.Errorf("grant role: %w", err)
	}
	fmt.Printf("user %s is now role=%s\n", userID, role)
	return nil
}

// runResolveDispute settles a dispute pallet-network-validator's
// resolve_dispute -- see the package doc comment for why this, uniquely
// among this session's Network Validator tooling, must run with the
// Control Plane's own bridge/sudo credentials rather than a validator's.
func runResolveDispute(ctx context.Context, args []string) error {
	if len(args) != 5 {
		return errors.New("usage: controlplane-admin resolve-dispute <provider-hex> <round> <dimension> <uphold|reject>")
	}
	rpcURL := os.Getenv("SUBSTRATE_RPC_URL")
	if rpcURL == "" {
		return errors.New("SUBSTRATE_RPC_URL is required")
	}
	signerKeyFile := os.Getenv("SUBSTRATE_SIGNER_KEY_FILE")
	if signerKeyFile == "" {
		return errors.New("SUBSTRATE_SIGNER_KEY_FILE is required (the Control Plane's own bridge/sudo key -- resolve_dispute is SuspensionOrigin-gated, an ordinary validator's key cannot call it)")
	}
	provider, err := parseAccountHex(args[1])
	if err != nil {
		return fmt.Errorf("parse provider: %w", err)
	}
	round, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		return fmt.Errorf("parse round: %w", err)
	}
	dimension, err := blockchainbridge.ParseScoreDimension(args[3])
	if err != nil {
		return err
	}
	uphold, err := parseUpholdOrReject(args[4])
	if err != nil {
		return err
	}

	chain, err := blockchainbridge.NewRPCClient(rpcURL, &http.Client{})
	if err != nil {
		return fmt.Errorf("configure Substrate RPC client: %w", err)
	}
	registrar, err := blockchainbridge.NewRegistrarFromPKCS8File(chain, signerKeyFile)
	if err != nil {
		return fmt.Errorf("configure bridge signer: %w", err)
	}
	if err := registrar.ResolveDispute(ctx, provider, round, dimension, uphold); err != nil {
		return fmt.Errorf("resolve_dispute: %w", err)
	}
	verb := "rejected (round's aggregate re-applied)"
	if uphold {
		verb = "upheld (rollback to the pre-round score kept)"
	}
	fmt.Printf("resolve_dispute submitted for provider=%s round=%d dimension=%s: %s\n", args[1], round, dimension, verb)
	return nil
}

// runFundAccount submits a plain balances transfer from the Control
// Plane's own bridge/sudo account -- the only account endowed at
// genesis -- to dest. Local dev bootstrap only (see the package doc
// comment): gives a freshly generated Network Validator signing key
// enough free balance for it to later call register_validator itself
// with its own key, never sudo-wrapped or run on the validator's behalf.
func runFundAccount(ctx context.Context, args []string) error {
	if len(args) != 3 {
		return errors.New("usage: controlplane-admin fund-account <account-hex> <amount>")
	}
	rpcURL := os.Getenv("SUBSTRATE_RPC_URL")
	if rpcURL == "" {
		return errors.New("SUBSTRATE_RPC_URL is required")
	}
	signerKeyFile := os.Getenv("SUBSTRATE_SIGNER_KEY_FILE")
	if signerKeyFile == "" {
		return errors.New("SUBSTRATE_SIGNER_KEY_FILE is required (the Control Plane's own bridge/sudo key -- the only account endowed at genesis)")
	}
	dest, err := parseAccountHex(args[1])
	if err != nil {
		return fmt.Errorf("parse account: %w", err)
	}
	amount, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		return fmt.Errorf("parse amount: %w", err)
	}

	chain, err := blockchainbridge.NewRPCClient(rpcURL, &http.Client{})
	if err != nil {
		return fmt.Errorf("configure Substrate RPC client: %w", err)
	}
	registrar, err := blockchainbridge.NewRegistrarFromPKCS8File(chain, signerKeyFile)
	if err != nil {
		return fmt.Errorf("configure bridge signer: %w", err)
	}
	if err := registrar.FundAccount(ctx, dest, amount); err != nil {
		return fmt.Errorf("transfer_allow_death: %w", err)
	}
	fmt.Printf("transfer_allow_death submitted: %d to %s\n", amount, args[1])
	return nil
}

func parseAccountHex(value string) ([32]byte, error) {
	var account [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return account, fmt.Errorf("%q is not valid hex: %w", value, err)
	}
	if len(decoded) != 32 {
		return account, fmt.Errorf("%q decodes to %d bytes, want 32", value, len(decoded))
	}
	copy(account[:], decoded)
	return account, nil
}

func parseUpholdOrReject(value string) (bool, error) {
	switch value {
	case "uphold":
		return true, nil
	case "reject":
		return false, nil
	default:
		return false, fmt.Errorf("%q must be exactly \"uphold\" or \"reject\"", value)
	}
}

func usageError() error {
	return errors.New("usage: controlplane-admin <create-user <display-name> | issue-key <user-id> | revoke-key <key-id> | grant-role <user-id> <tenant|operator_readonly|operator_admin> | revoke-provider <provider-id> | resolve-dispute <provider-hex> <round> <dimension> <uphold|reject> | fund-account <account-hex> <amount>>")
}
