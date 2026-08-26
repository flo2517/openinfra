package userauth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention
// workloadapi.newCapacityTestPool uses -- safe to run against the local
// dev stack's Postgres.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "userauth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	return ctx, pool
}

func TestAuthenticateAcceptsAFreshlyIssuedKey(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if key.Raw == "" {
		t.Fatal("expected a raw key to be returned at creation time")
	}

	got, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil {
		t.Fatalf("Authenticate() with a valid key: %v", err)
	}
	if got.UserID != user.UserID {
		t.Fatalf("Authenticate() resolved user %q, want %q", got.UserID, user.UserID)
	}
}

func TestAuthenticateRejectsAnUnknownKey(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	_, err := repository.Authenticate(ctx, userauth.HashAPIKey("oiu_never-issued"))
	if err != userauth.ErrInvalidKey {
		t.Fatalf("Authenticate() with an unknown key = %v, want ErrInvalidKey", err)
	}
}

func TestAuthenticateRejectsARevokedKey(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeAPIKey(ctx, key.KeyID); err != nil {
		t.Fatalf("RevokeAPIKey(): %v", err)
	}

	if _, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw)); err != userauth.ErrInvalidKey {
		t.Fatalf("Authenticate() with a revoked key = %v, want ErrInvalidKey", err)
	}
	if err := repository.RevokeAPIKey(ctx, key.KeyID); err != userauth.ErrInvalidKey {
		t.Fatalf("RevokeAPIKey() on an already-revoked key = %v, want ErrInvalidKey (not silently succeed twice)", err)
	}
}

func TestAuthenticateRejectsAnExpiredKey(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "carol")
	if err != nil {
		t.Fatal(err)
	}
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	// CreateAPIKey never sets expires_at; simulate an already-expired key
	// directly, the same way a future "issue a time-boxed key" admin path
	// would set it.
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE key_id = $1`, key.KeyID); err != nil {
		t.Fatal(err)
	}

	if _, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw)); err != userauth.ErrInvalidKey {
		t.Fatalf("Authenticate() with an expired key = %v, want ErrInvalidKey", err)
	}
}

func TestAuthenticateIsUnaffectedByAnotherKeysHash(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	userA, err := repository.CreateUser(ctx, "dave")
	if err != nil {
		t.Fatal(err)
	}
	userB, err := repository.CreateUser(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	keyA, err := repository.CreateAPIKey(ctx, userA.UserID)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := repository.CreateAPIKey(ctx, userB.UserID)
	if err != nil {
		t.Fatal(err)
	}

	gotA, err := repository.Authenticate(ctx, userauth.HashAPIKey(keyA.Raw))
	if err != nil || gotA.UserID != userA.UserID {
		t.Fatalf("Authenticate(keyA) = %+v, %v, want user %q", gotA, err, userA.UserID)
	}
	gotB, err := repository.Authenticate(ctx, userauth.HashAPIKey(keyB.Raw))
	if err != nil || gotB.UserID != userB.UserID {
		t.Fatalf("Authenticate(keyB) = %+v, %v, want user %q", gotB, err, userB.UserID)
	}
}

// TestCreateUserDefaultsToTenantRole pins ADR-016's fail-closed default:
// a brand new user (created via controlplane-admin, or -- though not
// exercised by this test directly -- auto-provisioned by wallet login,
// which shares the same DEFAULT 'tenant' at the schema level) never
// starts as an operator.
func TestCreateUserDefaultsToTenantRole(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != userauth.RoleTenant {
		t.Fatalf("CreateUser().Role = %q, want %q", user.Role, userauth.RoleTenant)
	}

	// Confirm the persisted row agrees with CreateUser's own return value
	// -- not just that the Go struct says "tenant", but that Authenticate
	// (a separate query, going through the actual users.role column) also
	// reports it.
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.Role != userauth.RoleTenant {
		t.Fatalf("Authenticate().Role = %q, want %q", authenticated.Role, userauth.RoleTenant)
	}
}

func TestSetRoleGrantsAndRevokesOperator(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	if err := repository.SetRole(ctx, user.UserID, userauth.RoleOperatorAdmin); err != nil {
		t.Fatalf("SetRole(operator_admin): %v", err)
	}
	promoted, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Role != userauth.RoleOperatorAdmin {
		t.Fatalf("Role after grant = %q, want %q", promoted.Role, userauth.RoleOperatorAdmin)
	}

	// The grant path is also the revoke path -- setting back to tenant
	// is not a separate method, matching ADR-016 §4's
	// `grant-role <user-id> tenant` CLI usage.
	if err := repository.SetRole(ctx, user.UserID, userauth.RoleTenant); err != nil {
		t.Fatalf("SetRole(tenant): %v", err)
	}
	demoted, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if demoted.Role != userauth.RoleTenant {
		t.Fatalf("Role after revoke = %q, want %q", demoted.Role, userauth.RoleTenant)
	}
}

func TestSetRoleReportsUserNotFoundForAnUnknownUserID(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	err := repository.SetRole(ctx, uuid.NewString(), userauth.RoleOperatorAdmin)
	if err != userauth.ErrUserNotFound {
		t.Fatalf("SetRole() for an unknown user = %v, want ErrUserNotFound", err)
	}
}

// TestSetRoleRejectsAnInvalidRoleAtTheDatabaseConstraint proves the CHECK
// constraint is the real backstop (SetRole's own doc comment says it
// deliberately does not duplicate ValidRole's check) -- an invalid value
// must fail loudly, not silently write something the schema doesn't
// allow.
// TestCreateAPIKeyForProjectRoundTripsTheScope pins ADR-031 §3's
// Keystone-token bridge at the storage layer: a project-scoped key
// authenticates to the same user AuthenticateScoped resolved, and the
// scope survives the round trip through Postgres, not just the returned
// Go struct.
func TestCreateAPIKeyForProjectRoundTripsTheScope(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	projectID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects (project_id, name) VALUES ($1,$2)`, projectID, "alpha-"+projectID); err != nil {
		t.Fatal(err)
	}

	key, err := repository.CreateAPIKeyForProject(ctx, user.UserID, projectID, nil)
	if err != nil {
		t.Fatalf("CreateAPIKeyForProject(): %v", err)
	}
	if key.ProjectID == nil || *key.ProjectID != projectID {
		t.Fatalf("CreateAPIKeyForProject().ProjectID = %v, want %q", key.ProjectID, projectID)
	}

	gotUser, gotProject, err := repository.AuthenticateScoped(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil {
		t.Fatalf("AuthenticateScoped(): %v", err)
	}
	if gotUser.UserID != user.UserID {
		t.Fatalf("AuthenticateScoped() resolved user %q, want %q", gotUser.UserID, user.UserID)
	}
	if gotProject == nil || *gotProject != projectID {
		t.Fatalf("AuthenticateScoped() project = %v, want %q", gotProject, projectID)
	}

	// Authenticate (the unscoped entry point every other caller uses)
	// still succeeds against the same key -- a scoped key is a strict
	// superset of an unscoped one, not a different credential type.
	plainUser, err := repository.Authenticate(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil || plainUser.UserID != user.UserID {
		t.Fatalf("Authenticate() on a scoped key = %+v, %v, want user %q", plainUser, err, user.UserID)
	}
}

// TestAuthenticateScopedReportsNoScopeForAnUnscopedKey proves the
// pre-existing unscoped path (CreateAPIKey/CreateAPIKeyWithExpiry) is
// unaffected by the new column: its keys resolve with a nil project.
func TestAuthenticateScopedReportsNoScopeForAnUnscopedKey(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	_, projectID, err := repository.AuthenticateScoped(ctx, userauth.HashAPIKey(key.Raw))
	if err != nil {
		t.Fatalf("AuthenticateScoped(): %v", err)
	}
	if projectID != nil {
		t.Fatalf("AuthenticateScoped() project = %v, want nil (unscoped key)", projectID)
	}
}

// TestRevokeAPIKeyByHashRevokesAndIsNotReplayable is the same
// "revoke, then confirm rejected, then confirm double-revoke reports
// ErrInvalidKey" shape TestAuthenticateRejectsARevokedKey already proves
// for RevokeAPIKey(keyID) -- this is the hash-addressed variant
// internal/openstackapi/keystone's token-delete bridge needs, since a
// client presenting a token for revocation never knows its key_id.
func TestRevokeAPIKeyByHashRevokesAndIsNotReplayable(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	key, err := repository.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	hash := userauth.HashAPIKey(key.Raw)

	if err := repository.RevokeAPIKeyByHash(ctx, hash); err != nil {
		t.Fatalf("RevokeAPIKeyByHash(): %v", err)
	}
	if _, err := repository.Authenticate(ctx, hash); err != userauth.ErrInvalidKey {
		t.Fatalf("Authenticate() after RevokeAPIKeyByHash = %v, want ErrInvalidKey", err)
	}
	if err := repository.RevokeAPIKeyByHash(ctx, hash); err != userauth.ErrInvalidKey {
		t.Fatalf("RevokeAPIKeyByHash() on an already-revoked key = %v, want ErrInvalidKey (not silently succeed twice)", err)
	}
}

func TestRevokeAPIKeyByHashRejectsAnUnknownHash(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	var neverIssued [32]byte
	if err := repository.RevokeAPIKeyByHash(ctx, neverIssued); err != userauth.ErrInvalidKey {
		t.Fatalf("RevokeAPIKeyByHash() for an unknown hash = %v, want ErrInvalidKey", err)
	}
}

func TestSetRoleRejectsAnInvalidRoleAtTheDatabaseConstraint(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := userauth.NewPostgresRepository(pool)

	user, err := repository.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.SetRole(ctx, user.UserID, "admin"); err == nil {
		t.Fatal("expected SetRole with an invalid role to fail against the CHECK constraint")
	}
}
