package userauth_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention
// workloadapi.newCapacityTestPool uses -- safe to run against the local
// dev stack's Postgres.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("OPENINFRA_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("OPENINFRA_TEST_DATABASE_URL is not set")
	}
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
