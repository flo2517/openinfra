package walletlogin_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/walletlogin"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention userauth/workloadapi's
// own Postgres integration tests use.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "walletlogin_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

func randomAccount(t *testing.T) [32]byte {
	t.Helper()
	var account [32]byte
	if _, err := rand.Read(account[:]); err != nil {
		t.Fatal(err)
	}
	return account
}

func TestChallengeLifecycleAgainstRealPostgres(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := walletlogin.NewPostgresRepository(pool)

	var nonce [32]byte
	copy(nonce[:], []byte("0123456789abcdef0123456789abcdef"))
	challengeID := uuid.NewString()
	if err := repository.CreateChallenge(ctx, challengeID, nonce, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	got, err := repository.LiveChallengeNonce(ctx, challengeID)
	if err != nil {
		t.Fatalf("LiveChallengeNonce(): %v", err)
	}
	if got != nonce {
		t.Fatalf("LiveChallengeNonce() = %x, want %x", got, nonce)
	}

	if err := repository.ConsumeChallenge(ctx, challengeID); err != nil {
		t.Fatalf("ConsumeChallenge(): %v", err)
	}
	if _, err := repository.LiveChallengeNonce(ctx, challengeID); err != walletlogin.ErrChallengeNotFound {
		t.Fatalf("LiveChallengeNonce() after consuming = %v, want ErrChallengeNotFound", err)
	}
	if err := repository.ConsumeChallenge(ctx, challengeID); err != walletlogin.ErrChallengeNotFound {
		t.Fatalf("ConsumeChallenge() a second time = %v, want ErrChallengeNotFound (single-use)", err)
	}
}

func TestLiveChallengeNonceRejectsAnExpiredChallenge(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := walletlogin.NewPostgresRepository(pool)

	var nonce [32]byte
	challengeID := uuid.NewString()
	if err := repository.CreateChallenge(ctx, challengeID, nonce, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.LiveChallengeNonce(ctx, challengeID); err != walletlogin.ErrChallengeNotFound {
		t.Fatalf("LiveChallengeNonce() for an expired challenge = %v, want ErrChallengeNotFound", err)
	}
}

func TestFindOrCreateUserByAccountIsIdempotent(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := walletlogin.NewPostgresRepository(pool)
	account := randomAccount(t)

	first, err := repository.FindOrCreateUserByAccount(ctx, account, walletlogin.SchemeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.FindOrCreateUserByAccount(ctx, account, walletlogin.SchemeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("expected the same user on a second login, got %q then %q", first, second)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE user_id = $1`, first).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one users row for %q, got %d", first, count)
	}
}

// TestFindOrCreateUserByAccountConcurrentFirstLoginNeverCreatesTwoUsers is
// the race the advisory lock in FindOrCreateUserByAccount exists for: two
// concurrent first logins for the same never-seen account must resolve to
// exactly one user, never two, and never leave an orphaned users row that
// no wallet_accounts entry points to.
func TestFindOrCreateUserByAccountConcurrentFirstLoginNeverCreatesTwoUsers(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := walletlogin.NewPostgresRepository(pool)
	account := randomAccount(t)

	var wg sync.WaitGroup
	results := make(chan string, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			userID, err := repository.FindOrCreateUserByAccount(ctx, account, walletlogin.SchemeEd25519)
			if err != nil {
				errs <- err
				return
			}
			results <- userID
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("FindOrCreateUserByAccount concurrent call failed: %v", err)
	}
	var userIDs []string
	for id := range results {
		userIDs = append(userIDs, id)
	}
	if len(userIDs) != 2 || userIDs[0] != userIDs[1] {
		t.Fatalf("expected both concurrent calls to resolve to the same user, got %v", userIDs)
	}

	var userCount, walletCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM wallet_accounts WHERE account_id = $1`, account[:]).Scan(&walletCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 1 {
		t.Fatalf("expected exactly one users row after the race, got %d (an orphaned row means the advisory lock didn't serialize the two calls)", userCount)
	}
	if walletCount != 1 {
		t.Fatalf("expected exactly one wallet_accounts row for the account, got %d", walletCount)
	}
}
