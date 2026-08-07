package walletlogin

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) CreateChallenge(ctx context.Context, challengeID string, nonce [32]byte, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO user_login_challenges (challenge_id, nonce, expires_at) VALUES ($1,$2,$3)`, challengeID, nonce[:], expiresAt)
	return err
}

func (r *PostgresRepository) LiveChallengeNonce(ctx context.Context, challengeID string) ([32]byte, error) {
	var nonce []byte
	err := r.pool.QueryRow(ctx, `SELECT nonce FROM user_login_challenges WHERE challenge_id=$1 AND consumed_at IS NULL AND expires_at > now()`, challengeID).Scan(&nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, ErrChallengeNotFound
	}
	if err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	if len(nonce) != 32 {
		return [32]byte{}, errors.New("stored challenge nonce has an unexpected length")
	}
	copy(result[:], nonce)
	return result, nil
}

func (r *PostgresRepository) ConsumeChallenge(ctx context.Context, challengeID string) error {
	command, err := r.pool.Exec(ctx, `UPDATE user_login_challenges SET consumed_at = now() WHERE challenge_id=$1 AND consumed_at IS NULL AND expires_at > now()`, challengeID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrChallengeNotFound
	}
	return nil
}

// FindOrCreateUserByAccount serializes its own check-then-create critical
// section with a transaction-scoped Postgres advisory lock keyed by the
// account, so two concurrent first logins for the same never-seen account
// can never both decide "I'm first" and each create their own users row
// -- one would win, the other's INSERT would violate wallet_accounts'
// primary key, and without the lock that race is exactly the kind of
// thing that only shows up under real concurrency, not in a
// single-request test. (See internal/workloadapi.AssignLease's doc
// comment for the same reasoning applied to a different resource.)
func (r *PostgresRepository) FindOrCreateUserByAccount(ctx context.Context, account [32]byte, scheme Scheme) (string, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	lockKey := int64(binary.LittleEndian.Uint64(account[:8])) //nolint:gosec // advisory lock key, not a security boundary
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return "", err
	}

	var userID string
	err = tx.QueryRow(ctx, `SELECT user_id FROM wallet_accounts WHERE account_id=$1`, account[:]).Scan(&userID)
	if err == nil {
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	userID = uuid.NewString()
	// A short, stable, non-identifying default: the account's first 4
	// bytes, hex-encoded. Editable later (out of scope here); never
	// blocks login on picking a "real" display name.
	displayName := "wallet-" + hex.EncodeToString(account[:4])
	if _, err := tx.Exec(ctx, `INSERT INTO users (user_id, display_name, created_at) VALUES ($1,$2,now())`, userID, displayName); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO wallet_accounts (account_id, scheme, user_id) VALUES ($1,$2,$3)`, account[:], byte(scheme), userID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
}
