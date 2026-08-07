package userauth

import (
	"context"
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

func (r *PostgresRepository) CreateUser(ctx context.Context, displayName string) (User, error) {
	user := User{UserID: uuid.NewString(), DisplayName: displayName, CreatedAt: time.Now().UTC()}
	if _, err := r.pool.Exec(ctx, `INSERT INTO users (user_id, display_name, created_at) VALUES ($1,$2,$3)`, user.UserID, user.DisplayName, user.CreatedAt); err != nil {
		return User{}, err
	}
	return user, nil
}

func (r *PostgresRepository) CreateAPIKey(ctx context.Context, userID string) (APIKey, error) {
	return r.CreateAPIKeyWithExpiry(ctx, userID, nil)
}

func (r *PostgresRepository) CreateAPIKeyWithExpiry(ctx context.Context, userID string, expiresAt *time.Time) (APIKey, error) {
	raw, hash, prefix, err := GenerateAPIKey()
	if err != nil {
		return APIKey{}, err
	}
	key := APIKey{KeyID: uuid.NewString(), UserID: userID, Prefix: prefix, Raw: raw, CreatedAt: time.Now().UTC(), ExpiresAt: expiresAt}
	if _, err := r.pool.Exec(ctx, `INSERT INTO api_keys (key_id, user_id, key_hash, prefix, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, key.KeyID, key.UserID, hash[:], key.Prefix, key.CreatedAt, key.ExpiresAt); err != nil {
		return APIKey{}, err
	}
	return key, nil
}

// Authenticate looks the key up by its hash, in one round trip, and
// rejects unknown/revoked/expired keys identically as ErrInvalidKey.
// last_used_at is updated best-effort in the same statement rather than a
// second query, so a read-only replica or a busy pool can't make
// authentication itself flaky.
func (r *PostgresRepository) Authenticate(ctx context.Context, hash [32]byte) (User, error) {
	var user User
	err := r.pool.QueryRow(ctx, `
		UPDATE api_keys SET last_used_at = now()
		FROM users
		WHERE api_keys.key_hash = $1
		  AND api_keys.revoked_at IS NULL
		  AND (api_keys.expires_at IS NULL OR api_keys.expires_at > now())
		  AND users.user_id = api_keys.user_id
		RETURNING users.user_id, users.display_name, users.created_at
	`, hash[:]).Scan(&user.UserID, &user.DisplayName, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrInvalidKey
	}
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (r *PostgresRepository) RevokeAPIKey(ctx context.Context, keyID string) error {
	command, err := r.pool.Exec(ctx, `UPDATE api_keys SET revoked_at = now() WHERE key_id = $1 AND revoked_at IS NULL`, keyID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidKey
	}
	return nil
}
