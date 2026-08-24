package providerjoin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) ProviderIdentity(ctx context.Context, providerID string) (ProviderIdentity, error) {
	var identity ProviderIdentity
	var nodeStatus int16
	err := r.pool.QueryRow(ctx, `SELECT public_key, status FROM providers WHERE provider_id = $1`, providerID).Scan(&identity.PublicKey, &nodeStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderIdentity{}, ErrProviderNotFound
	}
	if err != nil {
		return ProviderIdentity{}, err
	}
	identity.Status = sharedv1.NodeStatus(nodeStatus)
	return identity, nil
}

func (r *PostgresRepository) CreateOrGetChallenge(ctx context.Context, candidate Challenge) (Challenge, error) {
	command, err := r.pool.Exec(ctx, `
		INSERT INTO provider_join_challenges (
			challenge_id, begin_request_id, request_hash, public_key,
			protocol_version, agent_version, agent_endpoint, nonce, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (begin_request_id) DO NOTHING`,
		candidate.ChallengeID, candidate.BeginRequestID, candidate.RequestHash[:],
		candidate.PublicKey, candidate.ProtocolVersion, candidate.AgentVersion,
		candidate.AgentEndpoint, candidate.Nonce, candidate.ExpiresAt,
	)
	if err != nil {
		return Challenge{}, err
	}
	if command.RowsAffected() == 1 {
		return candidate, nil
	}

	stored, err := r.challengeByBeginRequestID(ctx, candidate.BeginRequestID)
	if err != nil {
		return Challenge{}, err
	}
	if stored.RequestHash != candidate.RequestHash {
		return Challenge{}, ErrConflict
	}
	return stored, nil
}

func (r *PostgresRepository) GetChallenge(ctx context.Context, challengeID string) (Challenge, error) {
	return scanChallenge(r.pool.QueryRow(ctx, `
		SELECT challenge_id, begin_request_id, request_hash, public_key,
		       protocol_version, agent_version, agent_endpoint, nonce, expires_at
		FROM provider_join_challenges
		WHERE challenge_id = $1`, challengeID))
}

func (r *PostgresRepository) CompleteJoin(ctx context.Context, completion Completion) (result Completion, err error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Completion{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	var existingChallengeID, existingProviderID string
	var existingRequestHash []byte
	var existingRegisteredAt time.Time
	var existingStatus int16
	err = tx.QueryRow(ctx, `
		SELECT c.challenge_id, c.request_hash, c.provider_id, c.registered_at, p.status
		FROM provider_join_completions c
		JOIN providers p ON p.provider_id = c.provider_id
		WHERE c.request_id = $1`, completion.RequestID,
	).Scan(&existingChallengeID, &existingRequestHash, &existingProviderID, &existingRegisteredAt, &existingStatus)
	if err == nil {
		if existingChallengeID != completion.Challenge.ChallengeID || !bytes.Equal(existingRequestHash, completion.RequestHash[:]) {
			return Completion{}, ErrConflict
		}
		completion.ProviderID = existingProviderID
		completion.RegisteredAt = existingRegisteredAt
		completion.Status = sharedv1.NodeStatus(existingStatus)
		if err = tx.Commit(ctx); err != nil {
			return Completion{}, err
		}
		return completion, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Completion{}, err
	}

	var nonce, publicKey []byte
	var expiresAt time.Time
	var consumedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT nonce, public_key, expires_at, consumed_at
		FROM provider_join_challenges
		WHERE challenge_id = $1
		FOR UPDATE`, completion.Challenge.ChallengeID,
	).Scan(&nonce, &publicKey, &expiresAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Completion{}, ErrChallengeNotFound
	}
	if err != nil {
		return Completion{}, err
	}
	if consumedAt != nil {
		return Completion{}, ErrChallengeConsumed
	}
	if !completion.RegisteredAt.Before(expiresAt) {
		return Completion{}, ErrChallengeExpired
	}
	if !bytes.Equal(nonce, completion.Challenge.Nonce) || !bytes.Equal(publicKey, completion.Challenge.PublicKey) {
		return Completion{}, ErrConflict
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO providers (
			provider_id, public_key, protocol_version, agent_version,
			agent_endpoint, capabilities, status, registered_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (provider_id) DO UPDATE SET
			protocol_version = EXCLUDED.protocol_version,
			agent_version = EXCLUDED.agent_version,
			agent_endpoint = EXCLUDED.agent_endpoint,
			capabilities = EXCLUDED.capabilities`,
		completion.ProviderID, publicKey, completion.Challenge.ProtocolVersion,
		completion.Challenge.AgentVersion, completion.Challenge.AgentEndpoint,
		completion.Capabilities, int16(completion.Status), completion.RegisteredAt,
	)
	if err != nil {
		return Completion{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO provider_chain_registrations (provider_id, state)
		VALUES ($1, 'READY')
		ON CONFLICT (provider_id) DO NOTHING`, completion.ProviderID)
	if err != nil {
		return Completion{}, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE provider_join_challenges
		SET consumed_at = $2, provider_id = $3
		WHERE challenge_id = $1`,
		completion.Challenge.ChallengeID, completion.RegisteredAt, completion.ProviderID,
	)
	if err != nil {
		return Completion{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO provider_join_completions (
			request_id, challenge_id, request_hash, provider_id, registered_at
		) VALUES ($1, $2, $3, $4, $5)`,
		completion.RequestID, completion.Challenge.ChallengeID,
		completion.RequestHash[:], completion.ProviderID, completion.RegisteredAt,
	)
	if err != nil {
		return Completion{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Completion{}, err
	}
	return completion, nil
}

func (r *PostgresRepository) ActivateProvider(ctx context.Context, providerID string, finalization ChainFinalization) (result Completion, err error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Completion{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	command, err := tx.Exec(ctx, `
		UPDATE providers
		SET status = $2, activated_at = COALESCE(activated_at, now()), updated_at = now()
		WHERE provider_id = $1`, providerID, int16(sharedv1.NodeStatus_NODE_STATUS_ACTIVE))
	if err != nil {
		return Completion{}, err
	}
	if command.RowsAffected() != 1 {
		return Completion{}, ErrProviderNotFound
	}
	_, err = tx.Exec(ctx, `
		UPDATE provider_chain_registrations
		SET state = 'FINALIZED', extrinsic_hash = $2, finalized_block_hash = $3,
		    finalized_block_number = $4, finalized_at = now(), updated_at = now(), last_error = NULL
		WHERE provider_id = $1`, providerID, finalization.ExtrinsicHash,
		finalization.FinalizedBlockHash, finalization.FinalizedBlockNumber)
	if err != nil {
		return Completion{}, err
	}
	err = tx.QueryRow(ctx, `
		SELECT c.request_id, c.provider_id, c.registered_at
		FROM provider_join_completions c
		WHERE c.provider_id = $1
		ORDER BY c.registered_at
		LIMIT 1`, providerID).Scan(&result.RequestID, &result.ProviderID, &result.RegisteredAt)
	if err != nil {
		return Completion{}, err
	}
	result.Status = sharedv1.NodeStatus_NODE_STATUS_ACTIVE
	if err = tx.Commit(ctx); err != nil {
		return Completion{}, err
	}
	return result, nil
}

// RevokeProvider implements ADR-027 §4's operator-only revocation path:
// controlplane-admin revoke-provider is the sole caller. Writing
// providers.status = REVOKED here is the entire authoritative act --
// PostgresRegistry.ListActive's existing WHERE status = $1 filter (see
// control-plane/internal/agentmanager/directory.go) excludes this provider
// from scheduling starting with the very next read, with no separate
// mechanism. Connectivity revocation (the Redis-backed live set
// pki.RedisRevocationStore checks on every handshake/RPC) is deliberately
// not written here: pki.Reconciler sweeps this exact status change into
// Redis on its own short period, keeping this method free of any
// dependency on Redis or on the pki package.
func (r *PostgresRepository) RevokeProvider(ctx context.Context, providerID string) error {
	command, err := r.pool.Exec(ctx, `
		UPDATE providers SET status = $2, updated_at = now() WHERE provider_id = $1`,
		providerID, int16(sharedv1.NodeStatus_NODE_STATUS_REVOKED))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrProviderNotFound
	}
	return nil
}

// ListRevokedProviderIDs implements pki.RevokedProviderSource: the
// authoritative (Postgres) read side pki.Reconciler sweeps into Redis.
func (r *PostgresRepository) ListRevokedProviderIDs(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT provider_id FROM providers WHERE status = $1`, int16(sharedv1.NodeStatus_NODE_STATUS_REVOKED))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DueChainRegistrations implements ChainRegistrationStore for the
// Reconciler: providers whose outbox row is READY or RETRY and due (no
// backoff scheduled, or the backoff has elapsed), oldest first so a
// persistently failing registration cannot starve others out of the batch.
func (r *PostgresRepository) DueChainRegistrations(ctx context.Context, limit int) ([]PendingChainRegistration, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT cr.provider_id, p.public_key, cr.attempt_count
		FROM provider_chain_registrations cr
		JOIN providers p ON p.provider_id = cr.provider_id
		WHERE cr.state IN ('READY', 'RETRY')
		  AND (cr.next_attempt_at IS NULL OR cr.next_attempt_at <= now())
		ORDER BY cr.created_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var due []PendingChainRegistration
	for rows.Next() {
		var pending PendingChainRegistration
		if err := rows.Scan(&pending.ProviderID, &pending.PublicKey, &pending.AttemptCount); err != nil {
			return nil, err
		}
		due = append(due, pending)
	}
	return due, rows.Err()
}

// RecordChainRegistrationFailure implements ChainRegistrationStore.
func (r *PostgresRepository) RecordChainRegistrationFailure(ctx context.Context, providerID string, attemptErr error, nextAttemptAt time.Time, terminal bool) error {
	state := "RETRY"
	var next *time.Time
	if terminal {
		state = "FAILED"
	} else {
		next = &nextAttemptAt
	}
	command, err := r.pool.Exec(ctx, `
		UPDATE provider_chain_registrations
		SET state = $2, attempt_count = attempt_count + 1, next_attempt_at = $3,
		    last_error = $4, updated_at = now()
		WHERE provider_id = $1`,
		providerID, state, next, attemptErr.Error())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrProviderNotFound
	}
	return nil
}

func (r *PostgresRepository) challengeByBeginRequestID(ctx context.Context, requestID string) (Challenge, error) {
	return scanChallenge(r.pool.QueryRow(ctx, `
		SELECT challenge_id, begin_request_id, request_hash, public_key,
		       protocol_version, agent_version, agent_endpoint, nonce, expires_at
		FROM provider_join_challenges
		WHERE begin_request_id = $1`, requestID))
}

type rowScanner interface {
	Scan(...any) error
}

func scanChallenge(row rowScanner) (Challenge, error) {
	var challenge Challenge
	var requestHash []byte
	err := row.Scan(
		&challenge.ChallengeID, &challenge.BeginRequestID, &requestHash,
		&challenge.PublicKey, &challenge.ProtocolVersion, &challenge.AgentVersion,
		&challenge.AgentEndpoint, &challenge.Nonce, &challenge.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Challenge{}, ErrChallengeNotFound
	}
	if err != nil {
		return Challenge{}, err
	}
	if len(requestHash) != sha256.Size {
		return Challenge{}, errors.New("invalid stored request hash")
	}
	copy(challenge.RequestHash[:], requestHash)
	return challenge, nil
}
