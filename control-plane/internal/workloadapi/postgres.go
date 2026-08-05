package workloadapi

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) CreateOrGet(ctx context.Context, candidate Workload) (Workload, error) {
	command, err := r.pool.Exec(ctx, `INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, candidate.WorkloadID, candidate.RequestID, candidate.RequestHash[:], candidate.Definition, candidate.Image, candidate.State, candidate.CreatedAt, candidate.UpdatedAt)
	if err != nil {
		return Workload{}, err
	}
	if command.RowsAffected() == 1 {
		return candidate, nil
	}
	stored, err := r.byRequestID(ctx, candidate.RequestID)
	if errors.Is(err, ErrNotFound) {
		return Workload{}, ErrConflict
	}
	if err != nil {
		return Workload{}, err
	}
	if stored.RequestHash != candidate.RequestHash || stored.WorkloadID != candidate.WorkloadID || !bytes.Equal(stored.Definition, candidate.Definition) || stored.Image != candidate.Image {
		return Workload{}, ErrConflict
	}
	return stored, nil
}

func (r *PostgresRepository) Get(ctx context.Context, workloadID string) (Workload, error) {
	return scanWorkload(r.pool.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1`, workloadID))
}

func (r *PostgresRepository) RequestStop(ctx context.Context, workloadID, requestID string, now time.Time) (Workload, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Workload{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	stored, err := scanWorkload(tx.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1 FOR UPDATE`, workloadID))
	if err != nil {
		return Workload{}, err
	}
	if stored.StopRequestID != "" && stored.StopRequestID != requestID {
		return Workload{}, ErrConflict
	}
	if stored.StopRequestID == "" {
		state := stored.State
		switch state {
		case "STOPPED", "COMPLETED", "FAILED":
		default:
			state = "STOPPING"
		}
		command, updateErr := tx.Exec(ctx, `UPDATE workloads SET stop_request_id=$2, stop_requested_at=$3, state=$4, version=version+1, updated_at=$3, next_attempt_at=NULL, error_code=NULL, last_error=NULL, worker_id=NULL, worker_lease_until=NULL WHERE workload_id=$1 AND stop_request_id IS NULL`, workloadID, requestID, now, state)
		if updateErr != nil {
			var postgresError *pgconn.PgError
			if errors.As(updateErr, &postgresError) && postgresError.Code == "23505" {
				return Workload{}, ErrConflict
			}
			return Workload{}, updateErr
		}
		if command.RowsAffected() != 1 {
			return Workload{}, ErrConflict
		}
		stored.State = state
		stored.StopRequestID = requestID
		stored.UpdatedAt = now
	}
	if err := tx.Commit(ctx); err != nil {
		return Workload{}, err
	}
	return stored, nil
}
func (r *PostgresRepository) byRequestID(ctx context.Context, requestID string) (Workload, error) {
	return scanWorkload(r.pool.QueryRow(ctx, selectWorkload+` WHERE request_id=$1`, requestID))
}

func (r *PostgresRepository) ClaimNext(ctx context.Context, workerID string, lease time.Duration) (Workload, error) {
	if workerID == "" || lease <= 0 {
		return Workload{}, errors.New("worker id and positive claim duration are required")
	}
	query := `WITH candidate AS (
		SELECT workload_id FROM workloads
		WHERE state IN ('REQUESTED','SCHEDULING','LEASE_PENDING','LEASED','DEPLOYING','STOPPING')
		  AND (next_attempt_at IS NULL OR next_attempt_at <= now())
		  AND (worker_lease_until IS NULL OR worker_lease_until <= now())
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	)
	UPDATE workloads AS w
	SET worker_id=$1, worker_lease_until=now()+$2::interval, version=w.version+1
	FROM candidate
	WHERE w.workload_id=candidate.workload_id
	RETURNING ` + returningWorkload
	return scanWorkload(r.pool.QueryRow(ctx, query, workerID, lease.String()))
}

func (r *PostgresRepository) MarkDeploying(ctx context.Context, item Workload, leaseID uint64) error {
	command, err := r.pool.Exec(ctx, `UPDATE workloads SET state='DEPLOYING',version=version+1,updated_at=now(),worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='LEASED' AND lease_id=$2 AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`, item.WorkloadID, leaseID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
func (r *PostgresRepository) MarkRunning(ctx context.Context, item Workload, containerID string) error {
	if containerID == "" {
		return errors.New("container id is required")
	}
	command, err := r.pool.Exec(ctx, `UPDATE workloads SET state='RUNNING',container_id=$2,version=version+1,updated_at=now(),next_attempt_at=NULL,error_code=NULL,last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='DEPLOYING' AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`, item.WorkloadID, containerID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
func (r *PostgresRepository) MarkStopped(ctx context.Context, item Workload, leaseID uint64) error {
	command, err := r.pool.Exec(ctx, `UPDATE workloads SET state='STOPPED',version=version+1,updated_at=now(),next_attempt_at=NULL,error_code=NULL,last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='STOPPING' AND lease_id=$2 AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`, item.WorkloadID, leaseID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (r *PostgresRepository) BeginScheduling(ctx context.Context, item Workload) error {
	command, err := r.pool.Exec(ctx, `UPDATE workloads SET state='SCHEDULING', version=version+1, updated_at=now(), error_code=NULL, last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='REQUESTED' AND version=$2 AND worker_id=$3 AND worker_lease_until>now()`, item.WorkloadID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (r *PostgresRepository) AssignLease(ctx context.Context, item Workload, providerID string, resourceHash [32]byte) (uint64, error) {
	var leaseID uint64
	err := r.pool.QueryRow(ctx, `UPDATE workloads SET state='LEASE_PENDING', provider_id=$2, lease_id=nextval('workload_lease_id_seq'), resource_hash=$3, version=version+1, updated_at=now(),worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='SCHEDULING' AND version=$4 AND worker_id=$5 AND worker_lease_until>now() RETURNING lease_id`, item.WorkloadID, providerID, resourceHash[:], item.Version, item.WorkerID).Scan(&leaseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConflict
	}
	return leaseID, err
}

func (r *PostgresRepository) MarkLeased(ctx context.Context, item Workload, leaseID uint64) error {
	command, err := r.pool.Exec(ctx, `UPDATE workloads SET state='LEASED', version=version+1, updated_at=now(), next_attempt_at=NULL, error_code=NULL, last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='LEASE_PENDING' AND lease_id=$2 AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`, item.WorkloadID, leaseID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (r *PostgresRepository) RetryLater(ctx context.Context, item Workload, code, message string, delay time.Duration) error {
	if len(message) > 512 {
		message = message[:512]
	}
	command, err := r.pool.Exec(ctx, `UPDATE workloads SET attempt_count=attempt_count+1, next_attempt_at=now()+$2::interval, error_code=$3, last_error=$4, updated_at=now(),version=version+1,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state IN ('REQUESTED','SCHEDULING','LEASE_PENDING','LEASED','DEPLOYING','STOPPING') AND version=$5 AND worker_id=$6 AND worker_lease_until>now()`, item.WorkloadID, delay.String(), code, message, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

const workloadColumns = `workload_id::text, request_id::text, request_hash, definition, COALESCE(resource_hash,'\x'::bytea), image, state, COALESCE(provider_id,''), COALESCE(lease_id::text,''), COALESCE(container_id,''), COALESCE(error_code,''), COALESCE(stop_request_id::text,''), created_at, updated_at, COALESCE(worker_id,''), worker_lease_until, version, attempt_count`
const selectWorkload = `SELECT ` + workloadColumns + ` FROM workloads`
const returningWorkload = `w.workload_id::text, w.request_id::text, w.request_hash, w.definition, COALESCE(w.resource_hash,'\x'::bytea), w.image, w.state, COALESCE(w.provider_id,''), COALESCE(w.lease_id::text,''), COALESCE(w.container_id,''), COALESCE(w.error_code,''), COALESCE(w.stop_request_id::text,''), w.created_at, w.updated_at, COALESCE(w.worker_id,''), w.worker_lease_until, w.version, w.attempt_count`

type scanner interface{ Scan(...any) error }

func scanWorkload(row scanner) (Workload, error) {
	var w Workload
	var hash, resourceHash []byte
	var workerLeaseUntil *time.Time
	err := row.Scan(&w.WorkloadID, &w.RequestID, &hash, &w.Definition, &resourceHash, &w.Image, &w.State, &w.ProviderID, &w.LeaseID, &w.ContainerID, &w.ErrorCode, &w.StopRequestID, &w.CreatedAt, &w.UpdatedAt, &w.WorkerID, &workerLeaseUntil, &w.Version, &w.AttemptCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return Workload{}, ErrNotFound
	}
	if err != nil {
		return Workload{}, err
	}
	if len(hash) != 32 {
		return Workload{}, errors.New("invalid stored request hash")
	}
	copy(w.RequestHash[:], hash)
	if len(resourceHash) != 0 {
		if len(resourceHash) != 32 {
			return Workload{}, errors.New("invalid stored resource hash")
		}
		copy(w.ResourceHash[:], resourceHash)
	}
	if workerLeaseUntil != nil {
		w.WorkerLeaseUntil = *workerLeaseUntil
	}
	return w, nil
}
