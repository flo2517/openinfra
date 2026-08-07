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
	command, err := r.pool.Exec(ctx, `INSERT INTO workloads (workload_id, request_id, owner_id, request_hash, definition, image, state, created_at, updated_at, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb, reserved_ingress_mbps, reserved_egress_mbps) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`, candidate.WorkloadID, candidate.RequestID, candidate.OwnerID, candidate.RequestHash[:], candidate.Definition, candidate.Image, candidate.State, candidate.CreatedAt, candidate.UpdatedAt, candidate.ReservedCPUMillicores, candidate.ReservedRAMMB, candidate.ReservedStorageGB, candidate.ReservedIngressMbps, candidate.ReservedEgressMbps)
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
	// The owner_id comparison matters as much as the others: request_id is
	// globally unique, not per-tenant, so without it a second tenant who
	// happens to reuse (or guess) another tenant's request_id would be
	// handed back that tenant's workload_id/definition/image as if it were
	// an idempotent replay of their own call.
	if stored.RequestHash != candidate.RequestHash || stored.WorkloadID != candidate.WorkloadID || stored.OwnerID != candidate.OwnerID || !bytes.Equal(stored.Definition, candidate.Definition) || stored.Image != candidate.Image {
		return Workload{}, ErrConflict
	}
	return stored, nil
}

func (r *PostgresRepository) Get(ctx context.Context, workloadID, ownerID string) (Workload, error) {
	return scanWorkload(r.pool.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1 AND owner_id=$2`, workloadID, ownerID))
}

func (r *PostgresRepository) RequestStop(ctx context.Context, workloadID, requestID, ownerID string, now time.Time) (Workload, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Workload{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Filtering by owner_id here, not just workload_id, means a non-owner
	// never takes the FOR UPDATE row lock on someone else's workload
	// either -- a fetch-then-compare in Go would still briefly lock a row
	// the caller has no right to touch.
	stored, err := scanWorkload(tx.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1 AND owner_id=$2 FOR UPDATE`, workloadID, ownerID))
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

// AssignLease commits this workload to providerID, but only if the
// provider's declared total capacity (capacity, from its latest heartbeat
// -- stable hardware facts, not the live "available" figure that only
// lives in Redis) still has headroom over every other open workload
// already assigned to it. The check and the commit happen in one
// Serializable transaction: two concurrent AssignLease calls racing to
// fill the same provider's last slot will not both read "capacity still
// free" before either commits -- Postgres aborts the loser with a
// serialization failure, surfaced here as ErrConflict so the worker
// retries the whole scheduling step (a different, or by-then-recovered,
// provider may be chosen next attempt).
//
// This is deliberately a hard ceiling against declared total capacity,
// not an attempt to reconcile with Redis's live "available" number --
// Postgres is the only store this transaction can make atomic guarantees
// about (AGENTS.md: PostgreSQL is authoritative off-chain, Redis is
// reconstructible), and mixing an eventually-consistent Redis read into
// an atomicity argument would not actually prevent overcommit, only look
// like it did.
func (r *PostgresRepository) AssignLease(ctx context.Context, item Workload, providerID string, resourceHash [32]byte, capacity ProviderCapacity) (leaseID uint64, err error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	var reservedCPU, reservedRAM, reservedStorage, reservedIngress, reservedEgress int64
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(SUM(reserved_cpu_millicores), 0), COALESCE(SUM(reserved_ram_mb), 0), COALESCE(SUM(reserved_storage_gb), 0),
		       COALESCE(SUM(reserved_ingress_mbps), 0), COALESCE(SUM(reserved_egress_mbps), 0)
		FROM workloads
		WHERE provider_id = $1 AND state IN ('LEASE_PENDING', 'LEASED', 'DEPLOYING', 'RUNNING')`,
		providerID,
	).Scan(&reservedCPU, &reservedRAM, &reservedStorage, &reservedIngress, &reservedEgress)
	if isSerializationFailure(err) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, err
	}
	if reservedCPU+item.ReservedCPUMillicores > capacity.TotalCPUMillicores ||
		reservedRAM+item.ReservedRAMMB > capacity.TotalRAMMB ||
		reservedStorage+item.ReservedStorageGB > capacity.TotalStorageGB ||
		reservedIngress+item.ReservedIngressMbps > capacity.TotalIngressMbps ||
		reservedEgress+item.ReservedEgressMbps > capacity.TotalEgressMbps {
		return 0, ErrCapacityExceeded
	}

	err = tx.QueryRow(ctx, `
		UPDATE workloads
		SET state='LEASE_PENDING', provider_id=$2, lease_id=nextval('workload_lease_id_seq'), resource_hash=$3,
		    version=version+1, updated_at=now(), worker_id=NULL, worker_lease_until=NULL
		WHERE workload_id=$1 AND state='SCHEDULING' AND version=$4 AND worker_id=$5 AND worker_lease_until>now()
		RETURNING lease_id`,
		item.WorkloadID, providerID, resourceHash[:], item.Version, item.WorkerID,
	).Scan(&leaseID)
	if errors.Is(err, pgx.ErrNoRows) || isSerializationFailure(err) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		if isSerializationFailure(err) {
			return 0, ErrConflict
		}
		return 0, err
	}
	return leaseID, nil
}

// isSerializationFailure reports whether err is Postgres SQLSTATE 40001, the
// error a Serializable transaction can surface on *any* statement -- not
// only at COMMIT -- once it detects a read/write conflict with a concurrent
// transaction. AssignLease checks this at every statement so a losing racer
// always surfaces as ErrConflict (retryable) rather than an opaque internal
// error the caller doesn't know how to handle.
func isSerializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "40001"
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

const workloadColumns = `workload_id::text, request_id::text, request_hash, definition, COALESCE(resource_hash,'\x'::bytea), image, state, COALESCE(provider_id,''), COALESCE(lease_id::text,''), COALESCE(container_id,''), COALESCE(error_code,''), COALESCE(stop_request_id::text,''), created_at, updated_at, COALESCE(worker_id,''), worker_lease_until, version, attempt_count, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb, COALESCE(owner_id::text,''), reserved_ingress_mbps, reserved_egress_mbps`
const selectWorkload = `SELECT ` + workloadColumns + ` FROM workloads`
const returningWorkload = `w.workload_id::text, w.request_id::text, w.request_hash, w.definition, COALESCE(w.resource_hash,'\x'::bytea), w.image, w.state, COALESCE(w.provider_id,''), COALESCE(w.lease_id::text,''), COALESCE(w.container_id,''), COALESCE(w.error_code,''), COALESCE(w.stop_request_id::text,''), w.created_at, w.updated_at, COALESCE(w.worker_id,''), w.worker_lease_until, w.version, w.attempt_count, w.reserved_cpu_millicores, w.reserved_ram_mb, w.reserved_storage_gb, COALESCE(w.owner_id::text,''), w.reserved_ingress_mbps, w.reserved_egress_mbps`

type scanner interface{ Scan(...any) error }

func scanWorkload(row scanner) (Workload, error) {
	var w Workload
	var hash, resourceHash []byte
	var workerLeaseUntil *time.Time
	err := row.Scan(&w.WorkloadID, &w.RequestID, &hash, &w.Definition, &resourceHash, &w.Image, &w.State, &w.ProviderID, &w.LeaseID, &w.ContainerID, &w.ErrorCode, &w.StopRequestID, &w.CreatedAt, &w.UpdatedAt, &w.WorkerID, &workerLeaseUntil, &w.Version, &w.AttemptCount, &w.ReservedCPUMillicores, &w.ReservedRAMMB, &w.ReservedStorageGB, &w.OwnerID, &w.ReservedIngressMbps, &w.ReservedEgressMbps)
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
