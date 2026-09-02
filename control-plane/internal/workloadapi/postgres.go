package workloadapi

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openinfra/network/internal/eventlog"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
	// eventLog/eventSigner are ADR-039's dual-write: nil by default, so
	// every existing test/deployment that predates ADR-039 is completely
	// unaffected -- see SetEventLog's doc comment. This is the governed
	// toggle ADR-039 §11 calls for ("a governed toggle... disables
	// event-log export to witnesses without affecting workloads-table
	// operation at all"): a Go-level, off-chain switch, not a new
	// on-chain governed boolean -- ADR-039 Decision §10 is explicit that
	// this design proposes no new pallet, no new runtime storage, and no
	// new extrinsic, so a chain-side toggle (the shape EscrowPaused/the
	// still-unimplemented OnChainSchedulingEnabled use for their own
	// pallets) is not an available option here without contradicting the
	// ADR's own stated scope. Flagged explicitly: this is a narrower,
	// simpler mechanism (a constructor-time value, not a live-toggleable
	// runtime flag) than "governed" might imply -- rotating it today means
	// a restart with SetEventLog called or not, not a live operator
	// command. A live-toggle admin surface is real, separable follow-up
	// work, not invented here.
	eventLog    *eventlog.PostgresRepository
	eventSigner eventlog.Signer
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// SetEventLog enables ADR-039's dual-write: every BeginScheduling/
// AssignLease/MarkLeased/MarkDeploying/MarkRunning/MarkStopped/
// MarkFailed/RetryLater call below additionally appends one signed
// event_log row, in the same Postgres transaction as its own workloads
// UPDATE, once this is called with non-nil arguments. Left unset (the
// zero *PostgresRepository's default, and every existing test/deployment
// that predates ADR-039), every method below takes its original,
// single-statement, non-transactional path -- byte-for-byte the same SQL
// this file issued before ADR-039, so disabling this dependency at
// startup is a real, exercisable rollback (ADR-039 §11 Test 6), not just
// a claim.
func (r *PostgresRepository) SetEventLog(eventLog *eventlog.PostgresRepository, signer eventlog.Signer) {
	r.eventLog, r.eventSigner = eventLog, signer
}

// chainAnchorFromItem builds ADR-039 §5's ChainAnchor from whatever this
// workload's row already carries: LeaseBlockHash is set once, by
// MarkLeased, the moment EnsureLeaseActive first confirms the lease
// Active in finalized storage, and every later Mark* call for the same
// workload_id reads it back from the already-loaded Workload rather than
// re-deriving it -- see LeaseBlockHash's own doc comment (service.go) and
// migration 000024's identical reasoning on workloads.lease_block_hash.
// Returns nil before a lease exists (LeaseID == "") -- ADR-039 §5's
// honestly-named pre-lease gap: there is no chain fact to anchor against
// yet.
func chainAnchorFromItem(item Workload) *eventlog.ChainAnchor {
	if item.LeaseID == "" || item.LeaseBlockHash == ([32]byte{}) {
		return nil
	}
	leaseID, err := strconv.ParseUint(item.LeaseID, 10, 64)
	if err != nil {
		return nil
	}
	return &eventlog.ChainAnchor{LeaseID: leaseID, BlockHash: item.LeaseBlockHash}
}

// appendEvent is the shared tail of every dual-writing Mark*/BeginScheduling
// method below: called only after that method's own guarded UPDATE has
// already succeeded (RowsAffected == 1) inside tx -- see
// eventlog.PostgresRepository.head's doc comment for why that ordering is
// what makes the append itself race-free without any extra locking here.
// eventlog.ErrConflict is translated to this package's own ErrConflict so
// callers never need to know eventlog's error types.
func (r *PostgresRepository) appendEvent(ctx context.Context, tx pgx.Tx, item Workload, eventType string, payload []byte) error {
	if r.eventLog == nil {
		return nil
	}
	_, err := r.eventLog.AppendControlPlaneSigned(ctx, tx, r.eventSigner, eventlog.SubjectWorkloadLifecycle, []byte(item.WorkloadID), eventType, payload, chainAnchorFromItem(item))
	if errors.Is(err, eventlog.ErrConflict) {
		return ErrConflict
	}
	return err
}

func (r *PostgresRepository) CreateOrGet(ctx context.Context, candidate Workload) (Workload, error) {
	command, err := r.pool.Exec(ctx, `INSERT INTO workloads (workload_id, request_id, owner_id, project_id, request_hash, definition, image, vm_image_sha256, state, created_at, updated_at, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb, reserved_ingress_mbps, reserved_egress_mbps) VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT DO NOTHING`, candidate.WorkloadID, candidate.RequestID, candidate.OwnerID, nullableID(candidate.ProjectID), candidate.RequestHash[:], candidate.Definition, candidate.Image, candidate.VmImageSha256, candidate.State, candidate.CreatedAt, candidate.UpdatedAt, candidate.ReservedCPUMillicores, candidate.ReservedRAMMB, candidate.ReservedStorageGB, candidate.ReservedIngressMbps, candidate.ReservedEgressMbps)
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
	// The owner_id/project_id comparisons matter as much as the others:
	// request_id is globally unique, not per-tenant, so without them a
	// second tenant (or a second project) who happens to reuse (or guess)
	// another tenant's request_id would be handed back that tenant's
	// workload_id/definition/image as if it were an idempotent replay of
	// their own call.
	if stored.RequestHash != candidate.RequestHash || stored.WorkloadID != candidate.WorkloadID || stored.OwnerID != candidate.OwnerID || stored.ProjectID != candidate.ProjectID || !bytes.Equal(stored.Definition, candidate.Definition) || stored.Image != candidate.Image || stored.VmImageSha256 != candidate.VmImageSha256 {
		return Workload{}, ErrConflict
	}
	return stored, nil
}

// nullableID converts an empty-string ID (this package's convention for
// "absent", e.g. Workload.ProjectID when a workload was not created
// through the OpenStack surface) into a genuine SQL NULL, so it can be
// bound against a nullable `uuid` column -- passing "" directly would fail
// uuid parsing instead of storing NULL.
func nullableID(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

func (r *PostgresRepository) Get(ctx context.Context, workloadID, ownerID string) (Workload, error) {
	return scanWorkload(r.pool.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1 AND owner_id=$2`, workloadID, ownerID))
}

// GetByProject is Get's project-scoped counterpart, for
// internal/openstackapi/nova (ADR-031 §3's "every OpenStack-facing query
// scopes by project_id the same literal way internal/workloadapi already
// scopes by owner_id"). A workload belonging to a different project (or
// not created through the OpenStack surface at all, ProjectID = "") is
// indistinguishable from a nonexistent one -- the same no-existence-oracle
// posture Get's owner_id scoping already provides for OwnerID.
func (r *PostgresRepository) GetByProject(ctx context.Context, workloadID, projectID string) (Workload, error) {
	return scanWorkload(r.pool.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1 AND project_id=$2`, workloadID, projectID))
}

// ListByProject lists every workload scoped to projectID, most recent
// first -- the project-scoped counterpart to internal/dashboard's own
// owner-scoped `myWorkloads` query, backing GET
// /v2.1/{project_id}/servers.
func (r *PostgresRepository) ListByProject(ctx context.Context, projectID string) ([]Workload, error) {
	rows, err := r.pool.Query(ctx, selectWorkload+` WHERE project_id=$1 ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var workloads []Workload
	for rows.Next() {
		workload, err := scanWorkload(rows)
		if err != nil {
			return nil, err
		}
		workloads = append(workloads, workload)
	}
	return workloads, rows.Err()
}

// ProviderReservedTotals sums reserved_cpu_millicores/ram_mb/storage_gb/
// ingress_mbps/egress_mbps across every currently-open workload assigned
// to providerID -- the exact aggregate AssignLease's own atomic capacity
// check already computes inline (see that method's doc comment). Exported
// as a read-only helper so a caller outside the commit path (e.g.
// internal/openstackapi/nova's Placement-shaped "resource provider usage"
// endpoint) can report the same "how much is committed against this
// provider" figure without duplicating or drifting from that query.
func (r *PostgresRepository) ProviderReservedTotals(ctx context.Context, providerID string) (cpuMillicores, ramMB, storageGB, ingressMbps, egressMbps int64, err error) {
	err = r.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(reserved_cpu_millicores), 0), COALESCE(SUM(reserved_ram_mb), 0), COALESCE(SUM(reserved_storage_gb), 0),
		       COALESCE(SUM(reserved_ingress_mbps), 0), COALESCE(SUM(reserved_egress_mbps), 0)
		FROM workloads
		WHERE provider_id = $1 AND state IN ('LEASE_PENDING', 'LEASED', 'DEPLOYING', 'RUNNING')`,
		providerID).Scan(&cpuMillicores, &ramMB, &storageGB, &ingressMbps, &egressMbps)
	return
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

// RequestStopByProject is RequestStop's project-scoped counterpart, for
// internal/openstackapi/nova's DELETE /v2.1/{project_id}/servers/{id} --
// identical logic, just scoped by project_id instead of owner_id (see
// GetByProject's doc comment for why that is the correct substitution,
// not an addition alongside owner_id: a Nova server's caller is
// identified by which project their token is scoped to, not by which
// individual user created it -- any member of the project may stop it).
func (r *PostgresRepository) RequestStopByProject(ctx context.Context, workloadID, requestID, projectID string, now time.Time) (Workload, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Workload{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	stored, err := scanWorkload(tx.QueryRow(ctx, selectWorkload+` WHERE workload_id=$1 AND project_id=$2 FOR UPDATE`, workloadID, projectID))
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

const markDeployingSQL = `UPDATE workloads SET state='DEPLOYING',version=version+1,updated_at=now(),worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='LEASED' AND lease_id=$2 AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`

func (r *PostgresRepository) MarkDeploying(ctx context.Context, item Workload, leaseID uint64) error {
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, markDeployingSQL, item.WorkloadID, leaseID, item.Version, item.WorkerID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, markDeployingSQL, item.WorkloadID, leaseID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := r.appendEvent(ctx, tx, item, "DEPLOYING", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const markRunningSQL = `UPDATE workloads SET state='RUNNING',container_id=$2,version=version+1,updated_at=now(),next_attempt_at=NULL,error_code=NULL,last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='DEPLOYING' AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`

func (r *PostgresRepository) MarkRunning(ctx context.Context, item Workload, containerID string) error {
	if containerID == "" {
		return errors.New("container id is required")
	}
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, markRunningSQL, item.WorkloadID, containerID, item.Version, item.WorkerID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, markRunningSQL, item.WorkloadID, containerID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := r.appendEvent(ctx, tx, item, "RUNNING", []byte(containerID)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const markStoppedSQL = `UPDATE workloads SET state='STOPPED',version=version+1,updated_at=now(),next_attempt_at=NULL,error_code=NULL,last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='STOPPING' AND lease_id=$2 AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`

func (r *PostgresRepository) MarkStopped(ctx context.Context, item Workload, leaseID uint64) error {
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, markStoppedSQL, item.WorkloadID, leaseID, item.Version, item.WorkerID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, markStoppedSQL, item.WorkloadID, leaseID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := r.appendEvent(ctx, tx, item, "STOPPED", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReconcileFromAgent implements Repository.ReconcileFromAgent (ADR-028
// §4). Both providerID and fromStates are part of the WHERE clause, not a
// fetch-then-compare in Go: an Agent can only ever reconcile a row it
// still owns, and only out of the exact precondition state
// reconciliationTransition selected for this phase. errorCode/last_error
// are set only for a FAILED transition (errorCode non-empty); a
// successful RUNNING/STOPPED transition instead clears them, matching
// MarkRunning/MarkStopped's own convention of clearing stale
// error/retry state on a forward transition. worker_id/worker_lease_until
// are always cleared: this write did not come from a worker claim, and
// leaving a stale claim in place could block the next legitimate
// ClaimNext for no reason.
func (r *PostgresRepository) ReconcileFromAgent(ctx context.Context, workloadID, providerID string, fromStates []string, toState, containerID, errorCode string) (bool, error) {
	if workloadID == "" || providerID == "" || toState == "" || len(fromStates) == 0 {
		return false, errors.New("workload id, provider id, target state, and at least one source state are required")
	}
	var command pgconn.CommandTag
	var err error
	if errorCode != "" {
		command, err = r.pool.Exec(ctx, `UPDATE workloads SET state=$1, error_code=$2, last_error=$3, version=version+1, updated_at=now(), next_attempt_at=NULL, worker_id=NULL, worker_lease_until=NULL WHERE workload_id=$4 AND provider_id=$5 AND state=ANY($6)`,
			toState, errorCode, "Agent reported "+errorCode, workloadID, providerID, fromStates)
	} else {
		command, err = r.pool.Exec(ctx, `UPDATE workloads SET state=$1, container_id=COALESCE(NULLIF($2,''), container_id), error_code=NULL, last_error=NULL, version=version+1, updated_at=now(), next_attempt_at=NULL, worker_id=NULL, worker_lease_until=NULL WHERE workload_id=$3 AND provider_id=$4 AND state=ANY($5)`,
			toState, containerID, workloadID, providerID, fromStates)
	}
	if err != nil {
		return false, err
	}
	return command.RowsAffected() == 1, nil
}

const beginSchedulingSQL = `UPDATE workloads SET state='SCHEDULING', version=version+1, updated_at=now(), error_code=NULL, last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='REQUESTED' AND version=$2 AND worker_id=$3 AND worker_lease_until>now()`

func (r *PostgresRepository) BeginScheduling(ctx context.Context, item Workload) error {
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, beginSchedulingSQL, item.WorkloadID, item.Version, item.WorkerID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, beginSchedulingSQL, item.WorkloadID, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	// ADR-039 §11 Out of scope note reflected honestly: this is the
	// workload's very first event_log entry (sequence=1), the
	// "REQUESTED"-equivalent pre-lease event named in ADR-039 §5 as
	// unanchorable by construction -- event_type here is "SCHEDULING"
	// (the state this write actually transitions *to*, matching every
	// other appendEvent call site's convention below), not "REQUESTED"
	// (the state before this write, which never itself gets a row since
	// CreateOrGet's initial insert predates any event-log involvement).
	if err := r.appendEvent(ctx, tx, item, "SCHEDULING", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AssignLease commits this workload to providerID, but only if capacity
// (the ceiling the caller built for this provider -- see ProviderCapacity's
// own doc comment for why that is not always the provider's raw declared
// total capacity verbatim, not the live "available" figure that only
// lives in Redis) still has headroom over every other open workload
// already assigned to it. The check and the commit happen in one
// Serializable transaction: two concurrent AssignLease calls racing to
// fill the same provider's last slot will not both read "capacity still
// free" before either commits -- Postgres aborts the loser with a
// serialization failure, surfaced here as ErrConflict so the worker
// retries the whole scheduling step (a different, or by-then-recovered,
// provider may be chosen next attempt).
//
// This is deliberately a hard ceiling against capacity as given, not an
// attempt to reconcile with Redis's live "available" number --
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
	// ADR-039 §5's honest pre-lease gap, precisely at its boundary: this
	// event (LEASE_PENDING) is emitted the instant an off-chain lease_id
	// is assigned, before the corresponding chain extrinsic exists --
	// worker.go's LEASE_PENDING case is what actually submits
	// create_lease/update_lease_state and confirms Active in finalized
	// storage. So this event's chain_anchor is nil (item.LeaseID is still
	// "" at this point, see chainAnchorFromItem); MarkLeased below is the
	// first WorkloadLifecycle event with a real anchor.
	if err := r.appendEvent(ctx, tx, item, "LEASE_PENDING", []byte(providerID)); err != nil {
		if errors.Is(err, ErrConflict) {
			return 0, ErrConflict
		}
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

// MarkLeased additionally persists blockHash into workloads.lease_block_hash
// -- the finalized block at which worker.go's LEASE_PENDING case observed
// this lease's on-chain Active state (blockchainbridge.FinalizedLease.
// FinalizedBlockHash from EnsureLeaseActive). Every later Mark* call for
// this workload_id reads this column back (via chainAnchorFromItem) to
// build its own event_log entry's chain_anchor, so this is the one call
// site that actually establishes ADR-039 §5's anchor for a workload's
// downstream lifecycle -- see LeaseBlockHash's doc comment (service.go).
func (r *PostgresRepository) MarkLeased(ctx context.Context, item Workload, leaseID uint64, blockHash [32]byte) error {
	const sql = `UPDATE workloads SET state='LEASED', lease_block_hash=$5, version=version+1, updated_at=now(), next_attempt_at=NULL, error_code=NULL, last_error=NULL,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state='LEASE_PENDING' AND lease_id=$2 AND version=$3 AND worker_id=$4 AND worker_lease_until>now()`
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, sql, item.WorkloadID, leaseID, item.Version, item.WorkerID, blockHash[:])
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, sql, item.WorkloadID, leaseID, item.Version, item.WorkerID, blockHash[:])
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	item.LeaseID = strconv.FormatUint(leaseID, 10)
	item.LeaseBlockHash = blockHash
	if err := r.appendEvent(ctx, tx, item, "LEASED", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const retryLaterSQL = `UPDATE workloads SET attempt_count=attempt_count+1, next_attempt_at=now()+$2::interval, error_code=$3, last_error=$4, updated_at=now(),version=version+1,worker_id=NULL,worker_lease_until=NULL WHERE workload_id=$1 AND state IN ('REQUESTED','SCHEDULING','LEASE_PENDING','LEASED','DEPLOYING','STOPPING') AND version=$5 AND worker_id=$6 AND worker_lease_until>now()`

func (r *PostgresRepository) RetryLater(ctx context.Context, item Workload, code, message string, delay time.Duration) error {
	if len(message) > 512 {
		message = message[:512]
	}
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, retryLaterSQL, item.WorkloadID, delay.String(), code, message, item.Version, item.WorkerID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, retryLaterSQL, item.WorkloadID, delay.String(), code, message, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := r.appendEvent(ctx, tx, item, "RETRY:"+code, []byte(message)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// MarkFailed is RetryLater's terminal counterpart: it moves a workload out
// of every non-terminal state into FAILED, for orchestrator.Worker.retry
// once its retry cap is reached (issue #138) instead of re-queuing it
// against a dead provider forever. Like RetryLater it accepts any of the
// states that can hit that retry path, including STOPPING -- a stop that
// can never get authoritative confirmation is exactly as stuck as a
// deploy that never proceeds, and FAILED is the same "give up, make it
// observable, let an operator act" terminal outcome for both. Uses the
// same optimistic-concurrency WHERE clause (version/worker_id/lease) as
// every other Mark* method so a worker that lost its claim never
// terminates a workload another worker has since picked back up.
const markFailedSQL = `UPDATE workloads SET state='FAILED', attempt_count=attempt_count+1, next_attempt_at=NULL, error_code=$2, last_error=$3, updated_at=now(), version=version+1, worker_id=NULL, worker_lease_until=NULL WHERE workload_id=$1 AND state IN ('REQUESTED','SCHEDULING','LEASE_PENDING','LEASED','DEPLOYING','STOPPING') AND version=$4 AND worker_id=$5 AND worker_lease_until>now()`

func (r *PostgresRepository) MarkFailed(ctx context.Context, item Workload, code, message string) error {
	if len(message) > 512 {
		message = message[:512]
	}
	if r.eventLog == nil {
		command, err := r.pool.Exec(ctx, markFailedSQL, item.WorkloadID, code, message, item.Version, item.WorkerID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, markFailedSQL, item.WorkloadID, code, message, item.Version, item.WorkerID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := r.appendEvent(ctx, tx, item, "FAILED", []byte(code+": "+message)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const workloadColumns = `workload_id::text, request_id::text, request_hash, definition, COALESCE(resource_hash,'\x'::bytea), image, COALESCE(vm_image_sha256,''), state, COALESCE(provider_id,''), COALESCE(lease_id::text,''), COALESCE(container_id,''), COALESCE(error_code,''), COALESCE(stop_request_id::text,''), created_at, updated_at, COALESCE(worker_id,''), worker_lease_until, version, attempt_count, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb, COALESCE(owner_id::text,''), reserved_ingress_mbps, reserved_egress_mbps, COALESCE(project_id::text,''), COALESCE(lease_block_hash,'\x'::bytea)`
const selectWorkload = `SELECT ` + workloadColumns + ` FROM workloads`
const returningWorkload = `w.workload_id::text, w.request_id::text, w.request_hash, w.definition, COALESCE(w.resource_hash,'\x'::bytea), w.image, COALESCE(w.vm_image_sha256,''), w.state, COALESCE(w.provider_id,''), COALESCE(w.lease_id::text,''), COALESCE(w.container_id,''), COALESCE(w.error_code,''), COALESCE(w.stop_request_id::text,''), w.created_at, w.updated_at, COALESCE(w.worker_id,''), w.worker_lease_until, w.version, w.attempt_count, w.reserved_cpu_millicores, w.reserved_ram_mb, w.reserved_storage_gb, COALESCE(w.owner_id::text,''), w.reserved_ingress_mbps, w.reserved_egress_mbps, COALESCE(w.project_id::text,''), COALESCE(w.lease_block_hash,'\x'::bytea)`

type scanner interface{ Scan(...any) error }

func scanWorkload(row scanner) (Workload, error) {
	var w Workload
	var hash, resourceHash, leaseBlockHash []byte
	var workerLeaseUntil *time.Time
	err := row.Scan(&w.WorkloadID, &w.RequestID, &hash, &w.Definition, &resourceHash, &w.Image, &w.VmImageSha256, &w.State, &w.ProviderID, &w.LeaseID, &w.ContainerID, &w.ErrorCode, &w.StopRequestID, &w.CreatedAt, &w.UpdatedAt, &w.WorkerID, &workerLeaseUntil, &w.Version, &w.AttemptCount, &w.ReservedCPUMillicores, &w.ReservedRAMMB, &w.ReservedStorageGB, &w.OwnerID, &w.ReservedIngressMbps, &w.ReservedEgressMbps, &w.ProjectID, &leaseBlockHash)
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
	if len(leaseBlockHash) != 0 {
		if len(leaseBlockHash) != 32 {
			return Workload{}, errors.New("invalid stored lease block hash")
		}
		copy(w.LeaseBlockHash[:], leaseBlockHash)
	}
	if workerLeaseUntil != nil {
		w.WorkerLeaseUntil = *workerLeaseUntil
	}
	return w, nil
}
