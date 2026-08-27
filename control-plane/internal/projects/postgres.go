package projects

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenWorkloadStates mirrors internal/workloadapi's own "open,
// provider-assigned" state list (see migration 000008's covering index)
// -- a workload that has left this set (COMPLETED/FAILED, or never
// scheduled at all) no longer holds a claim against its project's quota,
// the same way it no longer holds one against its provider's capacity.
//
// Exported (not just used internally by CommittedUsage below) so a
// caller that must reproduce this exact scoping inside its own
// transaction -- e.g. internal/openstackapi/cinder.PostgresRepository.
// CreateVolume, which cannot call CommittedUsage directly without a
// second pool connection alongside the one already held by its FOR
// UPDATE transaction (a real deadlock risk under a small connection
// pool: the transaction's own connection is busy holding the lock, and
// CommittedUsage would need to acquire another one just to read through
// it) -- uses the exact same list, not a second, hand-copied one that
// could silently drift.
var OpenWorkloadStates = []string{"LEASE_PENDING", "LEASED", "DEPLOYING", "RUNNING"}

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) CreateProject(ctx context.Context, name, description string) (Project, error) {
	project := Project{ProjectID: uuid.NewString(), Name: name, Description: description, Enabled: true}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO projects (project_id, name, description, enabled) VALUES ($1,$2,$3,true)
		 RETURNING created_at`,
		project.ProjectID, project.Name, project.Description).Scan(&project.CreatedAt)
	if isUniqueViolation(err) {
		return Project{}, ErrProjectNameTaken
	}
	if err != nil {
		return Project{}, err
	}
	return project, nil
}

func (r *PostgresRepository) GetProject(ctx context.Context, projectID string) (Project, error) {
	return r.scanProject(ctx, `SELECT project_id, name, description, enabled, created_at FROM projects WHERE project_id = $1`, projectID)
}

func (r *PostgresRepository) GetProjectByName(ctx context.Context, name string) (Project, error) {
	return r.scanProject(ctx, `SELECT project_id, name, description, enabled, created_at FROM projects WHERE name = $1`, name)
}

func (r *PostgresRepository) scanProject(ctx context.Context, query string, arg string) (Project, error) {
	var project Project
	err := r.pool.QueryRow(ctx, query, arg).Scan(&project.ProjectID, &project.Name, &project.Description, &project.Enabled, &project.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrProjectNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return project, nil
}

// AddMembership upserts: a repeat grant for the same (project, user)
// changes the role rather than erroring, matching userauth.SetRole's
// "grant path is also the revoke/change path" precedent.
func (r *PostgresRepository) AddMembership(ctx context.Context, projectID, userID, role string) error {
	command, err := r.pool.Exec(ctx, `
		INSERT INTO project_memberships (project_id, user_id, role)
		VALUES ($1,$2,$3)
		ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		projectID, userID, role)
	if isForeignKeyViolation(err) {
		return ErrProjectNotFound
	}
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrProjectNotFound
	}
	return nil
}

func (r *PostgresRepository) GetMembership(ctx context.Context, projectID, userID string) (Membership, error) {
	var membership Membership
	err := r.pool.QueryRow(ctx, `
		SELECT project_id, user_id, role, created_at FROM project_memberships
		WHERE project_id = $1 AND user_id = $2`, projectID, userID).
		Scan(&membership.ProjectID, &membership.UserID, &membership.Role, &membership.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrNotAMember
	}
	if err != nil {
		return Membership{}, err
	}
	return membership, nil
}

func (r *PostgresRepository) SetQuota(ctx context.Context, quota Quota) error {
	command, err := r.pool.Exec(ctx, `
		INSERT INTO project_quotas (project_id, max_cpu_millicores, max_ram_mb, max_storage_gb, max_workloads, updated_at)
		VALUES ($1,$2,$3,$4,$5, now())
		ON CONFLICT (project_id) DO UPDATE SET
			max_cpu_millicores = EXCLUDED.max_cpu_millicores,
			max_ram_mb = EXCLUDED.max_ram_mb,
			max_storage_gb = EXCLUDED.max_storage_gb,
			max_workloads = EXCLUDED.max_workloads,
			updated_at = now()`,
		quota.ProjectID, quota.MaxCPUMillicores, quota.MaxRAMMB, quota.MaxStorageGB, quota.MaxWorkloads)
	if isForeignKeyViolation(err) {
		return ErrProjectNotFound
	}
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrProjectNotFound
	}
	return nil
}

func (r *PostgresRepository) GetQuota(ctx context.Context, projectID string) (Quota, bool, error) {
	var quota Quota
	quota.ProjectID = projectID
	err := r.pool.QueryRow(ctx, `
		SELECT max_cpu_millicores, max_ram_mb, max_storage_gb, max_workloads
		FROM project_quotas WHERE project_id = $1`, projectID).
		Scan(&quota.MaxCPUMillicores, &quota.MaxRAMMB, &quota.MaxStorageGB, &quota.MaxWorkloads)
	if errors.Is(err, pgx.ErrNoRows) {
		return Quota{}, false, nil
	}
	if err != nil {
		return Quota{}, false, err
	}
	return quota, true, nil
}

// CommittedUsage sums the exact reservation columns
// internal/workloadapi's own provider-capacity ledger already populates
// at workload-creation time (migrations 000008/000010) -- one shared
// notion of "how much does this workload actually claim," never a
// second, independently-computed number that could drift from it.
//
// StorageGB additionally folds in every live (non-deleted)
// cinder_volumes row's size_gb (migration 000021, ADR-034 §4: "a
// volume's size_gb counts against \[the project's quota\] at create
// time, the same commit-time reservation-ledger check … not a new
// enforcement mechanism") -- a volume's committed storage is real
// whether or not it is currently attached to any workload (ADR-034 §2:
// an `available` volume still occupies real provider disk once created),
// so this is not scoped by attachment state the way the workload sum
// above is scoped by OpenWorkloadStates.
func (r *PostgresRepository) CommittedUsage(ctx context.Context, projectID string) (Usage, error) {
	var usage Usage
	var workloadCount int64
	err := r.pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(w.reserved_cpu_millicores), 0),
			COALESCE(SUM(w.reserved_ram_mb), 0),
			COALESCE(SUM(w.reserved_storage_gb), 0)
				+ (SELECT COALESCE(SUM(size_gb), 0) FROM cinder_volumes WHERE project_id = $1 AND deleted_at IS NULL),
			COUNT(*)
		FROM workloads w
		WHERE w.project_id = $1 AND w.state = ANY($2)`,
		projectID, OpenWorkloadStates).
		Scan(&usage.CPUMillicores, &usage.RAMMB, &usage.StorageGB, &workloadCount)
	if err != nil {
		return Usage{}, err
	}
	usage.Workloads = int32(workloadCount)
	return usage, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
