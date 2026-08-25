package projects

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openWorkloadStates mirrors internal/workloadapi's own "open,
// provider-assigned" state list (see migration 000008's covering index)
// -- a workload that has left this set (COMPLETED/FAILED, or never
// scheduled at all) no longer holds a claim against its project's quota,
// the same way it no longer holds one against its provider's capacity.
var openWorkloadStates = []string{"LEASE_PENDING", "LEASED", "DEPLOYING", "RUNNING"}

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
func (r *PostgresRepository) CommittedUsage(ctx context.Context, projectID string) (Usage, error) {
	var usage Usage
	var workloadCount int64
	err := r.pool.QueryRow(ctx, `
		SELECT
			COALESCE(SUM(reserved_cpu_millicores), 0),
			COALESCE(SUM(reserved_ram_mb), 0),
			COALESCE(SUM(reserved_storage_gb), 0),
			COUNT(*)
		FROM workloads
		WHERE project_id = $1 AND state = ANY($2)`,
		projectID, openWorkloadStates).
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
