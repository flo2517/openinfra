package cinder

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

const selectVolume = `
	SELECT volume_id, project_id, name, size_gb, state, provider_id, attached_workload_id, mount_path, read_only, encrypted, created_at
	FROM cinder_volumes`

func scanVolume(row pgx.Row) (Volume, error) {
	var v Volume
	err := row.Scan(&v.VolumeID, &v.ProjectID, &v.Name, &v.SizeGB, &v.State, &v.ProviderID, &v.AttachedWorkloadID, &v.MountPath, &v.ReadOnly, &v.Encrypted, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Volume{}, ErrNotFound
	}
	if err != nil {
		return Volume{}, err
	}
	return v, nil
}

func (r *PostgresRepository) CreateVolume(ctx context.Context, volume Volume) (Volume, error) {
	volume.VolumeID = uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO cinder_volumes (volume_id, project_id, name, size_gb, state)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING created_at`,
		volume.VolumeID, volume.ProjectID, volume.Name, volume.SizeGB, StateAvailable,
	).Scan(&volume.CreatedAt)
	if err != nil {
		return Volume{}, err
	}
	volume.State = StateAvailable
	return volume, nil
}

// GetVolume returns ErrNotFound unless volumeID names a live row owned
// by projectID -- unlike internal/openstackapi/glance's identical-shaped
// GetImage, there is no "OR visibility = 'public'" branch: a Cinder
// volume in this slice is never visible cross-project at all (ADR-034
// §8).
func (r *PostgresRepository) GetVolume(ctx context.Context, volumeID, projectID string) (Volume, error) {
	return scanVolume(r.pool.QueryRow(ctx, selectVolume+` WHERE volume_id = $1 AND project_id = $2 AND deleted_at IS NULL`, volumeID, projectID))
}

func (r *PostgresRepository) ListVolumes(ctx context.Context, projectID string) ([]Volume, error) {
	rows, err := r.pool.Query(ctx, selectVolume+` WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	volumes := make([]Volume, 0)
	for rows.Next() {
		volume, err := scanVolume(rows)
		if err != nil {
			return nil, err
		}
		volumes = append(volumes, volume)
	}
	return volumes, rows.Err()
}

// AttachVolume is the single atomic statement that is issue #26's
// double-attachment guard: the WHERE clause's state='available' check
// and the SET that flips it to 'in-use' happen in the same UPDATE, so
// two concurrent attach attempts against the same volume can never both
// succeed -- exactly one UPDATE affects a row, the other affects zero
// and falls into the diagnostic branch below. The provider-mismatch
// check (COALESCE(provider_id, $3) = $3, i.e. "unset, or already this
// provider") is in the same WHERE clause for the identical reason.
func (r *PostgresRepository) AttachVolume(ctx context.Context, volumeID, projectID, providerID, workloadID, mountPath string, readOnly bool) (Volume, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE cinder_volumes
		SET state = 'in-use', provider_id = $3, attached_workload_id = $4, mount_path = $5, read_only = $6
		WHERE volume_id = $1 AND project_id = $2 AND deleted_at IS NULL AND state = 'available'
			AND (provider_id IS NULL OR provider_id = $3)
		RETURNING volume_id, project_id, name, size_gb, state, provider_id, attached_workload_id, mount_path, read_only, encrypted, created_at`,
		volumeID, projectID, providerID, workloadID, mountPath, readOnly)
	volume, err := scanVolume(row)
	if err == nil {
		return volume, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Volume{}, err
	}
	// The UPDATE above affected no row -- find out why, for a specific
	// error the handler can turn into the right status code. This lookup
	// is diagnostic only, not the security boundary (the atomic UPDATE
	// above already is): a state change racing with this SELECT can only
	// make the diagnosis stale, never let a double-attach slip through.
	existing, getErr := r.GetVolume(ctx, volumeID, projectID)
	if getErr != nil {
		return Volume{}, ErrNotFound
	}
	if existing.State != StateAvailable {
		return Volume{}, ErrNotAvailable
	}
	if existing.ProviderID != nil && *existing.ProviderID != providerID {
		return Volume{}, ErrProviderMismatch
	}
	return Volume{}, ErrNotAvailable
}

// DetachVolume is AttachVolume's mirror: the WHERE clause's
// state='in-use' AND attached_workload_id=$3 check and the SET that
// clears it happen in the same UPDATE.
func (r *PostgresRepository) DetachVolume(ctx context.Context, volumeID, projectID, workloadID string) (Volume, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE cinder_volumes
		SET state = 'available', attached_workload_id = NULL, mount_path = NULL, read_only = false
		WHERE volume_id = $1 AND project_id = $2 AND deleted_at IS NULL AND state = 'in-use' AND attached_workload_id = $3
		RETURNING volume_id, project_id, name, size_gb, state, provider_id, attached_workload_id, mount_path, read_only, encrypted, created_at`,
		volumeID, projectID, workloadID)
	volume, err := scanVolume(row)
	if err == nil {
		return volume, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Volume{}, err
	}
	if _, getErr := r.GetVolume(ctx, volumeID, projectID); getErr != nil {
		return Volume{}, ErrNotFound
	}
	return Volume{}, ErrNotAttached
}

func (r *PostgresRepository) BeginDelete(ctx context.Context, volumeID, projectID string) (Volume, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE cinder_volumes
		SET state = 'deleting'
		WHERE volume_id = $1 AND project_id = $2 AND deleted_at IS NULL AND state = 'available'
		RETURNING volume_id, project_id, name, size_gb, state, provider_id, attached_workload_id, mount_path, read_only, encrypted, created_at`,
		volumeID, projectID)
	volume, err := scanVolume(row)
	if err == nil {
		return volume, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Volume{}, err
	}
	if _, getErr := r.GetVolume(ctx, volumeID, projectID); getErr != nil {
		return Volume{}, ErrNotFound
	}
	return Volume{}, ErrNotAvailable
}

func (r *PostgresRepository) FinishDelete(ctx context.Context, volumeID string) error {
	command, err := r.pool.Exec(ctx, `UPDATE cinder_volumes SET deleted_at = now() WHERE volume_id = $1 AND state = 'deleting' AND deleted_at IS NULL`, volumeID)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PostgresRepository) AbortDelete(ctx context.Context, volumeID string) error {
	command, err := r.pool.Exec(ctx, `UPDATE cinder_volumes SET state = 'available' WHERE volume_id = $1 AND state = 'deleting' AND deleted_at IS NULL`, volumeID)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
