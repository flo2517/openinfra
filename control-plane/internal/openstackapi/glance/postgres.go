package glance

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

func (r *PostgresRepository) CreateImage(ctx context.Context, image Image) (Image, error) {
	image.ImageID = uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO glance_images (image_id, project_id, name, source_ref, digest_sha256, size_bytes, visibility)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING created_at, updated_at`,
		image.ImageID, image.ProjectID, image.Name, image.SourceRef, image.DigestSHA256, image.SizeBytes, image.Visibility,
	).Scan(&image.CreatedAt, &image.UpdatedAt)
	if err != nil {
		return Image{}, err
	}
	return image, nil
}

// GetImage returns ErrNotFound unless imageID names a row projectID may
// see -- its own (any visibility) or another project's public one. The
// visibility check happens in the SQL WHERE clause, not after the fact
// in Go, so there is no window where a caller briefly holds a private
// row it should never have been handed.
func (r *PostgresRepository) GetImage(ctx context.Context, imageID, projectID string) (Image, error) {
	var image Image
	err := r.pool.QueryRow(ctx, `
		SELECT image_id, project_id, name, source_ref, digest_sha256, size_bytes, visibility, created_at, updated_at
		FROM glance_images
		WHERE image_id = $1 AND (project_id = $2 OR visibility = 'public')`,
		imageID, projectID).
		Scan(&image.ImageID, &image.ProjectID, &image.Name, &image.SourceRef, &image.DigestSHA256, &image.SizeBytes, &image.Visibility, &image.CreatedAt, &image.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Image{}, ErrNotFound
	}
	if err != nil {
		return Image{}, err
	}
	return image, nil
}

func (r *PostgresRepository) ListImages(ctx context.Context, projectID string) ([]Image, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT image_id, project_id, name, source_ref, digest_sha256, size_bytes, visibility, created_at, updated_at
		FROM glance_images
		WHERE project_id = $1 OR visibility = 'public'
		ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	images := make([]Image, 0)
	for rows.Next() {
		var image Image
		if err := rows.Scan(&image.ImageID, &image.ProjectID, &image.Name, &image.SourceRef, &image.DigestSHA256, &image.SizeBytes, &image.Visibility, &image.CreatedAt, &image.UpdatedAt); err != nil {
			return nil, err
		}
		images = append(images, image)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return images, nil
}

// DeleteImage returns ErrNotFound unless imageID names a row owned by
// projectID -- deliberately stricter than GetImage's WHERE clause:
// visibility controls who may see an image, never who may delete
// someone else's, even a public one.
func (r *PostgresRepository) DeleteImage(ctx context.Context, imageID, projectID string) error {
	command, err := r.pool.Exec(ctx, `DELETE FROM glance_images WHERE image_id = $1 AND project_id = $2`, imageID, projectID)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
