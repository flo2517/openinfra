package frontendrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get for an unknown release_id.
var ErrNotFound = errors.New("frontendrelease: release not found")

// ErrNoActiveRelease is returned by Latest when every published release
// has been revoked (or none has ever been published) -- distinct from a
// read failure, the same "found vs. unavailable" discipline
// dashboard.go's ReputationSummary/OfferSummary already apply.
var ErrNoActiveRelease = errors.New("frontendrelease: no active (non-revoked) release published")

// Release is one row of the frontend_releases table
// (migrations/000022_frontend_releases.sql) -- the Postgres-authoritative
// record of a published, signed, content-addressed frontend release
// (ADR-037 §2/§7/§9).
type Release struct {
	ReleaseID           string
	CID                 string
	ManifestSHA256      string
	Signature           string
	APIOrigin           string
	AllowedLoginOrigins []string
	PreviousCID         string
	ReleasedAt          time.Time
	Manifest            Manifest
	RevokedAt           *time.Time
	RevokedReason       string
}

// FromManifest builds a Release row from a signed Manifest, ready to
// Publish.
func FromManifest(m Manifest) Release {
	return Release{
		ReleaseID:           m.ReleaseID,
		CID:                 m.CID,
		ManifestSHA256:      m.ManifestSHA256,
		Signature:           m.Signature,
		APIOrigin:           m.APIOrigin,
		AllowedLoginOrigins: m.AllowedLoginOrigins,
		PreviousCID:         m.PreviousCID,
		ReleasedAt:          mustParseTime(m.ReleasedAt),
		Manifest:            m,
	}
}

func mustParseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// Repository is the persistence surface frontendrelease needs --
// implemented by PostgresRepository in production, and by any fake in
// tests (internal/dashboard's wellknown_test.go and cors_test.go use one
// rather than requiring a live database for handler-shape tests).
type Repository interface {
	// Publish inserts a new release row. release.Manifest must already
	// be signed (frontendrelease.Sign) -- Publish does not itself verify
	// the signature; callers that need that guarantee call Verify first
	// (the frontendrelease CLI's `publish` subcommand does).
	Publish(ctx context.Context, release Release) error
	// Latest returns the newest non-revoked release, or ErrNoActiveRelease
	// if none exists.
	Latest(ctx context.Context) (Release, error)
	// Get returns a specific release by ID, revoked or not (ADR-037 §9
	// rollback needs to read an old, still-pinned release's own row to
	// republish a fresh manifest pointing at its CID).
	Get(ctx context.Context, releaseID string) (Release, error)
	// List returns up to limit releases, newest first, revoked or not --
	// ADR-037 §8's pinning/retention window and §9's rollback candidates.
	List(ctx context.Context, limit int) ([]Release, error)
	// Revoke marks a release row revoked (ADR-037 §7 takedown). Never
	// deletes the row -- see migrations/000022_frontend_releases.sql's
	// comment for why.
	Revoke(ctx context.Context, releaseID, reason string) error
}

// PostgresRepository is Repository backed by the frontend_releases table.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Publish(ctx context.Context, release Release) error {
	if release.Signature == "" {
		return fmt.Errorf("frontendrelease: refusing to publish an unsigned release")
	}
	origins, err := json.Marshal(release.AllowedLoginOrigins)
	if err != nil {
		return err
	}
	manifestJSON, err := json.Marshal(release.Manifest)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO frontend_releases
			(release_id, cid, manifest_sha256, signature, api_origin, allowed_login_origins, previous_cid, released_at, manifest_json)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9)`,
		release.ReleaseID, release.CID, release.ManifestSHA256, release.Signature,
		release.APIOrigin, origins, release.PreviousCID, release.ReleasedAt, manifestJSON,
	)
	if err != nil {
		return fmt.Errorf("frontendrelease: publish release %s: %w", release.ReleaseID, err)
	}
	return nil
}

func (r *PostgresRepository) Latest(ctx context.Context) (Release, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT release_id, cid, manifest_sha256, signature, api_origin, allowed_login_origins,
		       COALESCE(previous_cid, ''), released_at, manifest_json, revoked_at, COALESCE(revoked_reason, '')
		FROM frontend_releases
		WHERE revoked_at IS NULL
		ORDER BY released_at DESC
		LIMIT 1`)
	release, err := scanRelease(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrNoActiveRelease
	}
	if err != nil {
		return Release{}, fmt.Errorf("frontendrelease: load latest release: %w", err)
	}
	return release, nil
}

func (r *PostgresRepository) Get(ctx context.Context, releaseID string) (Release, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT release_id, cid, manifest_sha256, signature, api_origin, allowed_login_origins,
		       COALESCE(previous_cid, ''), released_at, manifest_json, revoked_at, COALESCE(revoked_reason, '')
		FROM frontend_releases WHERE release_id = $1`, releaseID)
	release, err := scanRelease(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	if err != nil {
		return Release{}, fmt.Errorf("frontendrelease: load release %s: %w", releaseID, err)
	}
	return release, nil
}

func (r *PostgresRepository) List(ctx context.Context, limit int) ([]Release, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.pool.Query(ctx, `
		SELECT release_id, cid, manifest_sha256, signature, api_origin, allowed_login_origins,
		       COALESCE(previous_cid, ''), released_at, manifest_json, revoked_at, COALESCE(revoked_reason, '')
		FROM frontend_releases ORDER BY released_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("frontendrelease: list releases: %w", err)
	}
	defer rows.Close()
	var releases []Release
	for rows.Next() {
		release, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
	}
	return releases, rows.Err()
}

func (r *PostgresRepository) Revoke(ctx context.Context, releaseID, reason string) error {
	if reason == "" {
		return fmt.Errorf("frontendrelease: a revocation reason is required (ADR-037 §7's own audit trail)")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE frontend_releases SET revoked_at = now(), revoked_reason = $2
		WHERE release_id = $1 AND revoked_at IS NULL`, releaseID, reason)
	if err != nil {
		return fmt.Errorf("frontendrelease: revoke release %s: %w", releaseID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRelease(row rowScanner) (Release, error) {
	var (
		release      Release
		originsJSON  []byte
		manifestJSON []byte
		revokedAt    *time.Time
		revokedRsn   string
	)
	if err := row.Scan(
		&release.ReleaseID, &release.CID, &release.ManifestSHA256, &release.Signature,
		&release.APIOrigin, &originsJSON, &release.PreviousCID, &release.ReleasedAt,
		&manifestJSON, &revokedAt, &revokedRsn,
	); err != nil {
		return Release{}, err
	}
	if err := json.Unmarshal(originsJSON, &release.AllowedLoginOrigins); err != nil {
		return Release{}, fmt.Errorf("frontendrelease: decode allowed_login_origins: %w", err)
	}
	if err := json.Unmarshal(manifestJSON, &release.Manifest); err != nil {
		return Release{}, fmt.Errorf("frontendrelease: decode manifest_json: %w", err)
	}
	release.RevokedAt = revokedAt
	release.RevokedReason = revokedRsn
	return release, nil
}
