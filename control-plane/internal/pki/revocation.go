package pki

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// revokedSetKey is the single Redis key backing the live revocation set
// (ADR-027 §4): a set of provider_id strings, reconstructible at any time
// from providers.status = REVOKED in Postgres via Reconciler -- satisfying
// AGENTS.md's "Redis contains only reconstructible state" rule.
const revokedSetKey = "openinfra:revoked"

// RevocationChecker is consulted by both the TLS handshake's
// VerifyPeerCertificate callback and the unary interceptor on every RPC.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, providerID string) (bool, error)
}

// RedisRevocationStore is the ADR-027 §4 live revocation set.
type RedisRevocationStore struct {
	client redis.UniversalClient
}

func NewRedisRevocationStore(client redis.UniversalClient) *RedisRevocationStore {
	return &RedisRevocationStore{client: client}
}

func (s *RedisRevocationStore) IsRevoked(ctx context.Context, providerID string) (bool, error) {
	return s.client.SIsMember(ctx, revokedSetKey, providerID).Result()
}

// Add records providerID as revoked. Idempotent (SADD), never removed by
// this package -- ADR-027 names no un-revoke path, and reconciliation only
// ever adds entries a Postgres read confirms.
func (s *RedisRevocationStore) Add(ctx context.Context, providerID string) error {
	return s.client.SAdd(ctx, revokedSetKey, providerID).Err()
}

// RevokedProviderSource reads the authoritative (Postgres) set of revoked
// provider IDs for Reconciler to mirror into Redis.
type RevokedProviderSource interface {
	ListRevokedProviderIDs(ctx context.Context) ([]string, error)
}

// Reconciler periodically rebuilds the Redis revocation set from Postgres
// (ADR-027 §4: "a reconciliation sweep run at Control Plane startup and on
// a short period, e.g. every 30s"), so a flushed or cold-started Redis
// converges back to the authoritative state within one interval rather
// than silently granting connectivity back to a revoked provider.
type Reconciler struct {
	source   RevokedProviderSource
	store    *RedisRevocationStore
	interval time.Duration
}

func NewReconciler(source RevokedProviderSource, store *RedisRevocationStore, interval time.Duration) *Reconciler {
	return &Reconciler{source: source, store: store, interval: interval}
}

// DefaultReconcileInterval is ADR-027 §4's "e.g. every 30s."
const DefaultReconcileInterval = 30 * time.Second

// Run sweeps immediately, then on every tick, until ctx is cancelled. A
// read or write failure is logged and skipped for that tick -- transient
// Postgres/Redis unavailability must not crash the Control Plane process;
// the next tick tries again.
func (r *Reconciler) Run(ctx context.Context) {
	r.reconcileOnce(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcileOnce(ctx)
		}
	}
}

func (r *Reconciler) reconcileOnce(ctx context.Context) {
	ids, err := r.source.ListRevokedProviderIDs(ctx)
	if err != nil {
		slog.Warn("pki: revoked-provider reconciliation read failed", "error", err)
		return
	}
	for _, id := range ids {
		if err := r.store.Add(ctx, id); err != nil {
			slog.Warn("pki: revoked-provider reconciliation write failed", "provider_id", id, "error", err)
		}
	}
}
