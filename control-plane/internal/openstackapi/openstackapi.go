// Package openstackapi is the OpenStack-compatible HTTP surface ADR-031
// §2 places inside the existing Control Plane binary: a third wire
// protocol served alongside ControlPlaneService's gRPC+mTLS and
// internal/dashboard's HTTP/JSON API, on its own listener.
//
// This package is a pure translation layer, following ADR-031 §2's
// component-boundary reasoning: every handler converts an
// OpenStack-shaped HTTP request into calls against the same internal Go
// packages (internal/userauth, internal/projects, and -- once #24-#26
// land -- internal/workloadapi/internal/scheduler/internal/orchestrator)
// the gRPC server and internal/dashboard already call. No new
// authoritative store beyond migration 000017's projects/
// project_memberships/project_quotas tables.
//
// Structure, for #24 (Nova), #25 (Neutron), and #26 (Glance/Cinder) to
// extend: each gets its own subpackage under internal/openstackapi
// (internal/openstackapi/nova, /neutron, /glance, /cinder), matching
// internal/openstackapi/keystone's shape -- a Server type built by New,
// routes added to a *http.ServeMux via a Register method, and (for any
// route needing an authenticated caller) internal/openstackapi/osauth's
// RequireToken middleware, already built as this package's reusable
// piece rather than something keystone kept to itself. Wiring a new
// subpackage in means: construct its Server in this package's New (or
// pass through whatever dependencies it needs), call its Register from
// Handler below, and add its catalog entry in
// keystone/response.go's serviceCatalog. That's the whole diff --
// keystone's own routes and handlers are untouched by it.
//
// internal/openstackapi/glance (issue #26's Glance subset) is the first
// subpackage to follow that shape: a project-scoped image-registry
// surface with its own migration-000018-backed table, wired in below the
// same way. It owns its own Repository (glance.NewPostgresRepository),
// constructed here from the pool this package already has, rather than
// threaded through New's signature -- no other component needs to
// construct a glance.Repository, unlike users/projectsRepo above, which
// internal/dashboard and the gRPC server also need.
package openstackapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/glance"
	"github.com/openinfra/network/internal/openstackapi/keystone"
	"github.com/openinfra/network/internal/openstackapi/neutron"
	"github.com/openinfra/network/internal/openstackapi/nova"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/workloadapi"
)

// RateLimiter is satisfied by internal/ratelimit.RedisLimiter -- named
// locally rather than importing that package's own interface, matching
// internal/dashboard's identical RateLimiter interface (dashboard.go)
// so neither HTTP-surface package couples to Redis directly.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// Server composes every internal/openstackapi/* service surface. Built
// once by cmd/controlplane/main.go, the same construction shape
// internal/dashboard.New/Server.Handler already use.
type Server struct {
	pool     *pgxpool.Pool
	keystone *keystone.Server
	nova     *nova.Server
	neutron  *neutron.Server
	glance   *glance.Server
	limiter  RateLimiter
}

// New builds a Server. baseURL is this Control Plane's own
// internal/openstackapi listener address (e.g.
// "https://control-plane.example:8087"), used only to fill in the
// service catalog's endpoint URLs (keystone/response.go). limiter may be
// nil (unlimited) -- issueToken is the one unauthenticated,
// real-work-per-request route on this surface, the same shape
// internal/dashboard's authChallenge/authLogin rate limiting already
// follows.
//
// workloads/workloadStore/directory are #24's addition (internal/
// openstackapi/nova): the exact *workloadapi.Service, *workloadapi.
// PostgresRepository, and *agentmanager.Directory instances
// cmd/controlplane/main.go already constructs and shares with the gRPC
// ControlPlaneService, internal/dashboard, and internal/orchestrator --
// so a Nova-created server runs through the identical
// validation/scheduling/deploy path any other workload does, per
// ADR-031 §4's "no parallel execution model." The same directory also
// backs internal/openstackapi/neutron's availability-zone listing
// (ADR-026) as its ZoneLister -- one live view of "which zones are
// providers actually declaring right now," not a second one either
// package maintains independently.
func New(pool *pgxpool.Pool, users userauth.Repository, projectsRepo projects.Repository, workloads *workloadapi.Service, workloadStore *workloadapi.PostgresRepository, directory *agentmanager.Directory, baseURL string, limiter RateLimiter) *Server {
	audit := newAuditRecorder(pool)
	return &Server{
		pool:     pool,
		keystone: keystone.New(users, projectsRepo, baseURL, audit),
		nova:     nova.New(pool, users, projectsRepo, workloads, workloadStore, directory, nova.DefaultFlavors),
		neutron:  neutron.New(users, neutron.NewPostgresBandwidthRepository(pool), neutron.NewPostgresUsageRepository(pool), directory),
		glance:   glance.New(users, glance.NewPostgresRepository(pool), glance.AuditRecorder(audit)),
		limiter:  limiter,
	}
}

// Handler builds the *http.ServeMux every internal/openstackapi/*
// package registers into, wrapped in the same security-header/no-store
// discipline internal/dashboard.Handler already applies to its own
// mux -- this is a JSON API surface, never an HTML one, so the CSP is
// tighter (no script-src/style-src exceptions needed at all).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", s.ready)
	s.keystone.Register(mux)
	s.nova.Register(mux)
	s.neutron.Register(mux)
	s.glance.Register(mux)
	return rateLimitTokenIssuance(s.limiter, securityHeaders(mux))
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not_ready","postgres":"unavailable"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// rateLimitTokenIssuance applies limiter to POST /v3/auth/tokens only,
// keyed by caller IP -- the one unauthenticated, real-work route on this
// surface (every other route already requires a valid token, so
// internal/ratelimit's per-user limiting inside those handlers would be
// redundant with this). Fails closed: a limiter error denies the
// request, matching internal/dashboard.Server.allowRate's identical
// choice.
func rateLimitTokenIssuance(limiter RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter == nil || r.Method != http.MethodPost || r.URL.Path != "/v3/auth/tokens" {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		allowed, err := limiter.Allow(ctx, "openstack-token-issue:"+clientIP(r))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":503,"title":"Service Unavailable","message":"rate limiter unavailable"}}`))
			return
		}
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":429,"title":"Too Many Requests","message":"rate limit exceeded"}}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// newAuditRecorder adapts pool into the keystone.AuditRecorder shape,
// appending to the same audit_events table (migration 000014)
// internal/dashboard's own recordAudit writes to -- one audit trail for
// every authenticated write action reachable through either HTTP
// surface, not two. Best-effort by the same reasoning
// dashboard.recordAudit's doc comment already states: a failed audit
// write must not fail (or retroactively un-perform) the action it was
// describing.
func newAuditRecorder(pool *pgxpool.Pool) keystone.AuditRecorder {
	return func(ctx context.Context, actorUserID, action, targetType, targetID, outcome string) {
		if actorUserID == "" {
			// No resolved identity (e.g. authentication itself failed) --
			// audit_events.actor_user_id is NOT NULL, and there is no
			// "unknown actor" placeholder worth inventing; the outcome is
			// still observable via denied gRPC/HTTP logs elsewhere.
			return
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO audit_events (event_id, occurred_at, actor_user_id, actor_role, action, target_type, target_id, outcome)
			VALUES ($1, now(), $2, '', $3, $4, $5, $6)`,
			uuid.NewString(), actorUserID, action, targetType, targetID, outcome)
		if err != nil {
			slog.Error("openstackapi: audit event could not be recorded", "action", action, "target_type", targetType, "outcome", outcome, "error", err)
		}
	}
}
