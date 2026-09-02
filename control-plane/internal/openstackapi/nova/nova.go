// Package nova implements ADR-031 §4's Nova/Placement-compatible compute
// API (issue #24's non-VM half) over the existing Docker-workload
// execution model: a Nova "server" IS an existing internal/workloadapi
// workload, created/listed/shown/deleted through the exact
// SubmitWorkload/Get*/RequestStop* paths every other caller (gRPC
// ControlPlaneService, internal/dashboard's tenant-tier submit) already
// uses -- no parallel execution model, no new lease/deploy mechanism.
//
// This package deliberately does NOT implement a VM execution backend.
// ADR-031 §4 is explicit that the real libvirt/KVM half of issue #24 is
// out of scope here, gated on its own separate ADR extending ADR-006;
// nothing in this package, or anywhere else in this PR, touches
// provider-agent/crates/agent-executor's VM code paths.
//
// Non-goals named explicitly by ADR-031 §4's compute-mapping table and
// carried through unchanged here: console access (os-getConsoleOutput,
// VNC/serial -- no hypervisor, no equivalent Docker concept), live
// migration, in-place flavor resize, snapshots-as-images, nested-
// virtualization capability discovery, hw:* extra-specs/CPU pinning/NUMA
// topology. A real "reboot" action (ADR-031 §4's table names this as a
// stop-and-redeploy approximation) is also left unimplemented in this
// slice: this system has no callable "redeploy a STOPPED workload"
// primitive outside internal/orchestrator's own worker state machine
// today, and half-approximating one behind a wire-compatible "reboot"
// verb without a real restart underneath would be exactly the kind of
// silent, misleading success path AGENTS.md's "no placeholder success
// paths" rule forbids -- an unimplemented operation returns Nova's own
// "not implemented" shape instead (see writeNovaError's doc comment).
package nova

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/glance"
	"github.com/openinfra/network/internal/openstackapi/osauth"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/workloadapi"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
)

// WorkloadSubmitter is the subset of *workloadapi.Service this package
// needs. Create goes through the exact SubmitWorkload path every other
// caller already uses, so validation, request hashing, idempotency, and
// capacity reservation are never duplicated here -- the same "no business
// logic lives here" discipline internal/dashboard's own submitMyWorkload
// documents for its identical wrapping of SubmitWorkload.
type WorkloadSubmitter interface {
	SubmitWorkload(ctx context.Context, request *controlplanev1.SubmitWorkloadRequest) (*controlplanev1.SubmitWorkloadResponse, error)
}

// WorkloadStore is the subset of *workloadapi.PostgresRepository this
// package needs for list/get/delete and Placement's usage reporting --
// the project-scoped reads/writes added alongside this package
// specifically for ADR-031 §3's "every OpenStack-facing query scopes by
// project_id the same literal way internal/workloadapi already scopes by
// owner_id" rule.
type WorkloadStore interface {
	GetByProject(ctx context.Context, workloadID, projectID string) (workloadapi.Workload, error)
	ListByProject(ctx context.Context, projectID string) ([]workloadapi.Workload, error)
	RequestStopByProject(ctx context.Context, workloadID, requestID, projectID string, now time.Time) (workloadapi.Workload, error)
	ProviderReservedTotals(ctx context.Context, providerID string) (cpuMillicores, ramMB, storageGB, ingressMbps, egressMbps int64, err error)
}

// ProviderDirectory is the subset of *agentmanager.Directory this
// package's Placement-shaped resource_providers/inventories/usages
// endpoints need -- the same schedulable-provider list
// internal/orchestrator's own scheduling pass reads (ADR-031 §4:
// "Placement's API is a read/translation shim over data this system
// already computes, not a new ledger"). Declared locally, structurally
// satisfied by *agentmanager.Directory, rather than imported from
// internal/orchestrator: this translation-layer package must not depend
// on the orchestrator package.
type ProviderDirectory interface {
	ListSchedulableProviders(ctx context.Context) ([]agentmanager.SchedulableProvider, error)
}

// ImageLookup is the subset of *glance.PostgresRepository this package
// needs to resolve a server-create request's imageRef through #26's
// already-merged Glance image registry (internal/openstackapi/glance)
// instead of trusting a caller-supplied digest reference directly (the
// remaining Glance-integration gap named in issue #24). GetImage already
// scopes by project -- the caller's own image (any visibility) or another
// project's public one -- and collapses "doesn't exist" and "exists but
// isn't this caller's to see" into the identical glance.ErrNotFound; that
// exact behavior is reused here verbatim (not duplicated), so an imageRef
// naming an unknown or foreign-project-private image is rejected the same
// way Glance's own GET /v2/images/{image_id} already rejects it -- no
// second, independently-drifting scoping check.
type ImageLookup interface {
	GetImage(ctx context.Context, imageID, projectID string) (glance.Image, error)
}

// Server holds nova's handler dependencies. Constructed once by
// internal/openstackapi.New and registered via Register, matching
// internal/openstackapi/keystone.Server's exact shape.
type Server struct {
	pool      *pgxpool.Pool
	users     osauth.TokenAuthenticator
	projects  projects.Repository
	submitter WorkloadSubmitter
	store     WorkloadStore
	directory ProviderDirectory
	images    ImageLookup
	flavors   []Flavor
	now       func() time.Time
}

// New builds a nova Server. flavors may be nil, in which case
// DefaultFlavors is used -- the task's own "fixed/configurable catalog"
// requirement: fixed by default, configurable by a caller that wants a
// different list. images is internal/openstackapi.New's shared
// glance.Repository instance (the exact one glance.Server itself is built
// with) -- not a second, independently-constructed one -- so a server
// create and a direct Glance lookup always see the identical image state.
func New(pool *pgxpool.Pool, users osauth.TokenAuthenticator, projectsRepo projects.Repository, submitter WorkloadSubmitter, store WorkloadStore, directory ProviderDirectory, images ImageLookup, flavors []Flavor) *Server {
	if flavors == nil {
		flavors = DefaultFlavors
	}
	return &Server{pool: pool, users: users, projects: projectsRepo, submitter: submitter, store: store, directory: directory, images: images, flavors: flavors, now: time.Now}
}

// Register adds this package's routes to mux, the same pattern
// internal/openstackapi/keystone.Server.Register already establishes.
//
// Nova's own server/flavor routes carry a legacy, still-wire-compatible
// {project_id} path segment (Nova's 2.1-baseline URL shape,
// `/v2.1/{tenant_id}/...` -- ADR-031 §1 names 2.1 as the baseline
// microversion this slice targets) -- requireProjectScope checks that
// segment against the caller's token scope on every request, which is
// also this package's mechanism for a real, wire-authentic 403 across a
// project boundary (see that function's doc comment). Placement's own
// routes (/resource_providers, /allocations/{consumer_uuid}) keep real
// Placement's flat, non-project-prefixed URL shape instead.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v2.1/{project_id}/flavors", osauth.RequireToken(s.users, withMicroversion(s.listFlavors)))
	mux.HandleFunc("GET /v2.1/{project_id}/flavors/detail", osauth.RequireToken(s.users, withMicroversion(s.listFlavorsDetail)))
	mux.HandleFunc("GET /v2.1/{project_id}/flavors/{flavor_id}", osauth.RequireToken(s.users, withMicroversion(s.showFlavor)))

	mux.HandleFunc("POST /v2.1/{project_id}/servers", osauth.RequireToken(s.users, withMicroversion(s.createServer)))
	mux.HandleFunc("GET /v2.1/{project_id}/servers", osauth.RequireToken(s.users, withMicroversion(s.listServers)))
	mux.HandleFunc("GET /v2.1/{project_id}/servers/detail", osauth.RequireToken(s.users, withMicroversion(s.listServersDetail)))
	mux.HandleFunc("GET /v2.1/{project_id}/servers/{server_id}", osauth.RequireToken(s.users, withMicroversion(s.showServer)))
	mux.HandleFunc("DELETE /v2.1/{project_id}/servers/{server_id}", osauth.RequireToken(s.users, withMicroversion(s.deleteServer)))
	mux.HandleFunc("GET /v2.1/{project_id}/servers/{server_id}/metadata", osauth.RequireToken(s.users, withMicroversion(s.serverMetadata)))

	mux.HandleFunc("GET /resource_providers", osauth.RequireToken(s.users, s.listResourceProviders))
	mux.HandleFunc("GET /resource_providers/{uuid}/inventories", osauth.RequireToken(s.users, s.resourceProviderInventories))
	mux.HandleFunc("GET /resource_providers/{uuid}/usages", osauth.RequireToken(s.users, s.resourceProviderUsages))
	mux.HandleFunc("GET /allocations/{consumer_uuid}", osauth.RequireToken(s.users, s.allocationsForConsumer))
}

// requireProjectScope resolves the caller's identity (attached by
// osauth.RequireToken, which must wrap every route this is called from)
// and checks it against the {project_id} path segment every /v2.1/ route
// carries.
//
// A mismatch -- including an unscoped token, which has no project to
// match against -- fails closed with Nova's own "forbidden" fault shape
// (writeNovaError), a domain-level authorization decision made after
// authentication has already succeeded, not osauth.RequireToken's own
// authentication-layer 401: the caller presented a genuinely valid token,
// they simply are not authorized to act as the project named in the URL
// they chose. This is deliberately a 403, not a 404: unlike
// internal/dashboard's own owner-scoped lookups (which 404 a foreign
// workload to avoid confirming its existence, see myWorkload's doc
// comment), the project_id here is a value the caller supplied in the URL
// themselves -- returning 403 tells them nothing they did not already
// know, and is the acceptance criterion this task names explicitly
// ("403 across a project boundary"), while every *resource*-level lookup
// within a correctly-scoped project (GetByProject et al.) still 404s a
// nonexistent or foreign-project resource, for exactly the existence-
// oracle reason ADR-016 established.
func requireProjectScope(w http.ResponseWriter, r *http.Request) (identity osauth.Identity, projectID string, ok bool) {
	identity, found := osauth.FromContext(r.Context())
	if !found {
		// Programming error (a route registered without RequireToken), not
		// an expected runtime case -- same defensive posture
		// osauth.Identity's own doc comment describes for FromContext.
		writeNovaError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return osauth.Identity{}, "", false
	}
	pathProjectID := r.PathValue("project_id")
	if identity.ProjectID == nil {
		writeNovaError(w, http.StatusForbidden, "forbidden", "A project-scoped token is required to perform this operation.")
		return osauth.Identity{}, "", false
	}
	if *identity.ProjectID != pathProjectID {
		writeNovaError(w, http.StatusForbidden, "forbidden", "You are not authorized to perform the requested action on this project.")
		return osauth.Identity{}, "", false
	}
	return identity, pathProjectID, true
}

// MinMicroversion and MaxMicroversion are the only Nova API microversion
// this slice serves -- ADR-031 §1/§4 names 2.1 as the baseline
// microversion this ADR targets; there is no version-gated feature
// differences implemented above it yet, so Min and Max are deliberately
// equal today. Kept as two named constants (not one), and compared with
// real integer arithmetic (microversionInRange below), rather than a bare
// string-equality check, so widening this range later is a two-constant
// change, not a rewrite of the negotiation logic.
const (
	MinMicroversion = "2.1"
	MaxMicroversion = "2.1"
)

// withMicroversion is a minimal but real implementation of Nova's API
// microversion negotiation convention: a client may send
// `OpenStack-API-Version: compute X.Y` (or the older
// `X-OpenStack-Nova-API-Version: X.Y` header, still accepted by every
// real Nova deployment for backward compatibility) to request a specific
// microversion, or `compute latest` for the newest this deployment
// serves. No header at all defaults to MinMicroversion, matching real
// Nova's own "an unversioned request gets the oldest, most conservative
// behavior" default. A request naming a version outside
// [MinMicroversion, MaxMicroversion] is rejected with 406 Not Acceptable --
// real Nova's actual status code for an out-of-range microversion
// request -- rather than silently serving the closest version.
func withMicroversion(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requested, explicit := requestedMicroversion(r)
		negotiated := MinMicroversion
		if explicit {
			if requested == "latest" {
				negotiated = MaxMicroversion
			} else if microversionInRange(requested) {
				negotiated = requested
			} else {
				writeNovaError(w, http.StatusNotAcceptable, "badRequest",
					"Version "+requested+" is not supported by the API. Minimum is "+MinMicroversion+" and maximum is "+MaxMicroversion+".")
				return
			}
		}
		w.Header().Set("OpenStack-API-Version", "compute "+negotiated)
		w.Header().Set("X-OpenStack-Nova-API-Version", negotiated)
		w.Header().Add("Vary", "OpenStack-API-Version")
		next(w, r)
	}
}

func requestedMicroversion(r *http.Request) (version string, explicit bool) {
	if header := strings.TrimSpace(r.Header.Get("OpenStack-API-Version")); header != "" {
		parts := strings.Fields(header)
		if len(parts) == 2 && parts[0] == "compute" {
			return parts[1], true
		}
		return "", false
	}
	if header := strings.TrimSpace(r.Header.Get("X-OpenStack-Nova-API-Version")); header != "" {
		return header, true
	}
	return "", false
}

type microversion struct{ major, minor int }

func (a microversion) less(b microversion) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	return a.minor < b.minor
}

func parseMicroversion(s string) (microversion, bool) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return microversion{}, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
		return microversion{}, false
	}
	return microversion{major: major, minor: minor}, true
}

func microversionInRange(version string) bool {
	v, ok := parseMicroversion(version)
	if !ok {
		return false
	}
	min, _ := parseMicroversion(MinMicroversion)
	max, _ := parseMicroversion(MaxMicroversion)
	return !v.less(min) && !max.less(v)
}

// novaFault is real Nova's own error-body shape:
// {"<faultName>": {"code": ..., "message": ...}} -- deliberately distinct
// from Keystone's {"error": {...}} shape (osauth.WriteError). This
// matches real OpenStack's actual wire behavior, not an arbitrary choice:
// in a real deployment, keystonemiddleware's shared auth pipeline (the
// role osauth.RequireToken plays here) returns a Keystone-shaped 401
// before a request ever reaches nova-api's own handler code, while every
// domain-level error nova-api itself raises (404 on an unknown server,
// 403 on a policy/quota denial, 406 on an unsupported microversion, ...)
// uses this fault-wrapped shape instead. This package's own errors follow
// the identical split: osauth.RequireToken's 401 stays Keystone-shaped
// (authentication, shared middleware layer); everything this package's
// own handlers decide (authorization, validation, not-found,
// microversion negotiation) is Nova-shaped.
type novaFault struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeNovaError(w http.ResponseWriter, status int, faultName, message string) {
	writeJSON(w, status, map[string]novaFault{faultName: {Code: status, Message: message}})
}
