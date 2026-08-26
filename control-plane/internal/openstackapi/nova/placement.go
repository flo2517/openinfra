package nova

import (
	"context"
	"errors"
	"math"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// Placement resource classes this package reports -- the three
// dimensions this system's own capacity ledger already tracks
// (workloadapi.ProviderCapacity), mapped onto real Placement resource-
// class names. Real Placement supports many more (PCI_DEVICE, custom
// classes, ...); none of those have any signal in this system to report,
// so they are simply absent here rather than fabricated.
const (
	resourceClassVCPU     = "VCPU"
	resourceClassMemoryMB = "MEMORY_MB"
	resourceClassDiskGB   = "DISK_GB"
)

type resourceProviderBody struct {
	UUID       string     `json:"uuid"`
	Name       string     `json:"name"`
	Generation int        `json:"generation"`
	Links      []linkBody `json:"links"`
}

// requireAnyToken is Placement's own authorization posture in this slice:
// any valid, authenticated token, not scoped to a particular project.
// Real Placement resource-provider inventory is infrastructure-wide
// operator data (which providers exist, how much they have declared),
// not tenant-private data -- this system has no separate operator-tier
// token for the OpenStack surface yet (ADR-031 §3 bridges only
// internal/userauth's existing tenant-facing API keys), so restricting
// Placement reads to a role this surface cannot yet express would either
// lock every caller out or require inventing an authorization tier
// ADR-031 never decided. Documented here as the deliberate judgment call
// it is, not an oversight -- ADR-031 §4 itself calls Placement's mapping
// "read-focused", and a read of non-tenant-private infrastructure data is
// the least consequential thing to leave under-scoped in this slice.
func requireAnyToken(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := osauth.FromContext(r.Context()); !ok {
		writeNovaError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return false
	}
	return true
}

// listResourceProviders is GET /resource_providers: every currently
// schedulable provider (ProviderDirectory.ListSchedulableProviders, the
// same live source internal/orchestrator's own scheduling pass reads --
// ADR-031 §4's "a read/translation shim over data this system already
// computes, not a new ledger").
//
// provider_id in this system is sha256(public_key) hex-encoded, not an
// RFC 4122 UUID (ADR-031's own Context section flags this explicitly as
// an ID-mapping policy every OpenStack-compatible surface returning
// internal IDs must state). This package's policy: pass it through
// verbatim as Placement's "uuid" field. A real Placement client that
// strictly validates the uuid field as RFC 4122 would reject it; this is
// a known, disclosed wire-compatibility gap, not a silent
// misrepresentation -- inventing a synthetic UUID with no stable mapping
// back to the real provider_id would be worse: it would make this
// endpoint's data useless for cross-referencing against every other
// provider-identified surface in this system (the dashboard, the gRPC
// API, on-chain registry), which all use the real provider_id.
func (s *Server) listResourceProviders(w http.ResponseWriter, r *http.Request) {
	if !requireAnyToken(w, r) {
		return
	}
	providers, err := s.directory.ListSchedulableProviders(r.Context())
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "resource provider list unavailable")
		return
	}
	body := make([]resourceProviderBody, 0, len(providers))
	for _, provider := range providers {
		body = append(body, resourceProviderBody{
			UUID: provider.ProviderID, Name: provider.ProviderID, Generation: 1,
			Links: []linkBody{{Rel: "self", Href: "/resource_providers/" + provider.ProviderID}},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource_providers": body})
}

func (s *Server) findProvider(ctx context.Context, providerID string) (agentmanager.SchedulableProvider, bool, error) {
	providers, err := s.directory.ListSchedulableProviders(ctx)
	if err != nil {
		return agentmanager.SchedulableProvider{}, false, err
	}
	for _, provider := range providers {
		if provider.ProviderID == providerID {
			return provider, true, nil
		}
	}
	return agentmanager.SchedulableProvider{}, false, nil
}

type inventoryBody struct {
	Total           int64   `json:"total"`
	Reserved        int64   `json:"reserved"`
	MinUnit         int64   `json:"min_unit"`
	MaxUnit         int64   `json:"max_unit"`
	StepSize        int64   `json:"step_size"`
	AllocationRatio float64 `json:"allocation_ratio"`
}

// resourceProviderInventories is GET
// /resource_providers/{uuid}/inventories: each provider's declared total
// capacity (agentmanager.SchedulableProvider.Capabilities, the exact
// figures internal/orchestrator's own rankableCandidates already reads
// for scheduling), reported per Placement resource class. reserved is
// always 0 here -- this system's capacity ledger tracks reservations
// per-workload, not a provider-level pre-reservation the way real
// Placement's own `reserved` inventory field describes; usages (below)
// is where committed reservations are actually reported.
func (s *Server) resourceProviderInventories(w http.ResponseWriter, r *http.Request) {
	if !requireAnyToken(w, r) {
		return
	}
	providerID := r.PathValue("uuid")
	provider, found, err := s.findProvider(r.Context(), providerID)
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "resource provider lookup unavailable")
		return
	}
	if !found || provider.Capabilities == nil {
		writeNovaError(w, http.StatusNotFound, "itemNotFound", "No resource provider with uuid "+providerID+" found")
		return
	}
	cpuTotal := int64(math.Round(float64(provider.Capabilities.CpuTotal)))
	inventories := map[string]inventoryBody{
		resourceClassVCPU:     {Total: cpuTotal, MinUnit: 1, MaxUnit: maxOne(cpuTotal), StepSize: 1, AllocationRatio: 1.0},
		resourceClassMemoryMB: {Total: provider.Capabilities.RamTotalMb, MinUnit: 1, MaxUnit: maxOne(provider.Capabilities.RamTotalMb), StepSize: 1, AllocationRatio: 1.0},
		resourceClassDiskGB:   {Total: provider.Capabilities.StorageTotalGb, MinUnit: 1, MaxUnit: maxOne(provider.Capabilities.StorageTotalGb), StepSize: 1, AllocationRatio: 1.0},
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource_provider_generation": 1, "inventories": inventories})
}

// maxOne floors a Placement max_unit at 1 -- a provider that has declared
// zero of a resource class still needs a valid (non-zero) max_unit per
// Placement's own schema; 1 with total=0 already excludes any real
// allocation via the total, so this is a schema-validity floor, not a
// claim the provider actually has capacity.
func maxOne(v int64) int64 {
	if v < 1 {
		return 1
	}
	return v
}

// resourceProviderUsages is GET /resource_providers/{uuid}/usages: the
// same reservation aggregate AssignLease's atomic capacity check already
// computes inline (workloadapi.PostgresRepository.ProviderReservedTotals,
// added alongside this package specifically to expose that number
// read-only), reported per Placement resource class.
func (s *Server) resourceProviderUsages(w http.ResponseWriter, r *http.Request) {
	if !requireAnyToken(w, r) {
		return
	}
	providerID := r.PathValue("uuid")
	_, found, err := s.findProvider(r.Context(), providerID)
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "resource provider lookup unavailable")
		return
	}
	if !found {
		writeNovaError(w, http.StatusNotFound, "itemNotFound", "No resource provider with uuid "+providerID+" found")
		return
	}
	cpuMillicores, ramMB, storageGB, _, _, err := s.store.ProviderReservedTotals(r.Context(), providerID)
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "resource provider usage unavailable")
		return
	}
	usages := map[string]int64{
		// Rounded up to whole cores: Placement's VCPU resource class has no
		// millicore concept, and rounding a partially-consumed core down to
		// 0 would understate committed usage.
		resourceClassVCPU:     (cpuMillicores + 999) / 1000,
		resourceClassMemoryMB: ramMB,
		resourceClassDiskGB:   storageGB,
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource_provider_generation": 1, "usages": usages})
}

// allocationsForConsumer is GET /allocations/{consumer_uuid}: real
// Placement's own flat, non-project-prefixed URL shape -- consumer_uuid
// is this system's workload_id, since a Nova server IS a workload
// (ADR-031 §4). Authorization here cannot use requireProjectScope (there
// is no {project_id} path segment to check against, matching real
// Placement's own URL shape); instead the workload's own project_id is
// read directly from Postgres and compared to the caller's token scope --
// the same deny-on-mismatch decision requireProjectScope makes for the
// Nova routes, just sourced from the resource instead of the URL.
func (s *Server) allocationsForConsumer(w http.ResponseWriter, r *http.Request) {
	identity, ok := osauth.FromContext(r.Context())
	if !ok {
		writeNovaError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	consumerID := r.PathValue("consumer_uuid")
	var projectID, providerID string
	var cpuMillicores, ramMB, storageGB int64
	err := s.pool.QueryRow(r.Context(), `
		SELECT COALESCE(project_id::text,''), COALESCE(provider_id,''), reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb
		FROM workloads WHERE workload_id=$1`, consumerID).
		Scan(&projectID, &providerID, &cpuMillicores, &ramMB, &storageGB)
	if errors.Is(err, pgx.ErrNoRows) {
		// Real Placement's own behavior for an unknown consumer: 200 with
		// an empty allocations map, not 404 -- "this consumer holds no
		// allocations" is a valid, successful answer.
		writeJSON(w, http.StatusOK, map[string]any{"allocations": map[string]any{}})
		return
	}
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "allocation lookup unavailable")
		return
	}
	if identity.ProjectID == nil || projectID == "" || *identity.ProjectID != projectID {
		writeNovaError(w, http.StatusForbidden, "forbidden", "You are not authorized to perform the requested action on this project.")
		return
	}
	allocations := map[string]any{}
	if providerID != "" {
		allocations[providerID] = map[string]any{"resources": map[string]int64{
			resourceClassVCPU:     (cpuMillicores + 999) / 1000,
			resourceClassMemoryMB: ramMB,
			resourceClassDiskGB:   storageGB,
		}}
	}
	writeJSON(w, http.StatusOK, map[string]any{"allocations": allocations, "project_id": projectID})
}
