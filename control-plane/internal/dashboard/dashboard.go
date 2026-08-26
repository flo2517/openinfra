package dashboard

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/walletlogin"
	"github.com/openinfra/network/internal/workloadapi"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

//go:embed assets/*
var assets embed.FS

// RateLimiter is satisfied by internal/ratelimit.RedisLimiter -- named
// locally rather than importing that package's own interface, so this
// package doesn't couple to userauth's copy of the same tiny shape.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

type Server struct {
	pool    *pgxpool.Pool
	redis   redis.UniversalClient
	chain   *blockchainbridge.RPCClient
	wallet  *walletlogin.Service
	users   userauth.Repository
	limiter RateLimiter
	// workloads is the exact *workloadapi.Service instance
	// cmd/controlplane/main.go also wires into the gRPC
	// ControlPlaneService server -- submitMyWorkload (tenantviews.go)
	// calls its SubmitWorkload directly rather than duplicating
	// validateSubmission's checks or CreateOrGet's persistence here. Not
	// used to reach GetWorkload/StopWorkload: myWorkload/stopMyWorkload
	// already have their own, older, repository-level wiring
	// (workloadapi.NewPostgresRepository(s.pool)) and there is no reason
	// to disturb it for this change.
	workloads *workloadapi.Service
	now       func() time.Time
}

type Provider struct {
	fullID       string
	publicKey    []byte  // raw 32-byte on-chain key; reputation/offer lookups only, never serialized
	ProviderID   string  `json:"provider_id"`
	Status       string  `json:"status"`
	Liveness     string  `json:"liveness"`
	AgentVersion string  `json:"agent_version"`
	RegisteredAt string  `json:"registered_at"`
	HeartbeatAge *int64  `json:"heartbeat_age_seconds,omitempty"`
	CPUAvailable float32 `json:"cpu_available"`
	MemoryMB     int64   `json:"memory_available_mb"`
	// StorageAvailableGB/StorageTotalGB and IngressMbps/EgressMbps were
	// already decoded off every heartbeat (ResourceCapability carries
	// them) but never surfaced -- part of #14's "hardware/resource
	// inventory" provider view.
	StorageAvailableGB int64 `json:"storage_available_gb"`
	StorageTotalGB     int64 `json:"storage_total_gb"`
	IngressMbps        int32 `json:"bandwidth_ingress_mbps,omitempty"`
	EgressMbps         int32 `json:"bandwidth_egress_mbps,omitempty"`
	// ADR-033 §7 / issue #166: whether this provider passed the Agent's
	// fail-closed KVM probe and can be offered a VM workload. Surfaced
	// for operator visibility the same way IngressMbps/EgressMbps above
	// already are -- decoded off every heartbeat, previously unused here.
	VirtualizationCapable bool   `json:"virtualization_capable"`
	ChainState            string `json:"chain_state"`
	// Reputation/Offer are nil when not yet read (chain unavailable) --
	// see ReputationSummary/OfferSummary for the "no record yet" vs
	// "read failed" distinction within each.
	Reputation *ReputationSummary `json:"reputation,omitempty"`
	Offer      *OfferSummary      `json:"offer,omitempty"`
}

// ReputationSummary mirrors blockchainbridge.ReputationVector for display.
// Available is false when the provider has no on-chain reputation record
// yet (a normal, common state for a freshly joined provider) -- distinct
// from a read failure, which leaves Reputation nil on the Provider instead
// of fabricating an Available:true, all-zero record that would look like a
// proven-bad score.
type ReputationSummary struct {
	Available    bool   `json:"available"`
	Compute      uint32 `json:"compute"`
	Storage      uint32 `json:"storage"`
	Network      uint32 `json:"network"`
	Availability uint32 `json:"availability"`
	Reliability  uint32 `json:"reliability"`
	Global       uint32 `json:"global"`
}

// OfferSummary mirrors blockchainbridge.ResourceOffer for display. Found
// is false when pallet-resource-market has no finalized offer for this
// provider yet (e.g. the reconciler's first pass hasn't run) -- distinct
// from a read failure, which leaves Offer nil on the Provider.
type OfferSummary struct {
	Found         bool   `json:"found"`
	CPUMillicores uint32 `json:"cpu_millicores,omitempty"`
	RAMMB         uint64 `json:"ram_mb,omitempty"`
	StorageGB     uint64 `json:"storage_gb,omitempty"`
}

type Overview struct {
	GeneratedAt string `json:"generated_at"`
	// ProvidersTotal/WorkloadsTotal are true row counts (a separate
	// COUNT(*), not len(Providers)/len(Workloads)) -- #76's "pagination
	// and bounded cardinality" item: before this, a caller had no way to
	// tell "500 providers, all shown" apart from "500 providers, a page
	// of an unknown larger total" other than guessing from the hardcoded
	// LIMIT.
	ProvidersTotal  int `json:"providers_total"`
	ProvidersLimit  int `json:"providers_limit"`
	ProvidersOffset int `json:"providers_offset"`
	ProvidersFresh  int `json:"providers_fresh"`
	WorkloadsTotal  int `json:"workloads_total"`
	// WorkloadsByState replaces the per-workload list this endpoint used
	// to return (ADR-016 §3). Keys are workloads.state values; every
	// known state is present, including zero-count ones, so a client can
	// tell "no RUNNING workloads" from "this build doesn't report
	// RUNNING" without consulting the schema.
	WorkloadsByState map[string]int `json:"workloads_by_state"`
	CPUAvailable     float64        `json:"cpu_available"`
	MemoryMB         int64          `json:"memory_available_mb"`
	FinalizedBlock   uint64         `json:"finalized_block"`
	BestBlock        uint64         `json:"best_block"`
	ChainSyncing     bool           `json:"chain_syncing"`
	Partial          bool           `json:"partial"`
	Errors           []string       `json:"errors,omitempty"`
	Providers        []Provider     `json:"providers"`
	// ValidatorsActive is -1 when the read failed, so a client can tell
	// "no validators registered" (0) apart from "unavailable" (-1) --
	// ADR-011 requires never reporting false success on a degraded read.
	ValidatorsActive int      `json:"validators_active"`
	Validators       []string `json:"validators,omitempty"`
}

// emptyWorkloadStateCounts seeds every state workloads.state's CHECK
// constraint allows with an explicit zero, so a state with no rows is
// reported as 0 rather than being absent from the map -- the same
// no-false-success instinct operatorviews.go applies to its own
// per-state counts, and the reason a client can trust "0 RUNNING" here.
func emptyWorkloadStateCounts() map[string]int {
	counts := make(map[string]int, len(operatorWorkloadStates))
	for _, state := range operatorWorkloadStates {
		counts[state] = 0
	}
	return counts
}

// overviewPagination bounds /api/v1/overview's provider list. It used
// to bound a workload list too; ADR-016 §3 replaced that with
// WorkloadsByState, which is a fixed-size aggregate and needs no paging.
// The workloads_limit/workloads_offset query params are consequently
// gone -- a caller still passing them is simply ignored rather than
// erroring, matching boundedQueryInt's existing lenience about unusable
// values.
type overviewPagination struct {
	ProvidersLimit, ProvidersOffset int
}

const (
	defaultProvidersLimit = 500
	maxProvidersLimit     = 500
)

func parseOverviewPagination(r *http.Request) overviewPagination {
	query := r.URL.Query()
	return overviewPagination{
		ProvidersLimit:  boundedQueryInt(query, "providers_limit", defaultProvidersLimit, 1, maxProvidersLimit),
		ProvidersOffset: boundedQueryInt(query, "providers_offset", 0, 0, math.MaxInt32),
	}
}

// boundedQueryInt parses a query parameter to an int clamped to [min, max],
// falling back to fallback for a missing or unparsable value -- never an
// error response, since an operator-facing dashboard query param is not
// worth failing the whole request over; it just clamps to something safe.
func boundedQueryInt(query url.Values, key string, fallback, min, max int) int {
	raw := query.Get(key)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if parsed < min {
		return min
	}
	if parsed > max {
		return max
	}
	return parsed
}

func New(pool *pgxpool.Pool, redisClient redis.UniversalClient, chain *blockchainbridge.RPCClient, wallet *walletlogin.Service, users userauth.Repository, limiter RateLimiter, workloads *workloadapi.Service) *Server {
	return &Server{pool: pool, redis: redisClient, chain: chain, wallet: wallet, users: users, limiter: limiter, workloads: workloads, now: time.Now}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/overview", s.overview)
	mux.HandleFunc("POST /api/v1/auth/challenge", s.authChallenge)
	mux.HandleFunc("POST /api/v1/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/v1/auth/api-keys", s.authIssueAPIKey)
	mux.HandleFunc("GET /api/v1/me", s.authMe)
	mux.HandleFunc("GET /api/v1/agent-endpoint/{provider_id}", s.agentEndpoint)
	mux.HandleFunc("GET /api/v1/validator-scores/{provider_id}", s.validatorScores)
	mux.HandleFunc("GET /api/v1/validator/health", s.validatorHealth)
	mux.HandleFunc("GET /api/v1/validator/rounds/{provider_id}", s.validatorRounds)
	mux.HandleFunc("GET /api/v1/provider/{provider_id}/onchain", s.providerOnChain)
	mux.HandleFunc("GET /api/v1/my/workloads", s.requireRole(userauth.RoleTenant, s.myWorkloads))
	mux.HandleFunc("POST /api/v1/my/workloads", s.requireRole(userauth.RoleTenant, s.submitMyWorkload))
	mux.HandleFunc("GET /api/v1/my/workloads/{workload_id}", s.requireRole(userauth.RoleTenant, s.myWorkload))
	mux.HandleFunc("POST /api/v1/my/workloads/{workload_id}/stop", s.requireRole(userauth.RoleTenant, s.stopMyWorkload))
	mux.HandleFunc("GET /api/v1/operator/queue", s.requireRole(userauth.RoleOperatorReadOnly, s.operatorQueue))
	mux.HandleFunc("GET /api/v1/operator/workers", s.requireRole(userauth.RoleOperatorReadOnly, s.operatorWorkers))
	mux.HandleFunc("GET /api/v1/operator/audit", s.requireRole(userauth.RoleOperatorReadOnly, s.operatorAudit))
	mux.HandleFunc("GET /api/v1/operator/health", s.requireRole(userauth.RoleOperatorReadOnly, s.operatorHealth))
	mux.Handle("GET /dashboard/", http.StripPrefix("/dashboard/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/dashboard/", http.StatusTemporaryRedirect)
	})
	return securityHeaders(mux)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "postgres": "unavailable"})
		return
	}
	if err := s.redis.Ping(ctx).Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "redis": "unavailable"})
		return
	}
	if _, err := s.chain.Health(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "blockchain": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	result, err := s.loadOverview(ctx, parseOverviewPagination(r))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authoritative provider data unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) loadOverview(ctx context.Context, pagination overviewPagination) (Overview, error) {
	result := Overview{
		GeneratedAt:      s.now().UTC().Format(time.RFC3339),
		Providers:        []Provider{},
		WorkloadsByState: emptyWorkloadStateCounts(),
		ValidatorsActive: -1,
		ProvidersLimit:   pagination.ProvidersLimit,
		ProvidersOffset:  pagination.ProvidersOffset,
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM providers`).Scan(&result.ProvidersTotal); err != nil {
		return Overview{}, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.provider_id, p.public_key, p.status, p.agent_version, p.registered_at,
		       COALESCE(c.state, 'UNKNOWN')
		FROM providers p LEFT JOIN provider_chain_registrations c USING (provider_id)
		ORDER BY p.registered_at DESC LIMIT $1 OFFSET $2`, pagination.ProvidersLimit, pagination.ProvidersOffset)
	if err != nil {
		return Overview{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var p Provider
		var status int16
		var registered time.Time
		if err := rows.Scan(&p.ProviderID, &p.publicKey, &status, &p.AgentVersion, &registered, &p.ChainState); err != nil {
			return Overview{}, err
		}
		p.fullID = p.ProviderID
		p.ProviderID = abbreviate(p.ProviderID)
		p.Status = strings.TrimPrefix(sharedv1.NodeStatus(status).String(), "NODE_STATUS_")
		p.RegisteredAt = registered.UTC().Format(time.RFC3339)
		p.Liveness = "UNKNOWN"
		result.Providers = append(result.Providers, p)
	}
	if err := rows.Err(); err != nil {
		return Overview{}, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM workloads`).Scan(&result.WorkloadsTotal); err != nil {
		return Overview{}, err
	}
	// ADR-016 §3: this endpoint is Public tier, so it reports how many
	// workloads are in each state and nothing per-workload. It used to
	// return up to 100 rows of (workload_id, state, provider_id,
	// lease_id, created_at) to any unauthenticated caller -- none of
	// those fields is a secret on its own, but together they are exactly
	// the shape of "which tenants are using this network, and when."
	// Per-workload detail now lives behind GET /api/v1/my/workloads,
	// scoped to its owner.
	stateRows, err := s.pool.Query(ctx, `SELECT state, count(*) FROM workloads GROUP BY state`)
	if err != nil {
		return Overview{}, err
	}
	for stateRows.Next() {
		var state string
		var count int
		if err := stateRows.Scan(&state, &count); err != nil {
			stateRows.Close()
			return Overview{}, err
		}
		result.WorkloadsByState[state] = count
	}
	if err := stateRows.Err(); err != nil {
		stateRows.Close()
		return Overview{}, err
	}
	stateRows.Close()

	// Redis is reconstructible: failure makes liveness unknown, never zero/offline.
	for index := range result.Providers {
		fullID := result.Providers[index].fullID
		key := "openinfra:heartbeat:" + fullID
		values, err := s.redis.HMGet(ctx, key, "payload").Result()
		if err != nil {
			result.Partial = true
			appendError(&result, "heartbeat cache unavailable")
			break
		}
		ttl, err := s.redis.PTTL(ctx, key).Result()
		if err != nil || ttl <= 0 || len(values) != 1 || values[0] == nil {
			result.Providers[index].Liveness = "STALE"
			continue
		}
		payloadBytes, ok := values[0].(string)
		if !ok {
			result.Partial = true
			continue
		}
		var payload structHeartbeat
		if err := payload.Unmarshal([]byte(payloadBytes)); err != nil || payload.ProviderID != fullID {
			result.Partial = true
			continue
		}
		result.Providers[index].Liveness = "FRESH"
		age := int64(0)
		if payload.ObservedAt != nil {
			age = max(0, int64(s.now().Sub(payload.ObservedAt.AsTime()).Seconds()))
		}
		result.Providers[index].HeartbeatAge = &age
		if payload.Capabilities != nil {
			cpu := payload.Capabilities.CpuAvailable
			memory := payload.Capabilities.RamAvailableMb
			if cpu < 0 || math.IsNaN(float64(cpu)) || math.IsInf(float64(cpu), 0) || memory < 0 {
				result.Partial = true
				result.Providers[index].Liveness = "UNKNOWN"
				appendError(&result, "invalid provider capability ignored")
				continue
			}
			result.Providers[index].CPUAvailable = cpu
			result.Providers[index].MemoryMB = memory
			result.CPUAvailable += float64(cpu)
			result.MemoryMB += memory
			result.Providers[index].StorageAvailableGB = payload.Capabilities.StorageAvailableGb
			result.Providers[index].StorageTotalGB = payload.Capabilities.StorageTotalGb
			if bandwidth := payload.Capabilities.Bandwidth; bandwidth != nil {
				result.Providers[index].IngressMbps = bandwidth.IngressMbps
				result.Providers[index].EgressMbps = bandwidth.EgressMbps
			}
			result.Providers[index].VirtualizationCapable = payload.Capabilities.VirtualizationCapable
		}
		result.ProvidersFresh++
	}

	chainCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	health, healthErr := s.chain.Health(chainCtx)
	best, bestErr := s.chain.LatestHeader(chainCtx)
	finalHash, finalErr := s.chain.FinalizedHead(chainCtx)
	if healthErr != nil || bestErr != nil || finalErr != nil {
		result.Partial = true
		appendError(&result, "blockchain status unavailable")
		return result, nil
	}
	final, err := s.chain.HeaderAt(chainCtx, finalHash)
	if err != nil {
		result.Partial = true
		appendError(&result, "finalized block unavailable")
		return result, nil
	}
	result.ChainSyncing = health.IsSyncing
	result.BestBlock, _ = best.BlockNumber()
	result.FinalizedBlock, _ = final.BlockNumber()

	validators, err := s.chain.ActiveNetworkValidators(chainCtx, finalHash)
	if err != nil {
		result.Partial = true
		appendError(&result, "validator set unavailable")
		return result, nil
	}
	result.ValidatorsActive = len(validators)
	for _, account := range validators {
		result.Validators = append(result.Validators, abbreviate(hex.EncodeToString(account[:])))
	}

	// Per-provider chain reads (reputation vector, finalized resource-market
	// offer) all snapshot the same finalHash resolved above, so every
	// provider in one response reflects the same block -- not a race
	// between whichever block happened to be finalized when each read
	// fired. A single provider's read failing degrades only that
	// provider's Reputation/Offer to nil (and sets Partial), not the
	// whole response -- unlike the chain-wide health/validators checks
	// above, this is closer in spirit to the per-provider Redis
	// liveness loop than to a global precondition.
	for index := range result.Providers {
		key := result.Providers[index].publicKey
		if len(key) != ed25519.PublicKeySize {
			continue
		}
		var account [32]byte
		copy(account[:], key)

		if vector, found, err := s.chain.ProviderReputationVector(chainCtx, account, finalHash); err != nil {
			result.Partial = true
			appendError(&result, "provider reputation unavailable")
		} else {
			result.Providers[index].Reputation = &ReputationSummary{
				Available: found,
				Compute:   vector.Compute, Storage: vector.Storage, Network: vector.Network,
				Availability: vector.Availability, Reliability: vector.Reliability, Global: vector.Global,
			}
		}

		if offer, found, err := s.chain.FinalizedOffer(chainCtx, account, finalHash); err != nil {
			result.Partial = true
			appendError(&result, "provider offer unavailable")
		} else {
			result.Providers[index].Offer = &OfferSummary{Found: found, CPUMillicores: offer.CPUMillicores, RAMMB: offer.RAMMB, StorageGB: offer.StorageGB}
		}
	}

	return result, nil
}

type structHeartbeat struct {
	ProviderID   string
	ObservedAt   interfaceTimestamp
	Capabilities *sharedv1.ResourceCapability
}
type interfaceTimestamp interface{ AsTime() time.Time }

func (h *structHeartbeat) Unmarshal(data []byte) error {
	// Use the generated contract without exporting raw protobuf data to the UI.
	var p heartbeatPayload
	if err := proto.Unmarshal(data, &p); err != nil {
		return err
	}
	h.ProviderID, h.ObservedAt, h.Capabilities = p.GetProviderId(), p.GetObservedAt(), p.GetCapabilities()
	return nil
}

func abbreviate(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:12] + "…"
}
func appendError(o *Overview, value string) {
	for _, e := range o.Errors {
		if e == value {
			return
		}
	}
	o.Errors = append(o.Errors, value)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// Aliased below to keep the decoding dependency explicit and testable.
type heartbeatPayload = controlplanev1.HeartbeatSigningPayload
