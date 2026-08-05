package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/blockchainbridge"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	pool  *pgxpool.Pool
	redis redis.UniversalClient
	chain *blockchainbridge.RPCClient
	now   func() time.Time
}

type Provider struct {
	fullID       string
	ProviderID   string  `json:"provider_id"`
	Status       string  `json:"status"`
	Liveness     string  `json:"liveness"`
	AgentVersion string  `json:"agent_version"`
	RegisteredAt string  `json:"registered_at"`
	HeartbeatAge *int64  `json:"heartbeat_age_seconds,omitempty"`
	CPUAvailable float32 `json:"cpu_available"`
	MemoryMB     int64   `json:"memory_available_mb"`
	ChainState   string  `json:"chain_state"`
}

type Overview struct {
	GeneratedAt    string     `json:"generated_at"`
	ProvidersTotal int        `json:"providers_total"`
	ProvidersFresh int        `json:"providers_fresh"`
	CPUAvailable   float64    `json:"cpu_available"`
	MemoryMB       int64      `json:"memory_available_mb"`
	FinalizedBlock uint64     `json:"finalized_block"`
	BestBlock      uint64     `json:"best_block"`
	ChainSyncing   bool       `json:"chain_syncing"`
	Partial        bool       `json:"partial"`
	Errors         []string   `json:"errors,omitempty"`
	Providers      []Provider `json:"providers"`
	Workloads      []Workload `json:"workloads"`
}

type Workload struct {
	WorkloadID string `json:"workload_id"`
	State      string `json:"state"`
	ProviderID string `json:"provider_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	CreatedAt  string `json:"created_at"`
}

func New(pool *pgxpool.Pool, redisClient redis.UniversalClient, chain *blockchainbridge.RPCClient) *Server {
	return &Server{pool: pool, redis: redisClient, chain: chain, now: time.Now}
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
	result, err := s.loadOverview(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authoritative provider data unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) loadOverview(ctx context.Context) (Overview, error) {
	result := Overview{GeneratedAt: s.now().UTC().Format(time.RFC3339), Providers: []Provider{}, Workloads: []Workload{}}
	rows, err := s.pool.Query(ctx, `
		SELECT p.provider_id, p.status, p.agent_version, p.registered_at,
		       COALESCE(c.state, 'UNKNOWN')
		FROM providers p LEFT JOIN provider_chain_registrations c USING (provider_id)
		ORDER BY p.registered_at DESC LIMIT 500`)
	if err != nil {
		return Overview{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var p Provider
		var status int16
		var registered time.Time
		if err := rows.Scan(&p.ProviderID, &status, &p.AgentVersion, &registered, &p.ChainState); err != nil {
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
	result.ProvidersTotal = len(result.Providers)
	workloadRows, err := s.pool.Query(ctx, `SELECT workload_id::text, state, COALESCE(provider_id,''), COALESCE(lease_id::text,''), created_at FROM workloads ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return Overview{}, err
	}
	for workloadRows.Next() {
		var item Workload
		var created time.Time
		if err := workloadRows.Scan(&item.WorkloadID, &item.State, &item.ProviderID, &item.LeaseID, &created); err != nil {
			workloadRows.Close()
			return Overview{}, err
		}
		item.WorkloadID, item.ProviderID, item.CreatedAt = abbreviate(item.WorkloadID), abbreviate(item.ProviderID), created.UTC().Format(time.RFC3339)
		result.Workloads = append(result.Workloads, item)
	}
	if err := workloadRows.Err(); err != nil {
		workloadRows.Close()
		return Overview{}, err
	}
	workloadRows.Close()

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
