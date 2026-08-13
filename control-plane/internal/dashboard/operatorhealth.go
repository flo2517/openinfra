package dashboard

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// operatorTerminalStates are the workload states no retry can move out of.
// Alerts about retries deliberately exclude them: a FAILED workload that
// burned six attempts yesterday is history, not something an operator can
// act on now.
var operatorTerminalStates = []string{"STOPPED", "COMPLETED", "FAILED"}

// operatorRetryExhaustionThreshold is the attempt_count at which a
// still-running retry stops looking like normal backoff. It matches the
// upper bucket boundary operatorQueue already reports ("6+"), so the
// alert and the distribution never disagree about what "a lot of
// retries" means.
const operatorRetryExhaustionThreshold = 6

// dependencyProbeTimeout bounds each dependency probe individually.
// Unlike /readyz -- which short-circuits on the first failure, because
// its only job is to answer "should traffic come here" with one bit --
// this view probes all three regardless, since "Postgres fine, Redis
// fine, chain unreachable" is precisely the diagnosis an operator needs
// and a short-circuiting check cannot express it.
const dependencyProbeTimeout = 2 * time.Second

// DependencyHealth is one backing service's probe result.
type DependencyHealth struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok" | "degraded" | "unavailable"
	// LatencyUS is microseconds, not milliseconds: every probe against a
	// container on the same host completes well under 1ms, so a
	// millisecond field reads 0 for all three and tells an operator
	// nothing -- verified against the running stack, where that is
	// exactly what it did.
	LatencyUS int64 `json:"latency_us"`
	// Detail carries the reason for a non-ok status, or a qualifier for a
	// degraded one (e.g. the chain answering while still syncing). Never
	// the raw driver error: those can carry connection strings.
	Detail string `json:"detail,omitempty"`
}

// OperatorAlert is one actionable condition derived from state the
// Control Plane already holds. Every alert names the source it was
// derived from, so an operator can go verify it rather than trusting a
// severity badge.
type OperatorAlert struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // "critical" | "warning" | "info"
	Summary  string `json:"summary"`
	Count    int    `json:"count,omitempty"`
	Source   string `json:"source"`
}

// OperatorHealth is GET /api/v1/operator/health's response body.
type OperatorHealth struct {
	GeneratedAt  string             `json:"generated_at"`
	Dependencies []DependencyHealth `json:"dependencies"`
	Alerts       []OperatorAlert    `json:"alerts"`
	// AlertsPartial is true when a check could not run, so an empty
	// Alerts list is never mistaken for "everything verified healthy".
	AlertsPartial bool `json:"alerts_partial,omitempty"`
}

// operatorHealth is #76's remaining operator-view bullet: dependency
// health and alerts. Gated operator_readonly like the queue and worker
// views -- it aggregates cross-tenant operational state, and the alert
// counts alone would leak how much work other tenants have in flight.
//
// It deliberately computes alerts from state that already exists rather
// than introducing an alerting subsystem: this is a read-only view that
// answers "what is wrong right now", not a notifier, and nothing here
// stores, escalates, or acknowledges anything.
func (s *Server) operatorHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	result := OperatorHealth{
		GeneratedAt:  s.now().UTC().Format(time.RFC3339),
		Dependencies: s.probeDependencies(ctx),
		Alerts:       []OperatorAlert{},
	}
	for _, dependency := range result.Dependencies {
		if dependency.Status == "unavailable" {
			result.Alerts = append(result.Alerts, OperatorAlert{
				ID:       "dependency_unavailable",
				Severity: "critical",
				Summary:  dependency.Name + " is unreachable from the Control Plane",
				Source:   "dependency probe",
			})
		}
	}

	alerts, partial := s.databaseAlerts(ctx)
	result.Alerts = append(result.Alerts, alerts...)
	result.AlertsPartial = partial

	// An empty active validator set is not a database condition: the
	// challenge protocol is simply inert, since no committee can be
	// formed and therefore no round can ever close (see
	// pallet-network-validator's close_round quorum check). Reported as a
	// warning rather than left to be inferred from a validator count of
	// zero somewhere else on the page.
	if validators, err := s.activeValidatorsForAlert(ctx); err == nil && validators == 0 {
		result.Alerts = append(result.Alerts, OperatorAlert{
			ID:       "no_active_validators",
			Severity: "warning",
			Summary:  "no Network Validator is active on-chain: no scoring round can be assigned or closed",
			Source:   "pallet-network-validator ActiveValidatorSet",
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// activeValidatorsForAlert reads the active set size, treating an
// unconfigured chain client as an error rather than as "zero validators"
// -- the alert says the protocol is inert, which is a claim about the
// chain, not about whether this process was wired to one.
func (s *Server) activeValidatorsForAlert(ctx context.Context) (int, error) {
	if s.chain == nil {
		return 0, errors.New("no chain client configured")
	}
	validators, err := s.chain.LatestActiveNetworkValidators(ctx)
	return len(validators), err
}

// probeDependencies checks all three backing services concurrently and
// independently -- see dependencyProbeTimeout's comment for why this does
// not reuse /readyz.
func (s *Server) probeDependencies(ctx context.Context) []DependencyHealth {
	results := make([]DependencyHealth, 3)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		results[0] = s.probe(ctx, "postgres", func(ctx context.Context) (string, error) {
			return "", s.pool.Ping(ctx)
		})
	}()
	go func() {
		defer wg.Done()
		results[1] = s.probe(ctx, "redis", func(ctx context.Context) (string, error) {
			if s.redis == nil {
				return "not configured", nil
			}
			return "", s.redis.Ping(ctx).Err()
		})
	}()
	go func() {
		defer wg.Done()
		results[2] = s.probe(ctx, "blockchain", func(ctx context.Context) (string, error) {
			if s.chain == nil {
				return "not configured", nil
			}
			health, err := s.chain.Health(ctx)
			if err != nil {
				return "", err
			}
			if health.IsSyncing {
				return "syncing", nil
			}
			return "", nil
		})
	}()

	wg.Wait()
	return results
}

// probe runs one dependency check under its own timeout and turns its
// outcome into a DependencyHealth. A check that answers with a detail
// string but no error is "degraded": reachable, but not in the state an
// operator should treat as normal.
func (s *Server) probe(ctx context.Context, name string, check func(context.Context) (string, error)) DependencyHealth {
	probeCtx, cancel := context.WithTimeout(ctx, dependencyProbeTimeout)
	defer cancel()

	started := s.now()
	detail, err := check(probeCtx)
	latency := s.now().Sub(started).Microseconds()

	switch {
	case err != nil:
		// The error itself is not echoed: a driver error can embed a
		// connection string, and this endpoint is read by humans who
		// have the logs for the detail.
		return DependencyHealth{Name: name, Status: "unavailable", LatencyUS: latency, Detail: "probe failed"}
	case detail != "":
		return DependencyHealth{Name: name, Status: "degraded", LatencyUS: latency, Detail: detail}
	default:
		return DependencyHealth{Name: name, Status: "ok", LatencyUS: latency}
	}
}

// databaseAlerts derives the conditions visible in the workloads table.
// Both are single aggregate queries over columns that already exist
// (migrations/000004, 000006, 000007) -- no new schema, matching how the
// queue and worker views were built.
func (s *Server) databaseAlerts(ctx context.Context) ([]OperatorAlert, bool) {
	alerts := []OperatorAlert{}
	partial := false
	now := s.now()

	// A worker still holding claimed rows past its lease is the same
	// "stuck claim" signal operatorWorkers reports per worker; here it is
	// aggregated into one actionable line.
	var expiredClaims int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM workloads
		WHERE worker_id IS NOT NULL AND worker_lease_until IS NOT NULL AND worker_lease_until < $1`, now).Scan(&expiredClaims)
	if err != nil {
		partial = true
	} else if expiredClaims > 0 {
		alerts = append(alerts, OperatorAlert{
			ID:       "worker_claim_expired",
			Severity: "critical",
			Summary:  "workloads are claimed by a worker whose lease has expired",
			Count:    expiredClaims,
			Source:   "workloads.worker_lease_until",
		})
	}

	var exhausted int
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FROM workloads
		WHERE attempt_count >= $1 AND state <> ALL($2)`,
		operatorRetryExhaustionThreshold, operatorTerminalStates).Scan(&exhausted)
	if err != nil {
		partial = true
	} else if exhausted > 0 {
		alerts = append(alerts, OperatorAlert{
			ID:       "retry_exhaustion",
			Severity: "warning",
			Summary:  "non-terminal workloads have retried past the normal backoff range",
			Count:    exhausted,
			Source:   "workloads.attempt_count",
		})
	}

	return alerts, partial
}
