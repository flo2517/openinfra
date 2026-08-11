package dashboard

import (
	"context"
	"net/http"
	"time"
)

// operatorWorkloadStates lists every state workloads.state's CHECK
// constraint allows (migrations/000004_workloads.sql,
// 000006_workload_stop.sql), in the order a workload normally moves
// through them. Iterated rather than discovered via SELECT DISTINCT so
// QueueByState always reports every state -- including ones with zero
// rows right now -- the same "explicit zero, not a missing key" instinct
// Overview.ValidatorsActive's -1-vs-0 distinction already applies (#29).
var operatorWorkloadStates = []string{
	"REQUESTED", "SCHEDULING", "LEASE_PENDING", "LEASED", "DEPLOYING",
	"RUNNING", "STOPPING", "STOPPED", "COMPLETED", "FAILED",
}

// QueueStateCount is one state's slice of GET /api/v1/operator/queue's
// response: how many workloads sit in this state right now, plus the
// oldest next_attempt_at among them (nil when nothing in this state has
// one scheduled, e.g. terminal states or a state that isn't waiting on a
// retry timer) -- an operator's first useful question about a stuck
// queue is "what's been waiting longest," not just a raw count.
type QueueStateCount struct {
	State           string     `json:"state"`
	Count           int        `json:"count"`
	OldestNextRetry *time.Time `json:"oldest_next_retry_at,omitempty"`
}

// OperatorQueue is GET /api/v1/operator/queue's response body: per-state
// counts (ADR-016 §2's queue view), plus a coarse attempt_count
// distribution so an operator can tell "a healthy queue with normal
// retries" apart from "a few workloads retrying endlessly" without
// having to page through individual rows.
type OperatorQueue struct {
	GeneratedAt string            `json:"generated_at"`
	States      []QueueStateCount `json:"states"`
	// AttemptCountBuckets keys are "0", "1-2", "3-5", "6+" -- a fixed,
	// bounded set of buckets (not one key per distinct attempt_count,
	// which is unbounded in principle) so this payload's shape never
	// grows with how badly something is retrying.
	AttemptCountBuckets map[string]int `json:"attempt_count_buckets"`
}

// operatorQueue is ADR-016 §2's operator-tier queue view, gated
// operator_readonly (satisfied by operator_admin too, via
// userauth.RoleSatisfies's ranking). Every figure here comes from
// columns workloads already has -- migrations/000004, 000006, 000007 --
// no new schema, matching the ADR's sequencing note that this slice is
// "the lowest-risk slice."
func (s *Server) operatorQueue(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	result := OperatorQueue{
		GeneratedAt:         s.now().UTC().Format(time.RFC3339),
		States:              make([]QueueStateCount, 0, len(operatorWorkloadStates)),
		AttemptCountBuckets: map[string]int{"0": 0, "1-2": 0, "3-5": 0, "6+": 0},
	}

	rows, err := s.pool.Query(ctx, `
		SELECT state, count(*), min(next_attempt_at)
		FROM workloads
		GROUP BY state`)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue read unavailable"})
		return
	}
	counts := make(map[string]QueueStateCount, len(operatorWorkloadStates))
	for rows.Next() {
		var state string
		var count int
		var oldest *time.Time
		if err := rows.Scan(&state, &count, &oldest); err != nil {
			rows.Close()
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue read unavailable"})
			return
		}
		counts[state] = QueueStateCount{State: state, Count: count, OldestNextRetry: oldest}
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue read unavailable"})
		return
	}
	for _, state := range operatorWorkloadStates {
		if entry, ok := counts[state]; ok {
			result.States = append(result.States, entry)
		} else {
			result.States = append(result.States, QueueStateCount{State: state, Count: 0})
		}
	}

	bucketRows, err := s.pool.Query(ctx, `
		SELECT
			CASE
				WHEN attempt_count = 0 THEN '0'
				WHEN attempt_count BETWEEN 1 AND 2 THEN '1-2'
				WHEN attempt_count BETWEEN 3 AND 5 THEN '3-5'
				ELSE '6+'
			END AS bucket,
			count(*)
		FROM workloads
		GROUP BY bucket`)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue read unavailable"})
		return
	}
	defer bucketRows.Close()
	for bucketRows.Next() {
		var bucket string
		var count int
		if err := bucketRows.Scan(&bucket, &count); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue read unavailable"})
			return
		}
		result.AttemptCountBuckets[bucket] = count
	}
	if err := bucketRows.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "queue read unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// WorkerClaim is one distinct worker_id's current claim summary.
// worker_id/worker_lease_until (migrations/000007_workload_worker_claims.sql)
// identify a Control Plane orchestrator process's lease over a batch of
// workload rows, not a Provider Agent connection -- distinct from
// internal/agentmanager's provider liveness tracking, which this
// endpoint deliberately does not attempt to cross-reference: a
// worker_id here is this codebase's own internal work-claim actor, and
// nothing in agentmanager maps a Provider Agent connection to one.
// Documented explicitly, not silently assumed to line up.
type WorkerClaim struct {
	WorkerID         string    `json:"worker_id"`
	ClaimedWorkloads int       `json:"claimed_workloads"`
	LeaseUntil       time.Time `json:"lease_until"`
	LeaseExpired     bool      `json:"lease_expired"`
}

// OperatorWorkers is GET /api/v1/operator/workers's response body.
type OperatorWorkers struct {
	GeneratedAt string        `json:"generated_at"`
	Workers     []WorkerClaim `json:"workers"`
}

// operatorWorkers is ADR-016 §2's operator-tier worker-claim view, gated
// operator_readonly. A worker whose lease has expired but still shows a
// claimed row is exactly the "stuck claim" signal an operator needs --
// reported explicitly (LeaseExpired), not filtered out, since a filtered
// list would hide the failure this view exists to surface.
func (s *Server) operatorWorkers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT worker_id, count(*), max(worker_lease_until)
		FROM workloads
		WHERE worker_id IS NOT NULL
		GROUP BY worker_id
		ORDER BY worker_id`)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "worker read unavailable"})
		return
	}
	defer rows.Close()

	now := s.now()
	result := OperatorWorkers{GeneratedAt: now.UTC().Format(time.RFC3339), Workers: []WorkerClaim{}}
	for rows.Next() {
		var workerID string
		var count int
		var leaseUntil *time.Time
		if err := rows.Scan(&workerID, &count, &leaseUntil); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "worker read unavailable"})
			return
		}
		claim := WorkerClaim{WorkerID: workerID, ClaimedWorkloads: count}
		if leaseUntil != nil {
			claim.LeaseUntil = *leaseUntil
			claim.LeaseExpired = leaseUntil.Before(now)
		}
		result.Workers = append(result.Workers, claim)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "worker read unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
