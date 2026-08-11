package dashboard

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/userauth"
)

// Audit actions and target types. Kept as constants rather than inline
// strings so the set of things this system claims to audit is
// enumerable in one place -- an operator reading the log should not have
// to grep handlers to learn what actions exist.
const (
	auditActionWorkloadStop = "workload.stop"
	auditActionAPIKeyIssue  = "api_key.issue"

	auditTargetWorkload = "workload"
	auditTargetUser     = "user"

	auditOutcomeSuccess = "success"
	auditOutcomeDenied  = "denied"
	auditOutcomeError   = "error"
)

// defaultAuditLimit/maxAuditLimit bound the operator audit view's page
// size, the same bounded-cardinality discipline every other paginated
// endpoint here already applies.
const (
	defaultAuditLimit = 100
	maxAuditLimit     = 500
)

// recordAudit appends one audit row. Deliberately best-effort: a failure
// to write the audit row is logged and swallowed rather than failing the
// action that was already performed. The alternative -- failing the
// request after the workload was already stopped -- would tell the
// caller their action failed when it did not, which is a worse lie than
// a missing audit row, and this package's whole no-false-success
// discipline runs the other way.
//
// The trade-off is stated rather than hidden: this makes the log
// best-effort, not guaranteed-complete. Making it guaranteed would mean
// writing the audit row in the same transaction as the action itself,
// which internal/workloadapi's RequestStop owns and this package
// deliberately does not reach into (ADR-016 §2: "no new business logic,
// just a browser-reachable entry point"). Worth revisiting if the audit
// log ever becomes a compliance artifact rather than an operational one.
//
// Never pass raw credentials, tenant payloads, or error text from a
// workload's own application into targetID -- see the endpoints below
// for what is actually recorded (identifiers only).
func (s *Server) recordAudit(ctx context.Context, actor userauth.User, action, targetType, targetID, outcome string) {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_events (event_id, occurred_at, actor_user_id, actor_role, action, target_type, target_id, outcome)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), s.now().UTC(), actor.UserID, actor.Role, action, targetType, targetID, outcome)
	if err != nil {
		slog.Error("audit event could not be recorded",
			"action", action, "target_type", targetType, "outcome", outcome, "error", err)
	}
}

// AuditEvent is one row of GET /api/v1/operator/audit.
type AuditEvent struct {
	EventID     string    `json:"event_id"`
	OccurredAt  time.Time `json:"occurred_at"`
	ActorUserID string    `json:"actor_user_id"`
	ActorRole   string    `json:"actor_role"`
	Action      string    `json:"action"`
	TargetType  string    `json:"target_type"`
	TargetID    string    `json:"target_id"`
	Outcome     string    `json:"outcome"`
}

// AuditEvents is GET /api/v1/operator/audit's response body.
type AuditEvents struct {
	GeneratedAt string       `json:"generated_at"`
	Total       int          `json:"total"`
	Limit       int          `json:"limit"`
	Offset      int          `json:"offset"`
	Events      []AuditEvent `json:"events"`
}

// operatorAudit serves the audit log, newest first, gated
// operator_readonly per ADR-016 §5's sequencing note. Cross-tenant by
// nature -- that is what an audit log is -- which is exactly why it sits
// on the operator tier and not the tenant one.
func (s *Server) operatorAudit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	query := r.URL.Query()
	limit := boundedQueryInt(query, "limit", defaultAuditLimit, 1, maxAuditLimit)
	offset := boundedQueryInt(query, "offset", 0, 0, 1_000_000)

	result := AuditEvents{
		GeneratedAt: s.now().UTC().Format(time.RFC3339),
		Limit:       limit,
		Offset:      offset,
		Events:      []AuditEvent{},
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&result.Total); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit read unavailable"})
		return
	}

	rows, err := s.pool.Query(ctx, `
		SELECT event_id::text, occurred_at, actor_user_id::text, actor_role, action, target_type, target_id, outcome
		FROM audit_events
		ORDER BY occurred_at DESC, event_id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit read unavailable"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.EventID, &event.OccurredAt, &event.ActorUserID, &event.ActorRole,
			&event.Action, &event.TargetType, &event.TargetID, &event.Outcome); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit read unavailable"})
			return
		}
		result.Events = append(result.Events, event)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit read unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
