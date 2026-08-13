-- ADR-016 slice 5: an append-only record of every authenticated write
-- action taken through the dashboard's HTTP surface.
--
-- Append-only by convention and by the absence of any UPDATE/DELETE path
-- in internal/dashboard -- not by a database-level guarantee. Postgres
-- has no "append-only table" primitive short of a rule/trigger or a
-- restricted role, and the Control Plane connects as the schema's owner
-- for migrations anyway, so a trigger would be trivially bypassable by
-- the same credential. Stating the actual guarantee rather than implying
-- a stronger one: this table is tamper-evident only insofar as whoever
-- holds DATABASE_URL is trusted, which is the same trust boundary
-- controlplane-admin's grant-role already sits behind (ADR-016 §4).
CREATE TABLE IF NOT EXISTS audit_events (
    event_id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    -- actor_user_id is NOT a foreign key to users(user_id) on purpose: an
    -- audit row must survive the deletion of the user it describes. A
    -- cascading delete would let removing an account erase the evidence
    -- of what that account did, which defeats the point of the log.
    actor_user_id uuid NOT NULL,
    -- actor_role is the role the actor held *at the time of the action*,
    -- denormalized deliberately. users.role is mutable (grant-role), so
    -- joining to it later would retroactively rewrite history: an
    -- operator demoted to tenant would make every past operator action
    -- look like a tenant action.
    actor_role text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    -- outcome distinguishes an action that was performed from one that
    -- was attempted and refused. Both are worth recording: a burst of
    -- 'denied' rows is exactly the signal an operator wants.
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    CHECK (length(action) <= 64),
    CHECK (length(target_type) <= 32),
    CHECK (length(target_id) <= 128),
    CHECK (length(actor_role) <= 32)
);

-- The operator audit view reads newest-first, optionally filtered by
-- actor or action; this index serves the unfiltered newest-first page,
-- which is the common case.
CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx
    ON audit_events (occurred_at DESC);
