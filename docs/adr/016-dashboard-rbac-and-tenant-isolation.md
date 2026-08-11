# ADR-016: Dashboard RBAC, tenant isolation, and operator views

## Status

Accepted (by the repository owner, explicitly — this proposal was deliberately left unaccepted by
Claude Code when first written, unlike ADR-013/014/015 this session, since it decides who can see
which tenant's data: a real security boundary, not a narrower technical decision).

**Implementation note:** §7's three open questions are **not** all resolved by acceptance —
acceptance authorizes slice 1 (§ Sequencing: schema + grant path, no tenant-private data exposed
yet) to proceed immediately. Slice 2 (tenant workload views, which first exposes
`workload.definition`) still needs §7 questions 1 and 2 answered before it ships, exactly as
§ Consequences already said. Written to unblock issue #76's largest remaining item: "RBAC and
tenant isolation on the dashboard itself (today: no auth at all)," plus the user- and
operator-view items that depend on it.

**§7 resolved (repository owner, direct answer, not re-derived):**

1. `workload.definition`'s env values are **never** shown verbatim, to anyone, including the
   owning tenant — the safer default this proposal already assumed. Key names only.
2. `last_error`/`error_code` **are** shown to the owning tenant on their own workload (Tenant
   tier), while staying withheld from Operator-tier's cross-tenant queue view for the
   secret-leakage reason §6 already flags — the redaction rule is role-*and*-ownership-dependent,
   as this section anticipated it might need to be.
3. A single `operator` role is **not** enough — the repository owner chose a two-level split:
   `operator_readonly` (visibility: queue, workers, audit) and `operator_admin` (destructive
   actions: stop-any-workload, revoke-any-key), in addition to `operator_readonly`'s own
   visibility. Implemented in `migrations/000013_operator_role_levels.sql` and
   `internal/userauth`'s `roleRank`, which §1's original table already anticipated restructuring
   ("Unexported here deliberately... so the ranking itself can be restructured later (e.g. a third
   tier)"). §1's role table and §4's grant syntax below are updated in place to match, rather than
   left describing the superseded one-tier design.

## Context

Three things already exist, independently, and this proposal's whole job is wiring them together
rather than inventing anything new:

1. **Authentication** (ADR-014, accepted and implemented): a browser can log in by signing a
   challenge, getting back a session API key. `internal/userauth` already has `users`,
   `api_keys`, `Authenticate`, and an interceptor pattern (`internal/userauth/interceptor.go`,
   reused by the dashboard's own `authenticatedUserID` in `internal/dashboard/auth.go`).
2. **Ownership** (issue #12, accepted and implemented): `workloads.owner_id` (migration
   `000009_users_and_api_keys.sql`) already ties a workload to a `users.user_id`, and
   `internal/workloadapi`'s gRPC surface already scopes every query by it
   (`internal/workloadapi/postgres.go`: `WHERE workload_id=$1 AND owner_id=$2` throughout). A
   real per-tenant boundary already exists — just not on the dashboard's HTTP surface.
3. **A dashboard with no authorization at all.** `internal/dashboard`'s `loadOverview` reads
   every provider and the newest 500 workloads system-wide
   (`SELECT ... FROM workloads ORDER BY created_at DESC LIMIT $1`, no `owner_id` filter) and
   serves it to anyone who can reach the listener. `/api/v1/validator-scores/*` and
   `/api/v1/agent-endpoint/*` are the same: unauthenticated by design (documented in each as "not
   a new trust boundary" — correct today, because nothing tenant-private is exposed yet). Once
   this proposal adds tenant-scoped workload views (cost, logs, env-derived metadata), that
   "not a new trust boundary" reasoning stops applying to the *new* endpoints and must be revisited
   per-endpoint, not assumed to extend automatically.

What's missing is purely the authorization layer in between: **what does an authenticated
session's `users.user_id` get to see**, and **what does an unauthenticated caller still get to
see** (today: everything; after this proposal: only network-wide aggregate data, not per-tenant
detail).

## Decision

### 1. Three roles, one column

```sql
-- Slice 1 (migrations/000012_user_roles.sql), superseded by §7 question 3's
-- resolution:
ALTER TABLE users ADD COLUMN role text NOT NULL DEFAULT 'tenant'
    CHECK (role IN ('tenant', 'operator'));

-- migrations/000013_operator_role_levels.sql, current:
UPDATE users SET role = 'operator_admin' WHERE role = 'operator';
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('tenant', 'operator_readonly', 'operator_admin'));
```

Deliberately **not** a `user_roles` many-to-many table. Every real actor in this system today
(tenant submitting workloads, operator running the Control Plane) has exactly one job; multi-role
users are a real future need (an operator who is also a tenant of their own network) but adding
that flexibility now is speculative complexity this proposal doesn't need to carry. If that need
becomes real, migrating `role text` to a join table is a normal, additive schema change — nothing
built on top of this proposal has to be designed around it in advance.

`operator_readonly` and `operator_admin` are still one linearly-ranked column, not a second
dimension — `operator_admin` satisfies every `operator_readonly` gate too (`internal/userauth`'s
`roleRank`), matching how §7 question 3 was posed ("read-only vs. admin actions" as a hierarchy, an
admin can do everything a read-only viewer can) rather than as two unrelated permission sets.

Four effective access levels, not two, because "operator" and "authenticated tenant" alone don't
cover what's public today, and (§7 question 3) "operator" alone doesn't distinguish visibility from
destructive action:

| Level | Who | Determined by |
|---|---|---|
| **Public** | Anyone who can reach the listener, no session | No `Authorization` header |
| **Tenant** | A logged-in user, `role = 'tenant'` (the default) | Valid session/API key, `users.role` |
| **Operator (read-only)** | A logged-in user, `role = 'operator_readonly'` or higher | Valid session/API key, `users.role`, explicitly granted (see §4) |
| **Operator (admin)** | A logged-in user, `role = 'operator_admin'` | Valid session/API key, `users.role`, explicitly granted (see §4) |

**Network Validators are not a fourth dashboard role.** A validator authenticates to the *Agent*
over mTLS (ADR-013 §3) and to the *chain* by signing extrinsics directly — it has no reason to
hold a dashboard session, and nothing in ADR-013/§85's challenge loop calls a dashboard endpoint
that needs one (`GET /api/v1/agent-endpoint/{provider_id}` is deliberately public, per its own
doc comment, precisely so a validator's daemon needs no dashboard credential at all). "Validator
views" in #76's original scope (challenge queue, evidence, quorum, score history) are **public,
network-wide data** — #87 already shipped the score-history piece as a public endpoint, correctly,
and every other validator view belongs in the same Public tier, not a new role.

### 2. Endpoint classification

Every endpoint this proposal knows about, existing or planned, gets exactly one tier. This table
is the actual authorization contract; implementation is "make the code match this table," not a
separate design exercise per endpoint.

| Endpoint | Tier | Notes |
|---|---|---|
| `GET /api/v1/overview` | Public, **but stops including per-workload detail** | Provider/validator/chain-health data stays public (unchanged). Workload rows must drop to counts-by-state only for public callers — see §3. |
| `GET /api/v1/validator-scores/{provider_id}` | Public | Unchanged (#87). |
| `GET /api/v1/agent-endpoint/{provider_id}` | Public | Unchanged (#85/#13) — a validator's own credential-free discovery path. |
| `POST /api/v1/auth/*` | Public | Unchanged (ADR-014) — has to be, it's how you stop being anonymous. |
| `GET /api/v1/my/workloads` *(new)* | Tenant | Own workloads only, `WHERE owner_id = $session_user_id`. Replaces reading workload detail out of `/api/v1/overview`. |
| `GET /api/v1/my/workloads/{workload_id}` *(new)* | Tenant | 404 (not 403) for a workload that exists but isn't the caller's — matches `internal/workloadapi`'s existing "ownership check via the query itself" pattern, not a separate authorization branch that could be gotten wrong independently. |
| `POST /api/v1/my/workloads/{workload_id}/stop` *(new)* | Tenant | Thin HTTP wrapper over the same `StopWorkload` path `internal/workloadapi` already exposes over gRPC — no new business logic, just a browser-reachable entry point with the same ownership check. |
| `GET /api/v1/operator/queue` *(new)* | Operator (`operator_readonly`) | Counts of workloads by `state`, oldest `next_attempt_at` per state, `attempt_count` distribution — all already-existing columns (`migrations/000004_workloads.sql`, `000006`, `000007`), no new schema needed. |
| `GET /api/v1/operator/workers` *(new)* | Operator (`operator_readonly`) | Distinct `worker_id`/`worker_lease_until` currently holding a claim (`workloads.worker_id`) cross-referenced with `internal/agentmanager`'s live connection state. |
| `GET /api/v1/operator/audit` *(new, later slice)* | Operator (`operator_readonly`) | No audit log exists yet — this is new work, not a read of existing data. Flagged as its own slice in §5, not assumed free. |
| Dashboard static assets (`/dashboard/*`) | Public | Unchanged — the HTML/JS shell itself carries no data; per-role content is fetched by the JS after login, same SPA-shell pattern already in place for the auth panel. |

### 3. `/api/v1/overview`'s workload list must shrink for public callers

This is the one *behavior change* to an already-public, already-shipped endpoint, so it gets its
own paragraph rather than hiding in the table above. Today `Overview.Workloads` returns up to 100
workload rows (`workload_id`, `state`, `provider_id`, `lease_id`, `created_at`) to anyone. None of
those fields are secret today, but `workload_id`/`lease_id`/`created_at` are exactly the shape of
"which tenants are using this network and when" — not something this proposal wants to keep
broadcasting once a real multi-tenant answer (`GET /api/v1/my/workloads`) exists. Proposed
replacement: `Overview` keeps `WorkloadsTotal` and a **count-by-state** breakdown
(`{"REQUESTED": 3, "RUNNING": 12, ...}`), drops the per-row `Providers`... no — drops the per-row
`Workloads` list entirely. This is a breaking change to `Overview`'s JSON shape and needs its own
PR description calling that out explicitly, the same care given to every other behavior change to
shipped code this session (e.g. #90's Network-dimension evidence change).

### 4. Granting an operator role

Mirrors the existing `controlplane-admin` break-glass pattern (`cmd/controlplane-admin`'s
`create-user`/`issue-key`/`revoke-key`) rather than inventing a self-service path — becoming an
operator is not something a user should be able to grant themselves, unlike ADR-014 §6's
self-service API keys.

```
controlplane-admin grant-role <user-id> operator_readonly
controlplane-admin grant-role <user-id> operator_admin
controlplane-admin grant-role <user-id> tenant   # revoke back to default
```

Requires the same `DATABASE_URL` connection every other `controlplane-admin` user command already
needs — no new credential type.

### 5. Authorization enforcement point

One new, small piece of shared code: `internal/dashboard` gains a `requireRole(next
http.HandlerFunc, role string) http.HandlerFunc` wrapper, built directly on the existing
`authenticatedUserID` (`internal/dashboard/auth.go`) plus one `users.role` lookup. Every Tenant/
Operator-tier endpoint in §2's table is wrapped once at route registration
(`Server.Handler()`in `dashboard.go`) — the same place every route is already declared, so a
reviewer can audit the entire authorization surface by reading one function, not by finding every
handler's own ad hoc check. Public-tier endpoints are simply not wrapped, same as today.

### 6. Secret redaction: first-pass audit

#76 asks for this "as a stated requirement," not because a known leak exists. Walking every field
currently or newly proposed to cross the dashboard boundary:

| Data | Currently exposed? | Contains a secret? |
|---|---|---|
| Provider public keys, endpoints, capabilities | Yes, public | No — these are the provider's own on-chain-public identity/advertisement. |
| Workload `image`, `state`, timestamps | Yes, public today; moving to Tenant-only detail (§3) | No secrets in these fields themselves. |
| Workload `definition` (raw bytes, includes env vars per `WorkloadDefinition` in `shared.proto`) | **Not currently exposed anywhere in the dashboard** — `loadOverview` never selects the `definition` column. | **Yes, potentially** — a tenant's `env` map is exactly where a workload's secrets live (API keys, DB passwords for the deployed app). This must **never** be returned verbatim by `GET /api/v1/my/workloads/{workload_id}` — needs an explicit redaction pass (e.g. key names only, values withheld) before that endpoint ships, not an oversight to catch later. |
| Session API keys / raw keys | Never re-exposed after creation (ADR-014 §5/§6, unchanged) | N/A, already correctly handled |
| Container `last_error`/`error_code` | Not currently exposed; proposed for operator queue view and the owning tenant's own workload detail | Possible secret leakage if an application error message embeds a credential (e.g. a failed DB connection string in a stack trace) — resolved in §7 below: shown to the owning tenant, withheld from Operator-tier's cross-tenant queue view. |

### 7. Open questions for the accepting reviewer — resolved

Originally not resolved by this proposal; answered directly by the repository owner (see the
Status section's "§7 resolved" note for the verbatim answers). Kept here for the original framing
rather than deleted, since the reasoning each question raised still explains *why* the resolution
looks the way it does:

1. Does `workload.definition`'s env redaction need to be configurable per-tenant (some tenants
   may want their own values visible to themselves, just not to operators), or withheld from
   *everyone including the owning tenant* on principle? **Resolved: withheld from everyone,
   including the owner** — this proposal's safer-default assumption stands.
2. Should `last_error`/`error_code` be shown to the *owning tenant* (Tenant tier, their own
   workload) even though they're withheld from Operator-tier's cross-tenant queue view for the
   secret-leakage reason above? **Resolved: yes, shown to the owning tenant** — the redaction rule
   is role-*and*-ownership-dependent, as anticipated; `GET /api/v1/my/workloads/{workload_id}`
   (Tenant tier, ownership-scoped by its own query) includes it, the Operator-tier queue view does
   not.
3. Is a single global `operator` role sufficient, or does this need read-only-operator vs.
   operator-with-admin-actions (stop-any-workload, revoke-any-key) as separate levels? **Resolved:
   two separate levels** — `operator_readonly` and `operator_admin`, implemented in
   `migrations/000013_operator_role_levels.sql`.

## Sequencing

Mirrors ADR-013's slicing discipline: each slice is independently mergeable, independently
testable, and does not block on a later slice existing.

1. **Schema + grant path**: `role` column, `controlplane-admin grant-role`, `requireRole`
   middleware with no routes wrapped yet (dead code, but testable in isolation — matches how
   `CreateAPIKeyWithExpiry` landed ahead of wallet login using it).
2. **Tenant workload views**: `GET/POST /api/v1/my/workloads*`, wrapped in `requireRole(...,
   "tenant")` — note every role, including `operator`, must pass a `"tenant"` check too, i.e.
   `requireRole` checks "authenticated at all," and a stricter `"operator"` check is additive, not
   a separate hierarchy to design. §6/§7's redaction questions must be answered before this slice
   ships, not deferred past it, since it's this slice that first exposes `definition`.
3. **`/api/v1/overview` breaking change**: §3's workload-list removal, its own PR with an explicit
   "behavior change to shipped code" callout and updated dashboard JS/HTML.
4. **Operator queue/worker views**: read-only, gated `operator_readonly` (satisfied by
   `operator_admin` too, per §1's ranking), all from already-existing columns — the lowest-risk
   slice, could plausibly land before or in parallel with slice 2 if the accepting reviewer wants
   operator visibility sooner.
5. **Operator audit log**: new schema (an append-only `audit_events` table logging every
   Tenant/Operator-tier write action), its own slice — genuinely new work, not a read of existing
   data, sized separately. Read access is `operator_readonly`; nothing in slice 5 itself needs
   `operator_admin` unless a future slice adds destructive operator actions (stop-any-workload,
   revoke-any-key) that the audit log then needs to record — those actions themselves would be
   gated `operator_admin`.
6. **E2E tests** (#76's own separate item): once slices 1-4 exist, a real end-to-end test
   (login as tenant A, submit a workload, confirm tenant B's session cannot see it; login as an
   operator, confirm queue view works; confirm an unauthenticated caller gets exactly Public-tier
   data) becomes possible to write meaningfully — attempting it earlier would just be testing
   individual pieces already covered by their own slice's unit tests.

## Consequences

- `Overview`'s JSON shape loses its `Workloads` field — every existing consumer (today: only the
  dashboard's own `app.js`) must be updated in the same PR as §3's slice.
- A user's role becomes a real, persistent piece of authorization state for the first time in this
  codebase — `controlplane-admin grant-role` needs the same operational care (who has access to
  run it, is it logged) as `issue-key` already gets, since granting `operator_readonly` is granting
  cross-tenant visibility and granting `operator_admin` additionally grants destructive
  cross-tenant action (stop-any-workload, revoke-any-key) once those actions exist.
- §7 is now resolved (see Status), which unblocks slice 2 and slice 4 alike — "we'll figure out
  redaction/role-granularity later" is no longer a live risk for either.
- This proposal does not attempt multi-role users, fine-grained per-resource ACLs beyond
  ownership, or SSO/external-IdP integration — all plausible future needs, none required by #76's
  actual acceptance criteria, and adding any of them now would be exactly the kind of speculative
  complexity this proposal's role model (§1) deliberately avoids.
