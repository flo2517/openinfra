# ADR-037: Content-addressed distribution for the dashboard frontend

## Status

Proposed.

Written by Claude Code, autonomously, in direct response to issue #35 and the follow-up ADR-012 §6
names for it. Held as `Proposed` per the convention established by ADR-016/018/025/026/029/027/033:
nothing here is implemented by this ADR itself. Issue #35 is unblocked only once a repository owner
explicitly accepts this document, in-session, after reviewing its decisions.

**Numbering note, checked before writing anything.** ADR-012 §6's gate table names this gate
`ADR-021` ("content-addressed distribution and decentralized storage"). Fresh `origin/main` tops out
at `033` (`docs/adr/033-vm-execution-backend.md`); three further numbers are already claimed by
open, unmerged proposal PRs at the time of writing — `034` (`docs/adr-cinder-block-storage-proposal`,
PR #172), `035` (`docs/adr-neutron-security-groups-proposal`, PR #173), `036`
(`docs/adr-provider-slashing-economics`, PR #187) — so the true next-free number is `037`. This is
not a new collision needing ADR-012's cascading-renumbering fix: ADR-012's own "Consequences" section
already settled that gate names in its §6 table are "a reservation of intent, not a claim on the
number," and that "the next accepted ADR of any kind... takes the next integer regardless of what
this table says." `ADR-021` was never issued as an actual file — it simply gets skipped, the same way
`013`–`020` skipped ahead of their originally-reserved slots. At acceptance time, `AGENTS.md`'s
"decentralized storage (ADR-021)" citation and ADR-012 §6's table cell should be updated to point at
`037` — not done here, since this ADR is not yet accepted (see Consequences).

## Context

**What exists today, verified against source before writing anything below:**

- The dashboard's static bundle is five hand-written files —
  `control-plane/internal/dashboard/assets/{index.html,style.css,app.js,auth.js,tenant.js,operator.js}`
  — embedded into the Control Plane's own Go binary via `//go:embed assets/*`
  (`control-plane/internal/dashboard/dashboard.go:28`) and served at `GET /dashboard/` through
  `http.FileServer(http.FS(static))` (`dashboard.go:235`), inside `Server.Handler()`
  (`dashboard.go:209`). **There is no frontend build pipeline of any kind** — no bundler, no
  `package.json`, no transpilation step (confirmed: no `package.json`/`vite.config`/`webpack.config`
  anywhere in the repo outside an unrelated `.opencode` tool directory). "Reproducible build" for this
  ADR therefore means "deterministically hash and sign a directory of already-final static files," not
  "make an existing bundler deterministic."
- Every dynamic value the frontend needs is fetched from the Control Plane's own JSON API at
  same-origin relative paths — `fetch('/api/v1/overview...')`, `fetch('/api/v1/auth/challenge', ...)`,
  `fetch('/api/v1/auth/login', ...)` (`assets/app.js:30,74,115,144,188`; `assets/auth.js:149,158,186`).
  Nothing today distinguishes "the origin serving these static files" from "the origin the API lives
  at" because they are, today, the same origin by construction. That assumption breaks the moment the
  static bundle is served from a content-addressed gateway whose origin the Control Plane does not
  control — the central problem this ADR has to solve, not a side effect of it.
- `Server.Handler()`'s `securityHeaders` middleware (`dashboard.go:503-513`) sets exactly:
  `Content-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';
  script-src 'self'; frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on `/api/*` responses. This is set as
  an HTTP response header by the Go server. A static file served from an IPFS gateway this project
  does not operate cannot have a Go middleware set headers on it — this is a second concrete break,
  addressed in Decision §5.
- Login is already real and already keyed off signatures, not passwords: `internal/walletlogin`
  (ADR-014) issues a server-side nonce, verifies an Ed25519 or Sr25519 signature over
  `loginDomain ("openinfra-dashboard-login-v1\x00") ‖ nonce` (`walletlogin.go:25,140`), and on success
  mints a bearer session key through `internal/userauth`'s existing `CreateAPIKeyWithExpiry`
  (`userauth.go:159`; `HashAPIKey`/`GenerateAPIKey`, `userauth.go:124-141`, `oiu_`-prefixed, hashed at
  rest, raw value returned exactly once). `internal/providerjoin/service.go` uses the identical
  domain-separated-nonce-signature shape for Agent join/heartbeat (`joinDomain`/`heartbeatDomain`,
  `service.go:28-29,240,322`). This ADR reuses that exact convention for a new signature (release
  signing, §2) rather than inventing a fourth one. There is no `control-plane/internal/openstackapi/
  keystone/` package in this repository — checked directly, the directory does not exist — so wallet
  login's only real implementation to integrate with is `internal/walletlogin` + `internal/userauth`
  as read above.
- The Provider Agent's durable Ed25519 identity (`provider-agent/crates/agent-core/src/identity.rs`,
  `Ed25519IdentityManager`, key written 0600 via `write_private_key`) and ADR-027's mTLS leaf-cert
  enrollment are both **the wrong keys to reuse directly** for release signing, for the same reason
  ADR-027 §2 gave for not reusing the Agent's identity key as its TLS key: a release-signing key
  authenticates a different thing (a build artifact, not a provider or a TLS session) to a different
  audience (a browser verifying a download, not a peer completing a handshake), and folding it into an
  existing key multiplies that key's blast radius for no benefit. What *is* reused is the **pattern**:
  Ed25519, a domain-separated signed string, a 0600-permissioned local private key, and a publicly
  committed public key — exactly ADR-027 §2's own framing, applied to a new, narrowly-scoped key this
  ADR introduces (§2).
- `deployments/docker-compose.yml` already has a working precedent for adding a new stateful service
  with its own healthcheck, restart policy, and hardened `security_opt`/`cap_drop`/`read_only`/`tmpfs`
  posture (every existing service in the file follows this shape) — the shape §8's new `ipfs` service
  description below follows, without this ADR actually editing that file.
- ADR-012 §3's data-classification table already places "Dashboard / frontend assets" at target
  placement **content-addressed (#35)**, integrity need "Reproducible build + signature," availability
  "High," privacy "Public," retention "Versioned, rollback-safe" — this ADR's job is to make that row
  concrete, not to relitigate it. Every other row in that table (Workload metadata, Metrics, Logs,
  Secrets — all off-chain/encrypted/never-content-addressed) is unchanged by this ADR and is not
  revisited here.
- `gh issue view 35` acceptance criteria (restated in full): reproducible builds, signed releases,
  content hashes, rollback-safe version pinning; IPFS/Arweave or an approved equivalent evaluated with
  gateway/pinning/availability/cost strategy; no secrets/private keys/tenant data in static assets;
  wallet/identity login and API endpoint discovery authenticated and phishing-resistant; CSP,
  dependency integrity, revocation, and emergency takedown; offline/cache behavior and multi-gateway
  E2E tests. The issue body is explicit that this is "keeping API authorization and private data
  server-side until their own migration is complete" — this ADR does not move the API.

**Scope, stated before the Decision, not after.** ADR-012 §6 names `ADR-021` for `#35, #58, #59`
together. `#58` (S3-compatible object storage) and `#59` (replicated block volumes) are Stage 3
(v5.0) work with a fundamentally different shape — multi-tenant, mutable-by-owner, individually
authorized objects/blocks, not one project-published, publicly-readable static bundle — and are milestoned
after this issue's v3.0. **This ADR settles only what issue #35 needs: distributing the dashboard's own
static HTML/CSS/JS.** It does not choose, and should not be read as pre-choosing, the storage
technology or trust model for #58/#59; a future ADR must settle those on their own terms when that
work starts, and may or may not reuse IPFS.

## Decision

### 1. Storage technology: self-hosted IPFS (kubo), not Arweave, not a plain CDN

**Rejected: Arweave.** Arweave's entire value proposition is permanent, pay-once storage with no
ongoing pinning obligation — the wrong shape for a dashboard bundle in an MVP that is still iterating
rapidly (every workload-submission-form change, every RBAC UI change so far has shipped as a plain
`assets/*.js` diff) and needs frequent, cheap releases with real rollback, not a single permanent
inscription per version. It also requires a live AR-token market dependency this project has nowhere
else in its stack — the project's own Substrate chain (ADR-003/ADR-009) is a permissioned dev/test
network with no connection to any real payment rail, so "pay per release in a third-party token" would
be the first hard external-currency dependency this codebase has ever taken on, for a benefit
(permanence) that is actively undesirable here: permanence is a liability, not an asset, for the
takedown story in §7, since it means a compromised release can never actually be deleted from Arweave
at any price.

**Rejected: a plain CDN/object-storage bucket (S3, Cloudflare Pages, etc.) with a content hash in the
path.** This gets partway to "content hashes" and "rollback-safe pinning" cheaply, but it is not
decentralized distribution by any reading of the issue title or acceptance criteria — it is exactly
one more centralized origin the project alone controls, which is what this issue exists to move away
from. It is noted here only because it is the obvious cheaper alternative, and rejected on scope
grounds, not technical ones.

**Decision: IPFS**, using `kubo` (the reference Go implementation) self-hosted by this project,
justified against this project's actual constraints:

- **It matches the "another database" ADR gate this ADR exists to lift, precisely.** Content-addressed
  storage (immutable, hash-named, replicated by any node) is already a named placement class in
  ADR-012 §3's own vocabulary — IPFS is a direct, off-the-shelf implementation of exactly that class,
  not a new concept this ADR has to justify from scratch.
- **Zero-cost self-hosting fits the existing Docker Compose deployment story.** `kubo` ships as a
  single container with a documented image; adding it to `deployments/docker-compose.yml` (§8) follows
  the exact shape every other service in that file already follows (healthcheck, `restart:
  unless-stopped`, `security_opt: [no-new-privileges:true]`) rather than requiring a new deployment
  primitive, a new cloud account, or a recurring bill this MVP-stage project has no budget line for.
  Arweave has no equivalent self-hosted option at all — permanent storage is inherently a paid network
  service, not something you can run for free on your own hardware.
- **Its content-addressing is native, not bolted on.** A file's IPFS CID *is* its content hash; there
  is no separate "compute a hash, then also upload to a path" step to keep in sync, and "content
  hashes" (an explicit acceptance criterion) falls out of the storage model itself.
- **Multi-gateway is a mature, existing ecosystem**, not something this project has to build: public
  gateways (`dweb.link`, `ipfs.io`, Cloudflare's `cloudflare-ipfs.com`) already exist and already serve
  any pinned CID, giving the "multi-gateway" acceptance criterion real, already-deployed
  infrastructure to test against rather than a green field.
- **Cost model matches an MVP, not a funded production network.** IPFS pinning cost is proportional to
  bytes retained × replicas kept, controlled entirely by this project's own retention policy (§8) — a
  dashboard bundle is single-digit megabytes, and even redundant pinning across a self-hosted node plus
  one external pinning service is a cost this project can bound and stop at any time, unlike Arweave's
  irreversible-per-upload token spend.

### 2. Build and release pipeline: deterministic asset tree, a CID, a signed manifest published *outside* the bundle

**The bundle itself carries only what it needs to be self-describing on any gateway** — the existing
`assets/*` files, plus one new file, `config.json`, checked in alongside them and folded into the same
CID:

```json
{ "release_id": "2026-08-27T00:00:00Z-<short-manifest-hash>",
  "api_origin": "https://<control-plane-canonical-domain>",
  "allowed_login_origins": ["https://dashboard.<project-domain>"] }
```

`api_origin` is what `app.js`/`auth.js`/`tenant.js`/`operator.js` read instead of the same-origin-relative
paths they use today (Decision §4 explains why this alone is not sufficient for phishing resistance).
Because `config.json` is part of the hashed, CID-addressed tree, a gateway serving a tampered copy with
a different `api_origin` produces a *different* CID — this is the one piece of tamper-evidence content
addressing gives for free, and it is necessary but not sufficient (§4).

**Build steps** (described here as the process this ADR requires; not implemented by this ADR):

1. The static asset directory is built exactly as it is checked into
   `control-plane/internal/dashboard/assets/` today, plus `config.json` — no new compiler, no minifier,
   consistent with "no frontend build pipeline exists" from Context.
2. `ipfs add -Q -r --cid-version=1 --raw-leaves` over that directory. Pinning the exact flags is
   load-bearing for reproducibility: `--cid-version=1` and `--raw-leaves` are not `kubo`'s legacy
   defaults, and a build using different flags produces a different CID for byte-identical input —
   this ADR fixes the flags so "reproducible" is checkable by any third party re-running the same
   command, not just asserted.
3. A manifest is built **separately, outside the CID-addressed tree** (avoiding the self-referential
   problem of a file needing to describe its own hash):
   `{schema_version, cid, files: [{path, sha256, size}, ...], manifest_sha256, api_origin,
   allowed_login_origins, previous_cid, released_at}`.
4. The manifest is signed: `signature = Ed25519.sign(release_key, "openinfra-frontend-release-v1\x00"
   ‖ manifest_sha256 ‖ cid)` — the same domain-separated-string convention as `joinDomain`/
   `heartbeatDomain`/`loginDomain` above, with its own `v1` domain string so it can never be replayed
   against those flows or vice versa.
5. The signed manifest is published at two places outside the content-addressed tree, forming the
   actual trust root (§3) — never inside it, since anything inside the CID cannot anchor trust in that
   same CID.

**Release-signing key.** A new Ed25519 keypair, distinct from the Agent identity key, the mTLS CA key
(ADR-027), and any user's wallet key — reusing the *pattern* ADR-027 §2 already established for "why a
fresh key, not an existing one," not reusing the key itself. Private key held by whoever runs releases
(repository owner or CI, 0600 file convention as elsewhere in this codebase); public key committed to
the repository (e.g. `deployments/release-signing-pubkey.hex`, mirroring how `ca.crt` is already a
committed, non-secret artifact) and republished at the `.well-known` endpoint (§3) so a verifier never
has to trust the gateway to learn it. Key custody and rotation cadence are **not decided by this ADR**
— flagged as an open question (below), the same way ADR-027 left its own CA-root-algorithm question
open rather than silently picking an answer.

### 3. Canonical trust root: DNSLink + a `.well-known` endpoint, two trust tiers

A CID alone gives *integrity* (this exact content, unmodified) but not *provenance* (this is the
content the project actually released, not a phishing clone published under a different, unrelated
CID at a lookalike domain). Provenance needs one thing content-addressing structurally cannot supply
on its own: a root the user already trusts before they ever see the gateway.

- **Canonical origin.** The project's own DNS-registered domain (unresolved — see Open Questions)
  publishes a `.well-known` endpoint over ordinary domain-validated TLS —
  `GET https://<project-domain>/.well-known/openinfra-frontend` — returning exactly the signed
  manifest from §2. This is deliberately *not* itself content-addressed: it is the one piece of
  infrastructure this ADR still asks the project to operate and trust directly, by design, because a
  root of trust has to live somewhere that isn't circularly verified by the thing it's supposed to
  verify. What changes versus today is the size of that trusted surface: today the entire dashboard
  (every byte a user's browser runs) is server-trusted; after this ADR, only a small, auditable JSON
  document and its TLS certificate are.
- **DNSLink**, a `TXT` record at `_dnslink.dashboard.<project-domain>` resolving to `dnslink=/ipfs/
  <current CID>`, gives IPFS-native clients (Brave's built-in resolver, the `ipfs://` protocol handler,
  `ipfs-companion`) a human-memorable, DNS+TLS-anchored URL that still ultimately serves
  gateway-independent IPFS content. This is the **recommended primary access path** for this ADR, not
  a bare `<gateway>/ipfs/<cid>` URL.
- **Two trust tiers, stated explicitly, not blurred:**
  1. **Canonical tier** — the DNSLink-backed origin and/or a self-hosted `kubo` gateway this project
     operates directly (§8), reachable over the project's own TLS certificate. Full functionality:
     wallet login enabled, real API calls allowed.
  2. **Mirror tier** — third-party public gateways (`dweb.link`, `ipfs.io`, `cloudflare-ipfs.com`, ...).
     Trusted for availability only, exactly matching ADR-012 §2's existing "Storage node" trust row
     ("Trusted for: serving bytes that match their advertised hash... Never trusted for: retention
     without a proof, or confidentiality without client-side encryption") applied here to a gateway
     instead of a storage node. Read-only rendering works there (harmless: the bundle is public by
     construction, §6); §4 makes wallet login and authenticated API calls refuse to run from any
     mirror-tier origin.

**Vocabulary note.** ADR-012 §1 defines "Gateway node" as Stage-2 (#54) public-ingress routing into
the private workload mesh — a different, not-yet-built thing. "IPFS gateway" in this ADR is an
unrelated, pre-existing piece of public internet infrastructure this project does not operate (except
for its own self-hosted instance, §8) — the two are not to be conflated, per ADR-012 §1's own
insistence on precise vocabulary.

### 4. Phishing resistance: origin-pinned login, not CSP or hashing alone

This is the hardest problem this ADR has to answer, and it is not fully solved by §§1-3 alone — a
byte-for-bit copy of a legitimate release, republished under a *different* CID at a malicious gateway
URL a phishing email links to, is cryptographically indistinguishable from the real one until a user
checks it against something. The mechanisms above (pinned `api_origin` inside the CID, a DNS+TLS
canonical root outside it) are necessary. The following is the concrete control that actually blocks a
phishing clone from doing damage even if a victim never checks anything:

- **The API's CORS policy is the enforcement point, not the frontend's own JavaScript** (client-side
  checks alone are trivially stripped by a malicious copy). `internal/userauth`'s bearer-key
  authentication and `internal/walletlogin`'s login endpoint both start responding
  `Access-Control-Allow-Origin` only for origins in `config.json`'s `allowed_login_origins` list — the
  canonical DNSLink origin and the self-hosted gateway origin, nothing else. A phishing clone served
  from `evil-gateway.example/ipfs/<some-other-cid>` can render the page, but the browser's own CORS
  enforcement blocks its `fetch('/api/v1/auth/challenge')` call before any credential material is
  exchanged with the real API — the same "browser enforces it, server declares it" mechanism `dashboard.go`'s
  existing `Content-Security-Policy` header already relies on, extended to cross-origin credentialed
  requests specifically.
- **Residual risk, stated honestly rather than glossed over**: CORS protects *browser-initiated*
  cross-origin requests. It does **not** stop a more sophisticated phishing page from running its own
  server-side relay — proxying the victim's browser interaction through a backend the attacker
  controls, which then makes its own, non-browser, non-CORS-checked request to the real API. This is a
  live-relay ("real-time phishing") attack, and it is a known, structurally hard-to-fully-close problem
  for *any* challenge-response login (ADR-014's flow, faithfully replayed live, still produces a valid
  signature over the real nonce). This ADR does not solve that class of attack — no ADR realistically
  can with signatures alone — and says so explicitly rather than claiming "phishing-resistant" means
  "phishing-proof." What this ADR *does* close is the much larger, much easier attack this issue is
  actually about: a static clone silently harvesting credentials or redirecting API calls to an
  attacker-controlled backend, which CORS plus the pinned `api_origin` fully prevents. A live relay
  attack requires active, real-time attacker participation per victim, not a passively-hosted clone —
  a materially higher bar, even if not zero.

### 5. CSP and headers under gateway hosting

`dashboard.go:503-513`'s `securityHeaders` middleware cannot run on content served by a gateway this
project doesn't operate. Two concrete changes:

- **CSP moves into a `<meta http-equiv="Content-Security-Policy">` tag in `index.html` itself** (part
  of the hashed, signed tree — a tampered CSP changes the CID). Content mostly unchanged from today's
  header, with one required edit: `connect-src 'self'` becomes `connect-src https://<canonical-api-
  origin>` explicitly — `'self'` would otherwise mean "whichever gateway happens to be serving this
  copy," which is not the guarantee this directive exists to provide once asset origin and API origin
  diverge.
- **A real, spec-level limitation, stated rather than hidden: `frame-ancestors` is ignored entirely
  when delivered via `<meta>`** (per the CSP specification — a header-only directive). This ADR cannot
  restore header-level `frame-ancestors 'none'` on third-party public gateways it does not operate.
  Mitigations, layered rather than pretending this is fully closed: the self-hosted `kubo` gateway
  (§8, canonical tier) *can* be configured with custom response headers (`Gateway.HTTPHeaders` in
  `kubo`'s own config), so the canonical access path keeps full header-level protection including
  `frame-ancestors`; the mirror tier does not, and is explicitly documented as such. This is one more
  reason §4's CORS/origin allowlist — not CSP — is the actual load-bearing phishing/credential-theft
  control, since it does not depend on which tier served the page.
- `X-Content-Type-Options: nosniff` and `Referrer-Policy` have `<meta>`-equivalent-or-close-enough
  behavior via server or gateway config where controllable (canonical tier); on third-party mirrors
  they depend on that gateway's own default posture, outside this project's control — named as a known
  gap of relying on any infrastructure this project doesn't operate, not something this ADR invents a
  workaround for.

### 6. No secrets, private keys, or tenant data in static assets

Structurally already true, not merely a policy this ADR adds: ADR-016 already moved every per-tenant,
non-public dashboard value behind authenticated, server-side-scoped endpoints
(`GET /api/v1/my/workloads`, gated by `requireRole(userauth.RoleTenant, ...)`), and the public
`/api/v1/overview` endpoint already reports only aggregates (`WorkloadsByState` counts, not per-workload
rows — `dashboard.go`'s own comment at the `stateRows` query: "Per-workload detail now lives behind
`GET /api/v1/my/workloads`, scoped to its owner"). The static bundle itself is pure HTML/CSS/JS with no
server-side templating step that could ever interpolate a secret into it — there is no code path today
by which a secret, private key, or tenant row could end up in `assets/*`. This ADR adds one new,
mechanical guard on top of that structural fact: the release pipeline (§2) runs a fixed-pattern scan
(the `oiu_` API-key prefix, PEM key headers, common cloud-credential shapes) over the built tree before
signing, and refuses to sign and publish on any match — a fail-closed backstop against a future
accidental regression, not evidence that one is expected.

### 7. Revocation and emergency takedown

Content-addressed data is, per ADR-012 §4, "only as available as the nodes pinning it" — the converse
is also true and is the actual limitation this section has to be honest about: **this project cannot
force any third-party pinning service or public gateway to delete bytes it has already chosen to
mirror.** Takedown here is bounded and layered, the same "state the real bound, don't claim
instantaneous" discipline ADR-027 §4 already used for certificate revocation:

1. Unpin the compromised CID from the project's own `kubo` node and any project-controlled external
   pinning service — immediate, within this project's control.
2. Publish an updated, freshly signed manifest at the `.well-known` endpoint and DNSLink record,
   pointing at a patched CID and recording the compromised CID's revocation (reason, timestamp) in the
   manifest's history — anyone who checks the canonical root (as the recommended access path in §3
   directs them to) stops being pointed at the bad release immediately.
3. **The load-bearing cutoff for anything that matters, and it needs no propagation delay at
   all**: §4's CORS/`allowed_login_origins` check already refuses credentialed API calls from any
   origin the compromised release wasn't explicitly issued to trust. If the compromise is the release
   itself (not a stolen origin), the same manifest update in step 2 also rotates
   `allowed_login_origins`, so even a still-reachable, still-pinned-by-third-parties copy of the old
   release can no longer complete a real login or reach the real API the moment that change is live —
   independent of whether any external mirror ever actually removes the bytes.
4. What this does **not** achieve: a copy already fetched and cached by a third party (another
   pinning service, a browser's own IPFS cache, an archive crawler) keeps existing indefinitely as
   inert, unreachable-to-the-real-API bytes. This is a permanent, structural property of content
   addressing this ADR cannot design around — which is exactly why §6's "no secrets, ever" is load-
   bearing and non-negotiable, not a nice-to-have: the takedown story only works because there was
   never anything in the bundle worth taking down for confidentiality reasons in the first place, only
   for correctness/trust reasons.

### 8. Pinning, retention, and the new `kubo` service

Described here as the operational shape this ADR requires; the actual `deployments/docker-compose.yml`
edit is implementation, not made by this ADR. A new `ipfs` service, following the file's existing
pattern exactly (own healthcheck against `kubo`'s API, `restart: unless-stopped`,
`security_opt: [no-new-privileges:true]`, a named volume for its blockstore, ports bound to
`127.0.0.1` for the API/gateway the same way `postgres`/`redis`/`blockchain-node` already are).
Retention: keep the last **10** published releases pinned (an explicit, revisitable number, not
"forever") — old enough to cover any realistic rollback window (§9), bounded enough that storage cost
stays proportional to recent history, not full release lineage. Redundancy beyond the self-hosted node
— a second, external pinning service — is named as a real option but left as an **open question**
(below): worth the small recurring cost for genuine single-point-of-failure protection, or an
unnecessary expense at MVP scale where a single self-hosted pin plus the existing Docker Compose
healthcheck/restart discipline is probably enough. Not decided here.

**Erasure, addressed explicitly so it is clear this ADR is not inventing a new obligation.** ADR-012
§4's erasure guarantee is scoped to *tenant-private* classes (workload metadata, logs, secrets) —
"Dashboard / frontend assets" is classified **Public** in ADR-012 §3's own table. Nothing in this data
class is personal or tenant data (§6), so ADR-012's erasure rule simply does not apply to it; the only
"removal" concept that matters here is the security-incident takedown in §7, which is a different
guarantee (stop trusting/serving a compromised release) from privacy-driven erasure (delete a specific
person's data on request).

### 9. Rollback

Because every release is a distinct, immutable CID and the last 10 stay pinned (§8), rollback is
republishing a manifest (§2 step 5) pointing `cid` back at a previous, still-pinned, still-signed
release — no rebuild, no redeploy of the Control Plane itself, propagating exactly as fast as a
`.well-known` HTTP response and a DNS TXT record do (typically sub-minute; real DNS TTL tuning is an
operational detail, not designed here).

### 10. Offline and cache behavior

The bundle's immutability (a new release is a new CID/URL, never an in-place mutation of an old one)
is a natural fit for a cache-first Service Worker over the static shell (`index.html`/`*.js`/`*.css`) —
once fetched, a given release's assets never need re-validation, since they cannot change under a
fixed CID. `/api/*` calls stay network-only/no-store, matching `dashboard.go`'s existing
`Cache-Control: no-store` on API responses (`dashboard.go:503-513`) unchanged. Left genuinely open (see
Open Questions): what a client with a Service-Worker-cached *old* release should do when that release
has since been revoked (§7) or superseded (§9) — this ADR does not fully design a "your cached copy is
stale, please refresh" UX.

### 11. Testing: multi-gateway E2E

A new `tests/e2e` suite (not written by this ADR, matching this document's own "docs only" scope)
should exercise, at minimum: (a) the same login → fetch-my-workloads flow succeeding from the canonical
DNSLink/self-hosted-gateway origin; (b) the same flow's login step being *rejected* (CORS failure, not
a silent fallback) from at least one mirror-tier public gateway origin, proving §4's allowlist is live,
not aspirational; (c) read-only rendering succeeding from a mirror-tier gateway, proving the public
overview still works there; (d) a rollback (§9) actually serving the previous release's exact bytes
after a manifest update, with no rebuild step; (e) the CSP `<meta>` tag present and blocking an injected
inline script, exercised the same way `dashboard_test.go`'s existing `securityHeaders` header-presence
test does today, adapted for a `<meta>`-tag assertion instead of a header assertion.

### 12. Relationship to ADR-012 §6's `ADR-021` gate

This ADR is the accepted-or-not answer to the `ADR-021` gate **for issue #35's slice only** — static
dashboard frontend distribution. It settles the four things ADR-012 §6 requires that gate to settle,
scoped to this slice: **pinning** (§8, self-hosted `kubo` plus an open redundancy question),
**retention proofs** (§8, an explicit 10-release window — not a cryptographic retention proof scheme,
which is not needed here since the project's own node is the authoritative pinner, unlike a
trust-minimized multi-party storage-market design), **erasure** (§8, explicitly inapplicable to this
Public-classified data, per ADR-012 §3/§4), and **gateway trust** (§3's two-tier model). It does
**not** settle pinning/retention/erasure/gateway-trust for `#58`/`#59` — those need their own
accepted ADR when that Stage 3 work starts, informed by but not bound to this one's choices.

## Consequences

- **`AGENTS.md`'s "decentralized storage (ADR-021)" prohibition** is lifted, narrowly, for the one
  purpose this ADR describes (public, non-authoritative frontend static assets) — not for `#58`/`#59`,
  which stay prohibited until their own ADR. This edit, and ADR-012 §6's table-cell correction from
  `ADR-021` to `037`, happen at acceptance time, in the acceptance PR, not in this document (this
  ADR's Status stays `Proposed`).
- **No `protocol/proto` changes.** This is the first ADR in this sequence (compare ADR-027, ADR-033)
  that touches no cross-process wire contract at all — the frontend's own `fetch()` target changes
  (relative path → `config.json`'s `api_origin`), but the API surface it calls is unchanged.
- **New operational surface**: a `kubo` service in `deployments/docker-compose.yml` (§8); a release
  pipeline and a new Ed25519 release-signing key needing custody and rotation procedure (§2, open
  question); a `.well-known` endpoint and DNSLink `TXT` record the Control Plane's own domain must
  serve (§3); a CORS-origin-allowlist change to `internal/userauth`/`internal/walletlogin`'s handlers
  (§4).
- **`GET /dashboard/`'s existing direct-serve path is additive, not replaced.** Mirroring ADR-033 §1's
  "additive, not a replacement" framing: the Control Plane keeps serving `assets/*` directly exactly as
  it does today (this remains the simplest path for local dev and is likely also how the canonical
  self-hosted `kubo` gateway itself gets exposed publicly); IPFS/DNSLink access is a new, additional,
  decentralization-oriented path alongside it, not a cutover.
- **CSP moves from a header to a `<meta>` tag** (§5) with a stated, real capability loss
  (`frame-ancestors` unenforceable via `<meta>` on any gateway this project doesn't directly configure)
  — a genuine, named trade-off, not a wash.
- **A permanent limitation this ADR cannot design around**: once a release is pinned by any third
  party this project doesn't control, this project cannot force its deletion (§7) — the reason §6's
  "no secrets, ever" rule is treated as absolute rather than best-effort.

## Open questions for the accepting reviewer

- **Canonical domain.** This ADR assumes a project-owned, DNS-registered domain capable of hosting a
  `.well-known` endpoint and a `TXT` record; the project's dev stack today only has `localhost`. Where
  that domain comes from, and who administers its DNS, is not decided here.
- **Release-signing key custody and rotation.** Held by the repository owner personally, by CI as a
  secret, or something else — and how often it rotates — is not decided here, matching how ADR-027 left
  its own analogous CA-root-algorithm question open rather than silently picking an answer.
- **External pinning redundancy.** Worth a second, paid pinning service for genuine single-point-of-
  failure protection at this project's current MVP scale, or is a single self-hosted `kubo` node
  (with ordinary Docker Compose restart/healthcheck discipline) an acceptable initial risk to accept
  and revisit later? Not decided here.
- **Whether to enable the mirror tier (§3) at all yet.** Shipping DNSLink + self-hosted-gateway only,
  with *no* third-party public-gateway CORS allowlisting in the first release, is a strictly smaller,
  more conservative first slice than what §3/§4 describe — worth the owner's explicit call on whether
  to start there and expand later, rather than shipping both tiers from day one.
- **Stale-cache UX (§10).** A Service-Worker-cached old release, after a takedown (§7) or a rollback
  (§9), needs some "this release is stale, please refresh" behavior this ADR does not fully design.

## Verification

Checked against source before writing: `control-plane/internal/dashboard/dashboard.go` (full file —
`Handler()`, `//go:embed assets/*` at line 28, the `/dashboard/` file-server mount at line 235,
`securityHeaders` and its exact CSP string at lines 503-513, `loadOverview`'s public/aggregate-only
workload-state query and its own comment citing ADR-016 §3); `control-plane/internal/dashboard/assets/
{index.html,app.js,auth.js}` (confirmed every `fetch()` call target is a same-origin relative path,
confirmed no build tooling references anywhere); `control-plane/internal/dashboard/agentendpoint.go`
(full file — the existing "public data, no new trust boundary" precedent for an unauthenticated
endpoint); `control-plane/internal/walletlogin/walletlogin.go` (full file — `loginDomain`,
`Login`'s signature-verification flow, `Session`/`Repository` shapes); `control-plane/internal/
userauth/userauth.go` (full file — `APIKey`/`GenerateAPIKey`/`HashAPIKey`, `RoleTenant`/
`RoleOperatorReadOnly`/`RoleOperatorAdmin`, `Authenticate`); `control-plane/internal/providerjoin/
service.go` (`joinDomain`/`heartbeatDomain` constants and their signed-message construction, lines
28-29, 240, 322 — the domain-separation convention reused in §2); confirmed no
`control-plane/internal/openstackapi/keystone/` directory exists anywhere in this repository;
`provider-agent/crates/agent-core/src/identity.rs` (full file — `Ed25519IdentityManager`,
`write_private_key`'s 0600 handling, the pattern §2's release key reuses); `docs/adr/
027-mtls-pki-enrollment-rotation-revocation.md` (full file — the "why a fresh key, not an existing
one" reasoning §2 mirrors, the revocation-bound-not-instantaneous framing §7 mirrors); `docs/adr/
033-vm-execution-backend.md` (full file — format/voice precedent, the "additive, not a replacement"
framing reused in Consequences, its own Verification-section discipline of confirming the next-free
ADR number against `main` and open PRs before writing); `docs/adr/012-decentralization-roadmap-and-
trust-boundaries.md` (full file — §1 vocabulary, especially "Gateway node"'s Stage-2/#54 meaning
disambiguated from this ADR's unrelated "IPFS gateway" usage in §3; §2's "Storage node" trust row,
reused for gateway trust in §3; §3's full data-classification table, especially the "Dashboard /
frontend assets" and "Workload metadata"/"Metrics"/"Logs"/"Secrets" rows, none of which are
relitigated here; §4's replay-protection and erasure conventions; §6's gate table and its exact
`ADR-021` naming for `#35, #58, #59`; the "Consequences" section's renumbering policy, applied directly
to this ADR's own number); `AGENTS.md` (full file — the "another database"/"decentralized storage
(ADR-021)" prohibited-changes line this ADR proposes lifting narrowly); `deployments/
docker-compose.yml` (full file — confirmed the exact service-definition shape, healthcheck/
`security_opt`/`restart` conventions §8's described `ipfs` service follows, without editing this file);
`gh issue view 35` (full text — every acceptance-criteria bullet addressed by a numbered section
above); `git ls-tree -r origin/main -- docs/adr` and `gh pr list -R flo2517/openinfra --state open
--json number,title,headRefName` (confirmed `033` is `main`'s highest merged ADR and `034`/`035`/`036`
are claimed by open, unmerged PRs at time of writing, making `037` this ADR's number).

Refs #35. Related: ADR-012 (§3 data classification — the target-placement row this ADR fulfills; §6
gate table — the `ADR-021` name this ADR's actual number diverges from, expectedly), ADR-014
(wallet-based dashboard login — the signature convention §2/§4 build on), ADR-016 (dashboard RBAC and
tenant isolation — the reason the static bundle already contains no tenant data, §6), ADR-027 (mTLS
PKI hardening — the fresh-key-per-purpose and honestly-bounded-revocation patterns this ADR reuses),
ADR-033 (VM execution backend — the "additive, not a replacement" framing and next-free-number
verification discipline this document follows).
