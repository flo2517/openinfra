# Dashboard: migration path to decentralized static hosting

## Status

Planning note, not an ADR. It authorizes no implementation by itself — see "Relationship to
ADR-012" below. Written to close the corresponding item in issue #76 ("a migration path from the
MVP same-origin UI to decentralized static hosting — not written up anywhere yet").

## Where the dashboard is today (Stage 0)

`control-plane/internal/dashboard` serves the dashboard as static assets embedded directly in the
Control Plane's own Go binary (`//go:embed assets/*`, `internal/dashboard/dashboard.go`) at
`GET /dashboard/`, same-origin with every JSON API it calls (`/api/v1/overview`,
`/api/v1/validator-scores/{provider_id}`, the `/api/v1/auth/*` wallet-login endpoints). This is
exactly ADR-012 §3's Stage 0 placement for the "Dashboard / frontend assets" data class: "Served by
the Control Plane". It is also a single point of failure and a single point of trust — one
operator's binary is both the only place the UI can be fetched from and the only origin the
browser's `Content-Security-Policy` (`default-src 'self'`, `internal/dashboard/dashboard.go`'s
`securityHeaders`) will trust.

ADR-012 §3 already names the target: **content-addressed**, gated behind the still-unwritten
"content-addressed distribution and decentralized storage" ADR (renumbered `ADR-021` per ADR-012's
own "Consequences" correction — see that ADR for why the number moved). That gate ADR is scoped
far beyond the dashboard alone: it also covers S3-compatible object storage (#58) and replicated
block volumes (#59), and per ADR-012 §6 it "must settle: pinning, retention proofs, erasure, and
gateway trust" for *all three*. This document does not attempt to settle those — it only lays out
the dashboard-specific path so that work has somewhere to land once the gate ADR exists, and so
`#76`'s acceptance criterion has an honest answer today rather than silence.

## Why this is harder than "upload the build to IPFS"

The dashboard is not a static site today — it is a thin client over authenticated, live,
same-origin APIs:

- **Same-origin CSP.** `securityHeaders` sets `connect-src 'self'`. A dashboard served from a
  content-addressed host (a different origin than the Control Plane API) needs a CSP that names the
  API origin(s) explicitly, which reopens a CORS/CSRF design question this repository has not
  needed to answer yet — today "same origin" *is* the authentication boundary for the unauthenticated
  read endpoints (`agentEndpoint`, `validatorScores`), and loosening it changes that boundary.
- **Wallet login's origin binding.** ADR-014's challenge/signature flow (`internal/walletlogin`) and
  its browser client (`assets/auth.js`) generate and store an Ed25519 keypair in the browser's
  `localStorage`, which is origin-scoped by the browser itself. Moving the UI to a
  content-addressed origin either fragments a user's stored key per hosting mirror (bad UX: "log
  in again from every gateway") or requires a deliberate decision to widen key storage beyond
  single-origin `localStorage` (a real security-relevant change, not a hosting detail).
- **Multiple Control Plane replicas don't exist yet.** ADR-012 Stage 1 (#34, gated by the
  renumbered `ADR-017`) is what makes "which Control Plane API does this dashboard build talk to"
  a real question with more than one honest answer. Decentralizing the frontend before
  decentralizing the API it calls only decentralizes the part that was never the trust bottleneck.
- **Versioning and rollback.** A content-addressed build is immutable by construction (new build,
  new hash). ADR-012 §7's rollback guarantee ("every stage must keep its predecessor operable for
  one release") means an old, pinned build must keep working against a newer Control Plane API for
  at least one release window — this repository's dashboard/API pairing has never had to be
  backward compatible before, because there has only ever been one build talking to one API.

None of this is a reason not to do it. It is the reason it needs the gate ADR's actual
pinning/retention/erasure/gateway-trust decisions settled first, rather than a build script bolted
on ahead of them.

## Proposed staged path

Mirrors ADR-012 §5's own staging discipline: each stage removes one piece of the current
same-origin assumption, keeps the previous stage's path working, and is explicit about what
degrades if it fails.

**Stage 0 (today).** Embedded in the Control Plane binary, same-origin. No action needed; this
document changes nothing about it.

**Stage 0.5 — decoupled build, still Control-Plane-served (no new trust boundary).** Extract
`internal/dashboard/assets` into a standalone static build (its own `package.json`/build step is
optional — the assets are already hand-written HTML/CSS/vanilla JS with no bundler dependency
today, so "build" may just mean "lint and version-stamp"), still served by
`//go:embed` from the same binary at the same origin. This is pure refactoring with zero behavior
change and needs no ADR: it does not move any data class, per ADR-012 §3's "Nothing here moves a
class from off-chain to on-chain" framing (moving *how a build is produced* is not moving *where a
data class lives*). Value: makes every later stage a smaller diff, and lets CI verify the dashboard
build in isolation from the Go binary.

**Stage 1 — content-addressed mirror, Control-Plane-served remains the default and the source of
truth.** Publish each build's static output to content-addressed storage (IPFS or equivalent — the
gate ADR chooses) *in addition to* the existing `//go:embed` path, with the Control Plane
continuing to serve `/dashboard/` itself as the default entry point. The published hash is
advertised (e.g. a `GET /api/v1/dashboard-build` endpoint reporting the current build's hash),
letting an operator who wants to self-host or mirror it not depend on this Control Plane's uptime,
without yet requiring any browser trust the mirror over the origin. This needs the gate ADR's
pinning/retention answer (who keeps the content available, and for how long) but not its full
gateway-trust or multi-origin-CSP answer, since nothing about how the *default* dashboard is served
changes yet.

**Stage 2 — content-addressed as an explicit alternative, CSP widened deliberately.** Once ADR-012
Stage 1 (#34, multi-Control-Plane) has landed, widen `connect-src` to a configured allowlist of
known Control Plane API origins and document a supported way to run the dashboard build from a
content-addressed gateway against any of them. This is the point where the wallet-login
origin-scoping question above must be answered (widen key storage deliberately, or accept
per-origin re-login) — that decision belongs in the gate ADR, not here.

**Stage 3 — content-addressed as the default, Control-Plane-served becomes the fallback.** Flip the
default entry point once Stage 2 has run in production long enough to trust its gateway/pinning
story, keeping direct Control-Plane serving available per ADR-012 §7's rollback rule.

## What this document does not do

- It does not choose a content-addressing technology, a pinning provider, or a CDN — those are the
  gate ADR's decisions (ADR-012 §6).
- It does not authorize starting Stage 0.5 or later — Stage 0.5 needs no ADR per the reasoning
  above, but Stage 1 onward is gated the same way every other item in ADR-012 §6 is: "No
  implementation in those milestones starts before its gate ADR is accepted" (`ROADMAP.md`).
- It does not resolve the wallet-login origin-scoping question raised in Stage 2 — flagged for the
  gate ADR to settle, not decided here.

## Relationship to ADR-012

This document elaborates ADR-012 §3's "Dashboard / frontend assets" row and §6's `ADR-021` gate
(originally reserved as `ADR-018` before the renumbering documented in ADR-012's own
"Consequences" section) without being that gate ADR itself. When `ADR-021` is written, it should
supersede this document's staging proposal or explicitly adopt it — this file is not meant to be
maintained in parallel with an eventually-accepted ADR covering the same ground.
