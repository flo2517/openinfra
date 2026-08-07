# ADR-014: Wallet-based dashboard login

## Status

Accepted.

## Context

Issue #12 gave end users an authenticated identity, but only for machine
callers: a bearer API key, minted out-of-band by `cmd/controlplane-admin`
and pasted into whatever gRPC client calls `SubmitWorkload`/etc. There is
no human-facing login at all — the dashboard (#14/#76) is entirely
unauthenticated read-only data today.

Providers and Network Validators already authenticate to this system a
different way: prove control of an Ed25519 (or, for validators, any
`MultiSignature`-compatible) key by signing a server-issued nonce
(`internal/providerjoin`'s `BeginJoin`/`CompleteJoin`, domain-separated
`"openinfra-join-v1\0"`). No password, no pre-shared secret — the same key
the account *is* proves the account controls it. This is a better fit for
end users too, for two independent reasons: it is a strictly nicer browser
UX than copy-pasting an opaque token, and it is consistent with the rest
of this project's Bittensor-inspired, key-is-identity design rather than
introducing password-shaped UX for humans while everything else in the
system authenticates by signature.

WalletConnect was considered and set aside for this ADR: it changes
nothing about the server-side protocol below (a WalletConnect session
still ends in "here is a signature over this message"), so it can be
added later as a pure client-side transport option without any backend
rework. It was not chosen for the first slice because it requires
depending on an external relay network (a new, real dependency AGENTS.md
requires scrutiny for) and its Substrate/Polkadot support is less mature
than its Ethereum support; its real advantage — signing from a phone via
QR code — serves mobile/cross-device use, and this dashboard is an
operations tool used from a desktop first.

## Decision

### 1. Challenge/login endpoints

Two new endpoints on the dashboard's existing plain-HTTP listener
(`internal/dashboard`, not the mTLS gRPC listener the Agent talks to —
this is deliberately the browser-facing surface):

```
POST /api/v1/auth/challenge  -> { challenge_id, nonce, expires_at }
POST /api/v1/auth/login      { challenge_id, account, scheme, signature }
                              -> { session_key, expires_at }
```

`account` is the raw 32-byte public key (hex), `scheme` distinguishes
Ed25519 (0) from Sr25519 (1) — see §3. The signed message is
`"openinfra-dashboard-login-v1\0"` followed by the exact `nonce` bytes,
the same domain-separation convention `BeginJoin`/`CompleteJoin` and
heartbeats already use.

Both endpoints are unauthenticated by definition (that's the point) and
therefore need their own rate limit, keyed by caller IP via the existing
`internal/ratelimit`, tighter than the authenticated-user limit from #12
— an unauthenticated endpoint that does real work (signature
verification, a Postgres write) per request is a more attractive abuse
target than an authenticated one.

### 2. Challenge storage

A new `user_login_challenges` table, deliberately mirroring
`provider_join_challenges`'s exact shape and lifecycle (migration
000001): `challenge_id uuid PRIMARY KEY, nonce bytea, expires_at
timestamptz, consumed_at timestamptz`. Short TTL (5 minutes). Consumed
(single-use) the same way a provider join challenge is: `consumed_at` set
atomically on successful login, a second login attempt against the same
`challenge_id` fails. This is not a new pattern to design — it is the
existing one, applied to a second caller type.

### 3. Signature scheme: both Ed25519 and Sr25519

Every other key in this system (provider identity, the Control Plane
bridge, Network Validators) is Ed25519, and `internal/blockchainbridge`'s
extrinsic signing already only speaks Ed25519. But the default account
type the Polkadot.js browser extension generates — the most common real
wallet a user connecting to a Substrate-adjacent product will already
have — is Sr25519, and the chain's own `AccountId32`/`MultiSignature`
model is already scheme-agnostic (confirmed directly: the extrinsic
encoding `internal/blockchainbridge/registrar.go` builds includes an
explicit signature-scheme discriminator byte before the signature,
`0` for Ed25519). Accepting only Ed25519 here would make "connect your
Polkadot wallet" not work for most real Polkadot.js accounts out of the
box, which defeats the point of this ADR.

This means a new Go dependency for Sr25519 (Schnorrkel) verification —
flagged here explicitly for the scrutiny AGENTS.md requires of new
dependencies. Ed25519 verification needs nothing new (Go's standard
`crypto/ed25519`, already used throughout `internal/blockchainbridge`).

### 4. Identity model: `wallet_accounts` joins to the existing `users` table

`users.user_id` (from #12, migration 000009) stays a server-generated
UUID — **not** migrated to be the account bytes directly, to avoid
touching `workloads.owner_id`'s existing foreign key or any other already
-shipped reference to it. A new table:

```sql
CREATE TABLE wallet_accounts (
    account_id bytea PRIMARY KEY CHECK (octet_length(account_id) = 32),
    scheme     smallint NOT NULL, -- 0 = Ed25519, 1 = Sr25519
    user_id    uuid NOT NULL REFERENCES users(user_id),
    linked_at  timestamptz NOT NULL DEFAULT now()
);
```

One account maps to exactly one user; nothing yet stops (or needs to
stop) a user having multiple linked accounts — the table already supports
it, just with no UI for it yet.

**Auto-provisioning**: the first successful login for a never-seen
`account_id` creates a `users` row (`display_name` defaulted to an
abbreviated hex of the account, editable later, out of scope here) and
its `wallet_accounts` link in the same transaction. There is no separate
"register" step — connecting a wallet *is* registering, the same "Sign-In
with Ethereum"-style pattern this design otherwise already follows.

### 5. Session issuance reuses #12's API keys, not a new mechanism

A successful login does not invent a new session/cookie mechanism. It
mints a short-lived (24h) API key through the same path
`cmd/controlplane-admin` already uses (`userauth.CreateAPIKey`, extended
to accept an optional expiry — today it only ever creates keys with
`expires_at = NULL`), and returns the raw key once in the login response
body. The dashboard's JS stores it in `sessionStorage` (cleared when the
tab closes — a shorter-lived credential is a better fit for
`sessionStorage` than `localStorage`'s persistence) and sends it as
`Authorization: Bearer` on every subsequent dashboard API call.

This is the entire point of building it this way: `internal/userauth`'s
interceptor, `Authenticate`, revocation, and expiry logic from #12 need
**zero** changes to support wallet login — a session key is just an API
key that happens to have been minted by a signature instead of by
`controlplane-admin`, and expires instead of needing manual revocation.

### 6. Self-service long-lived API keys, after login

Once holding a session key, a new authenticated endpoint
(`POST /api/v1/auth/api-keys`) lets a user mint their own long-lived
(no-expiry, or an explicit longer expiry) API key for CI/automation use —
self-service, replacing `controlplane-admin issue-key` as the *primary*
path for a user who reaches the system through the dashboard first.
`controlplane-admin` remains, unchanged, as an operator break-glass tool
(a user locked out with no wallet access, or the very first bootstrap
before anyone has logged in).

### 7. Client-side signing: extension now is out of scope; local-key fallback is the first slice

Two client-side ways to produce the signature, both speaking to the exact
same backend endpoints above (the backend does not know or care which was
used):

- **Browser extension** (Polkadot.js, Talisman) via the standard
  `injectedWeb3` API real Substrate-ecosystem wallets already expose.
  Broader compatibility with a real wallet's key custody. **Deferred**
  past this ADR's first implementation slice — it is purely additive
  client-side JS once the backend exists, tracked in the implementation
  issue.
- **Local key fallback**: the dashboard generates (or imports) an
  Ed25519 keypair in the browser, using a small, specific, vetted
  JS Ed25519 library (not hand-rolled crypto), and signs locally. Weaker
  custody than a real wallet/extension (a browser-local key has no
  hardware backing and is only as safe as the browser profile it lives
  in) — the UI must say so plainly, not imply parity with a real wallet.
  This is the **first implementation slice**: it needs no new client
  dependency beyond one small crypto library, exercises the full
  challenge/login/session/self-service-key-issuance backend end to end,
  and does not need the Sr25519 dependency from §3 (a fallback-generated
  key can simply always be Ed25519) — meaning Sr25519 support can land in
  a second slice, together with extension support, without blocking the
  first slice's backend from being real and useful.

## Consequences

- Two new unauthenticated HTTP endpoints on the dashboard's public
  listener are a real increase in attack surface: they do a Postgres
  write and (for login) a signature verification per request. Both need
  their own rate limit and bounded-input tests (oversized/malformed
  `account`/`signature`, expired/already-consumed/unknown `challenge_id`,
  wrong-scheme signature).
- A new Go dependency for Sr25519 verification, needed by the second
  implementation slice, not the first.
- Session tokens are ordinary API keys under the hood: `internal/userauth`
  needs no new revocation/expiry code, only `CreateAPIKey` accepting an
  optional expiry (a small, additive change) instead of always `NULL`.
- The local-key fallback's custody model is weaker than a real wallet's;
  shipping it first (ahead of extension support) is a deliberate
  sequencing choice to prove the backend end to end quickly, not a claim
  that it is the intended primary experience long-term.
- `users.user_id` staying a UUID (not becoming the account bytes) means a
  user's "identity" is still an internal database concept that happens to
  have zero or more wallet accounts attached — not, architecturally, "the
  account is the user." This keeps today's schema/FKs untouched but is
  worth naming as a choice: it would be more purely "blockchain-native"
  to make the account itself the primary identity, traded off here for
  not touching #12's already-shipped `workloads.owner_id` foreign key.
