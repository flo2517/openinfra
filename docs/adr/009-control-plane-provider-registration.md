# ADR-009: Control Plane Provider Registration Authority

**Status:** Accepted (2026-08-05)

## Context

The Provider Agent proves ownership of an Ed25519 key to the Control Plane and must not communicate directly with Substrate in the MVP. The current `provider-registry::register_provider` extrinsic records `origin` as the provider account. A single Control Plane signer therefore cannot register multiple providers, while asking every Agent to submit the extrinsic would violate the accepted component boundary.

The off-chain provider identifier is currently `hex(SHA-256(agent_public_key))`; the runtime uses `AccountId32` as its storage key. Activation must not be reported until finalized chain state authoritatively confirms it.

## Decision

Add an authorized, additive `register_provider_for(provider, public_key)` extrinsic to `provider-registry`. Its `RegistrationOrigin` is configured as `EnsureRoot` in the development runtime; a future governance origin may replace it without changing Agent contracts. Keep the existing self-registration extrinsic for compatibility.

For the MVP, derive the provider `AccountId32` directly from the 32-byte Ed25519 public key. The Control Plane keeps its SHA-256 provider ID for external APIs and persists the corresponding chain account separately.

The Blockchain Bridge signs and submits registration and required status transitions with a dedicated operations account. PostgreSQL records `PENDING` plus transaction identifiers. The Control Plane exposes `ACTIVE` only after finalized storage or events confirm the provider is active. Submission and reconciliation are idempotent; private signing material is injected as a deployment secret and never stored in PostgreSQL or logs.

## Consequences

- Provider identity remains controlled by the Agent key while chain submission remains a Control Plane responsibility.
- Runtime tests must cover unauthorized registration, duplicate accounts and keys, transitions, and events.
- Control Plane tests must cover finalization, timeout, restart reconciliation, duplicate requests, and conflicting identity mappings.
- Deployment must provision and fund the bridge account and protect its key.
- This ADR must be accepted before changing the pallet interface or implementing signed submissions.

## Rejected Alternatives

- Register every provider under one Control Plane account: the storage model permits only one record per account.
- Give the Control Plane each Agent private key: this breaks identity ownership and secret isolation.
- Let the Agent submit directly to Substrate: this violates the frozen MVP architecture.
