# ADR-015: Independent bandwidth throughput measurement

## Status

Accepted.

## Context

Issue #30's first slice (merged) made bandwidth a reserved, scheduled
resource — but the capacity a provider advertises is entirely
operator-declared, the same trust boundary as its price/reputation
self-declarations, with zero independent verification (issue #73). The
Network Validator daemon built for #78/ADR-013 does independently test
every `ScoreDimension` including `Network` — but `SolveChallenge`'s
existing protocol (`agent-api`'s `solve_challenge` handler,
`MAX_CHALLENGE_PAYLOAD = 4096` bytes) computes `SHA256(payload)` on a
small, bounded input and times the whole RPC round trip. That is a
liveness-and-correctness test — proof the Agent is reachable and signs
correctly within a deadline — not a throughput measurement. A 4 KB
payload transferred in a few seconds says essentially nothing about a
link's real Mbps capacity, especially on a fast local/dev network where
transfer time is dominated by RPC/TLS overhead, not payload size.

`agent-api`'s `StreamMetrics` RPC exists in `agent.proto` but is entirely
unimplemented (`Status::unimplemented`) — not reusable as-is, and its
shape (an empty request, a stream of periodic metrics *from* the Agent)
doesn't fit an active bandwidth probe naturally; it reads as designed for
ongoing telemetry, not a bounded on-demand measurement.

This ADR decides the measurement protocol only — see #73 for the larger,
explicitly out-of-scope remainder (WireGuard overhead accounting,
regional endpoint selection, workload-level rate limit enforcement, and
the adversarial test suite: congestion, asymmetric links, spoofed
results, partitions).

## Decision

### 1. A new, dedicated RPC — not an overload of `SolveChallenge`'s `TYPE_NETWORK`

`TYPE_NETWORK` already exists, is merged, and is exercised by the live
challenge loop (#85) with its existing small-payload semantics.
Redefining what it measures now would silently change already-shipped,
tested behavior. Instead: a new RPC,
`rpc MeasureBandwidth(MeasureBandwidthRequest) returns (MeasureBandwidthResponse)`,
on `ProviderAgentService`.

```protobuf
message MeasureBandwidthRequest {
  string probe_id = 1;
  // Sent by the validator; its size is what's actually being measured
  // for *ingress* (validator -> Agent). Bounded server-side (see §3).
  bytes upload_payload = 2;
  // Requested size of download_payload in the response, for measuring
  // *egress* (Agent -> validator) in the same round trip. 0 means "don't
  // bother," e.g. when a caller only wants one direction this probe.
  uint32 requested_download_bytes = 3;
}

message MeasureBandwidthResponse {
  string probe_id = 1;
  bytes upload_payload_hash = 2;   // SHA256(upload_payload) -- proves full, correct receipt
  bytes download_payload = 3;      // exactly requested_download_bytes of Agent-generated data
  uint32 server_processing_ms = 4; // time from full request received to response ready, excluding queueing
  bytes signature = 5;             // Ed25519 over a domain-separated construction, see §4
}
```

Both directions share one RPC deliberately: a validator that wants only
one direction sets the other side's size to (near) zero, and a single
round trip avoids the clock-skew problems of trying to reconcile two
separately-timed calls.

### 2. What is actually measured, and by whom

The **validator** times the whole RPC round trip on its own clock (dial
already established, so this is pure request-write + response-read
time), and separately reads `server_processing_ms` from the response to
subtract server-side compute/serialization from the network-bound
portion it cares about. Two throughput figures per probe:

- `ingress_mbps ≈ len(upload_payload) * 8 / (upload_write_time_ms) / 1000`
  (approximated from the portion of the round trip attributable to
  sending — see §5's honest caveat about why this is approximate, not
  exact).
- `egress_mbps ≈ len(download_payload) * 8 / (download_read_time_ms) / 1000`.

This is deliberately coarse (one HTTP/2 stream, no multi-connection
saturation, no removal of TCP slow-start effects) — a real ISP-grade
bandwidth test (iperf3-style) is a much larger undertaking than an MVP
validator daemon needs. The goal is "plausibly close to the declared
figure, done independently, better than trusting the operator outright,"
not a laboratory-grade measurement.

### 3. Payload size and rate limiting

`upload_payload`/`requested_download_bytes` are both bounded by a new
constant, `MAX_BANDWIDTH_PROBE_BYTES` (agent-api), distinct from and
larger than `MAX_CHALLENGE_PAYLOAD` — large enough to produce a
meaningful timing signal over a local/typical WAN link (an 8 MiB probe
takes ~7ms at 10 Gbps, ~640ms at 100 Mbps — enough resolution to
distinguish realistic tiers without either flooding a slow link for
unreasonably long or being too short to time meaningfully on a fast one),
small enough to bound the Agent's per-request memory/CPU cost the same
way every other Agent RPC already is bounded. `agent-api` rate-limits
this RPC per caller (reuses the existing allowlist-authenticated-caller
identity from ADR-013 §3 -- a validator is already an authenticated
caller by the time it can call any Agent RPC) to prevent a validator
(malicious or buggy) from using repeated large probes as a bandwidth-
exhaustion vector against a provider it does not like.

### 4. Signing and evidence

`signature` covers a domain-separated construction analogous to
`solve_challenge`'s: `BANDWIDTH_PROBE_DOMAIN ++ probe_id ++
upload_payload_hash ++ download_payload ++ be_u32(server_processing_ms)`
(exact byte layout is the implementing PR's responsibility to pin down
and document precisely, matching this ADR's intent, not necessarily this
exact byte order). The validator verifies this the same way it already
verifies `SolveChallenge` responses (Ed25519, using the Agent's public
key from the existing agent-endpoint discovery response), so a
fabricated/tampered measurement is still caught by the same signature-
verification discipline `Challenge()` already applies.

### 5. Scoring: same binary philosophy, against the declared figure

`Network` dimension evidence for a round becomes: run one
`MeasureBandwidth` probe, compute `ingress_mbps`/`egress_mbps`, compare
each against the provider's own declared `ResourceCapability.Bandwidth`
(read from the same live directory data the scheduler already uses) with
a tolerance factor (a new constant, e.g. 70%: measured must reach at
least 70% of declared in *both* directions to pass) — matching the
existing binary pass/fail convention (`score_bps = 10_000` or `0`,
`sample_count = 1`) every other dimension in the challenge loop already
uses, not a new latency-graded scheme. `payload_hash` for the evidence
submission is `SHA256(upload_payload_hash ++ download_payload)`, a
bounded, addressable summary of what was actually measured.

**Honest caveat, stated plainly rather than hidden:** a single-stream,
single-probe-per-round measurement over gRPC/HTTP2 is a real but
approximate signal, not a certified benchmark. It is still strictly more
than #30's first slice had (zero independent verification at all), and
is explicitly scoped as "good enough to catch a materially false
declaration," not "precise enough to bill by."

## Consequences

- A new Agent RPC (`MeasureBandwidth`) is new attack surface: needs its
  own payload-size bound, its own rate limit, and its own tests
  (oversized payload rejected, malformed `probe_id` rejected, signature
  verifies against the Agent's real key, an unauthenticated/non-
  allowlisted caller is rejected the same way any other Agent RPC already
  is via ADR-013 §3's mTLS trust model).
- The challenge loop's `Network` dimension evidence changes from a
  liveness/correctness check to a real throughput measurement --
  behavior change to already-shipped code (#85), done deliberately and
  documented here, not silently.
- Still explicitly out of scope, tracked in #73: WireGuard overhead
  accounting (a lease-gated overlay adds its own throughput ceiling this
  ADR's raw Agent-to-validator measurement doesn't see), regional
  endpoint selection, workload-level rate limit *enforcement* (this ADR
  only measures capacity, it does not throttle a running workload's
  actual usage against its reservation), and the adversarial test suite
  (congestion, asymmetric links, spoofed results, partitions) -- each is
  its own substantial piece, not a quick follow-up to this measurement
  protocol.
