# ADR-015: Slashing and economic penalties

## Status

Accepted.

## Context

ADR-011 shipped Network Validator rewards and deliberately stopped short of
penalties: "slashing stake for provably bad submissions is the intended
long-term deterrent but its economic parameters need their own analysis —
**out of scope for this ADR**, tracked as follow-up work" (ADR-011 §5). ADR-012
§6 records that follow-up as this ADR, and names it as the gate for issue #52.

Today the network has exactly two penalties, and neither is economic:

- **Earning nothing.** `close_round` credits `PointsPerAcceptedSubmission` only
  to submitters that survive trimming
  (`blockchain/pallets/network-validator/src/lib.rs:639`, accruing through
  `pallet_rewards::accrue_points` at `blockchain/pallets/rewards/src/lib.rs:182`).
  A validator that submits garbage loses its share of ten points per round and
  nothing else.
- **Suspension.** `suspend` / `reinstate`
  (`blockchain/pallets/network-validator/src/lib.rs:529,549`) flip a validator
  out of the active set. They are gated on `SuspensionOrigin`, which the runtime
  binds to `EnsureRoot` (`blockchain/runtime/src/lib.rs:316`) — one sudo key.

Investigating #52 surfaced a prerequisite that its one-line description hides.
**Providers bond nothing.** `pallet-network-validator` takes a real bond —
`ReservableCurrency` (`lib.rs:161`), `MinStake` (`lib.rs:173`, bound to
`MinValidatorStake = 1_000` at `blockchain/runtime/src/lib.rs:106,317`), reserved
on registration (`lib.rs:449`) and released only after `UnbondingPeriod`
(`lib.rs:503`). `pallet-provider-registry` has no `Currency` association at all,
and `pallet-lease` holds no collateral. Issue #52 asks for "financial penalties
for providers that do not honor their availability commitments"; there is
currently nothing to take. Provider bonding is not an implementation detail of
#52 — it is a precondition, and it is the larger half of the work.

Slashing is also the first mechanism in this repository that can destroy value
belonging to a participant on the strength of other participants' testimony.
That makes its failure mode qualitatively worse than anything shipped so far: a
wrong reputation number recovers on the next round, a wrong slash does not.

## Decision

### 1. Two subjects, one mechanism

"Slashing" covers two different accusations that share machinery but not
evidence:

| | Validator slashing | Provider slashing (#52) |
|---|---|---|
| Bonded today | Yes (`MinStake`) | **No — must be added, §2** |
| Accusation | Submitted evidence that is provably false or self-contradictory | Failed a committed availability level |
| Evidence | On-chain, from the validator's own signed submissions | Aggregated closed rounds, per ADR-011 §5 |
| Deferred by | ADR-011 §5 | Never specified |

They are specified together because they must share the ordering rules of §5 and
the appeal path of §6; a network that can slash one party under weaker rules than
the other has simply moved the attack.

### 2. Provider bonding (prerequisite for #52)

Extend `pallet-provider-registry` with a bond, mirroring the shape already proven
in `pallet-network-validator` rather than inventing a second one:
`ReservableCurrency`, a reserve on registration, an `Exiting { available_at }`
status, and a `withdraw_unbonded` release path.

- The bond is **required to hold leases**, not to appear in the registry. A
  provider may register and be discoverable with no bond; it may not be scheduled
  a workload. This keeps discovery permissionless while keeping obligations
  collateralized.
- The bond scales with committed capacity, not a flat minimum. A flat bond makes
  a large provider's downside negligible relative to its revenue while pricing a
  small provider out — the parameter must be a function of what the provider has
  promised, floored at a minimum.
- Reducing committed capacity below what an active lease requires is refused, not
  silently accepted; a provider cannot shrink its bond out from under its
  obligations.

### 3. What is slashable evidence

**Never a single party's word.** Concretely:

- A slash may only cite a round that is `Final` — closed by `close_round` with at
  least `MinQuorum` submissions — and whose `DisputeWindow` has fully elapsed with
  no upheld dispute.
- A single bad round never slashes. Slashing triggers on a governed number of
  **consecutive** qualifying rounds below a governed threshold. One round is
  noise; a sustained pattern is a breach.
- Degraded quorum produces low confidence, never a penalty. A round that closed at
  the quorum floor is weaker evidence than a full committee and must not be
  counted toward a slash; this is the same honesty rule that #29 applies to the
  dashboard.

For validators specifically:

- **Being trimmed as an outlier is not evidence of dishonesty.** The trimmed mean
  in `close_round` discards the highest and lowest submission by construction, so
  an honest validator observing a genuine edge case is trimmed exactly like a liar.
  Persistent outlier status may inform selection or rewards; it must never, on its
  own, slash.
- What is slashable: **equivocation** — two conflicting signed submissions for the
  same `(provider, round, dimension)` — and evidence provably contradicted by the
  `payload_hash` it committed to. Both are self-incriminating and need no
  third-party judgement.

### 4. Parameters

These are the economic parameters ADR-011 §5 said needed their own analysis. All
are governed values, not constants compiled into a pallet.

| Parameter | Meaning | Constraint |
|---|---|---|
| `SlashFractionBps` | Fraction of the bond destroyed per qualifying breach | Basis points, integer; small enough that one wrong slash is survivable, large enough to exceed the profit from the breach |
| `BreachRounds` | Consecutive qualifying rounds before a slash arms | Greater than one, by §3 |
| `SlashCooldown` | Minimum interval between slashes citing overlapping rounds | Prevents the same breach being slashed repeatedly |
| `AppealWindow` | Bounded window to contest an armed slash | §6; at least `DisputeWindow` |

**Where slashed funds go.** Burned, or sent to a treasury — **never to the
accuser, and never to the counterparty of the slashed party.** Paying a slash out
to whoever reported it manufactures an incentive to fabricate breaches, and
paying it to the tenant makes every tenant a beneficiary of its provider's
failure. Compensation for a failed lease is a settlement question (#19, #21), not
a slashing question, and mixing them corrupts both. The MVP burns.

**Accrued rewards are not clawed back.** `pallet-rewards` already documents this
for upheld disputes, and this ADR keeps it: points already credited stay
credited, and the penalty acts on the bond. Clawback across an unbounded history
is unbounded work in the runtime and is refused on those grounds.

### 5. Ordering against disputes, exit, and finality

- A slash **cannot be finalized while the round justifying it is `Disputed`**.
  `dispute_round` and `resolve_dispute`
  (`blockchain/pallets/network-validator/src/lib.rs:709,755`) already suspend and
  resolve a round's reputation effect; a pending slash follows the same state.
- An upheld dispute **reverses** any slash armed on that round, releasing the
  reserved amount. A rejected dispute lets it proceed.
- **Exit must not outrun a slash.** Stake in `Exiting { available_at }` remains
  slashable until released by `withdraw_unbonded`. The invariant is
  `UnbondingPeriod >= DisputeWindow + AppealWindow + BreachRounds × round length`;
  today `ValidatorUnbondingPeriod = 14_400` against `ValidatorDisputeWindow = 300`
  (`blockchain/runtime/src/lib.rs:107,115`), which leaves ample margin, but the
  invariant must be asserted in the runtime rather than left to whoever next tunes
  a parameter.
- Nothing is slashed on unfinalized state. A reorganization that removes the
  qualifying round removes the slash with it.

### 6. Appeals

An armed slash is contestable within `AppealWindow` by the accused party, through
a bounded on-chain call, resolved by a governance origin.

Today that origin would be `EnsureRoot` (`blockchain/runtime/src/lib.rs:316`) —
a single sudo key deciding whether to destroy a participant's stake. That is not
an acceptable terminal authority for an irreversible economic penalty, and it is
precisely the centralization the roadmap exists to remove.

**Therefore: slashing does not go live before ADR-020** (decentralized identity
and governance, gating #36). The mechanism specified here may be implemented,
tested, and merged behind a disabled parameter; enabling it in a live network
requires the governance work first. ADR-012 §5 places #36 in the same stage as
#52, so this ordering costs no schedule.

### 7. Arithmetic and safety

Standard runtime rules from `AGENTS.md` apply and are restated because this
pallet destroys balances: no floats, checked or saturating arithmetic throughout,
a slash that can never exceed the reserved bond, never underflow it, and never
leave an inconsistent `Exiting` position. Every extrinsic carries an explicit
origin check. Weights are benchmarked, not stubbed — a slash path with a stub
weight is a denial-of-service vector.

### 8. False positives

The scenario this ADR most needs to survive is an honest provider that looks
unavailable because the observers are partitioned.

- A partitioned committee cannot reach `MinQuorum`, the round does not qualify
  under §3, and no slash arms.
- A colluding minority below quorum cannot close a round at all, which is the
  property ADR-011 §4 already relies on.
- A colluding majority of a committee **can** slash an honest provider. This ADR
  does not solve that; ADR-011 §4 flags operator-level collusion as an accepted
  gap, and ADR-012 §2 repeats it. `BreachRounds` raises the cost — the colluders
  must win the committee draw repeatedly — and the appeal path of §6 is the
  backstop. Attestation (#61) is the real fix, and it is deliberately later.

### 9. Out of scope

Token economics and monetary policy; insurance or compensation markets for
slashed leases; reputation-weighted stake; and the concrete numeric values of §4,
which are governed parameters to be set at deployment, not architecture.

## Consequences

- **#52 is substantially larger than its description.** It cannot be implemented
  as written, because providers hold no bond to slash. The bonding work of §2
  lands in `pallet-provider-registry` — a pallet #52 does not mention — and
  changes the meaning of provider registration for every existing caller,
  including the Control Plane's `register_provider_for` path (ADR-009).
- **#52 is now dependent on #36.** Section 6 forbids going live while `EnsureRoot`
  is the appeal authority. This is a real schedule coupling and should be
  reflected in issue ordering.
- The network gains its first irreversible operation. Every other mechanism to
  date is corrigible on the next round; a finalized slash is not. This justifies
  the conservative posture throughout: consecutive-round thresholds rather than
  single-round triggers, burning rather than paying accusers, and no clawback.
- Being an outlier stays unpunished (§3). Honest validators reporting genuine
  edge cases will keep being trimmed, and the network keeps paying that cost in
  exchange for not punishing honest disagreement.
- A colluding committee majority can still slash an honest provider (§8). This
  ADR bounds and prices that attack; it does not eliminate it, and no
  implementation should claim otherwise.
