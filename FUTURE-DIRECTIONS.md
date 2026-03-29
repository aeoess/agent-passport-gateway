# FUTURE DIRECTIONS: Advanced Persistence & Distributed Governance

**Status:** Research notes from 8-model consilium (March 26, 2026)
**Classification:** PRIVATE — product roadmap, not open protocol

These primitives become relevant when APS moves from single-gateway to multi-gateway,
multi-principal, enterprise-grade governance. Each is backed by published research.

---

## Verifiable Data Structures

**Merkle Patricia Tries (MPT)** — Ethereum Yellow Paper (Wood, 2014), Authenticated
Data Structures (Tamassia, 2003). Single hash commits to entire gateway state. Any
individual piece of state provable with O(log n) inclusion proof. Enables: efficient
state proofs, non-existence proofs, state diffs between snapshots. Relevant when
auditors need to verify specific delegations without downloading the full database.

**Merkle Mountain Ranges (MMR)** — Used in Mimblewimble (Grin/Beam). Strictly
append-only. O(1) append, O(log n) inclusion proof. Better than simple hash chains
for receipt ledgers at scale. Relevant when receipt count exceeds ~100K and startup
verification becomes a bottleneck.

**Skip List Receipts** — Each receipt hashes not just the previous, but also N-2, N-4,
N-8 etc. Gives O(log n) verification of any sub-range vs O(n) for linear chain.
Same principle as Git commit graph. Cheaper to implement than full MMR.

---

## Distributed State Coordination

**Vector Clocks** — Lamport 1978, Fidge 1988. Each gateway maintains (gatewayId,
sequence) pairs. On state exchange, vector tells exactly which events each gateway
has seen. Gives causal ordering without global consensus. Foundation of DynamoDB,
Riak. Maps to: revocation propagation ordering, checkpoint exchange, partial sync.

**CRDTs for Spend** — Shapiro et al. 2011. PN-Counter (positive-negative counter)
tracks cumulative spend across independent gateways without coordination. Each
gateway increments its own counter. Total = sum of all counters. Guarantees Strong
Eventual Consistency. Same model as credit cards: authorize locally, reconcile
globally, dispute later. Does NOT prevent real-time overspend — only makes it
mergeable after the fact.

**OR-Set for Revocations** — Observed-Remove Set CRDT. Naturally monotonic (once
revoked, never unrevoked). Good candidate for semilattice/monotone merge model.
Design revocation objects now with unique IDs and causal metadata so they fit
this world later.

---

## Cryptographic Primitives

**Cryptographic Accumulators** — Camenisch & Lysyanskaya 2002. Single short value
"accumulates" all non-revoked delegations. O(1) verification with witness proof.
O(1) state size regardless of revocation count. Relevant at >10M revocations
where even indexed SQL becomes a bottleneck.

**Bloom Filters for Revocation** — O(1) probabilistic check with zero false
negatives. 120KB for 100K revocations at 1% false positive rate. How OCSP
stapling works in TLS. Relevant when revocation list is huge and disk I/O matters.

**Pedersen Commitments + ZKP** — Pedersen 1991. Commit to spend amount without
revealing it. Gateway logs commitment, plaintext held only by agent/principal.
GDPR deletion = delete plaintext, commitment stays. Dispute = principal produces
ZK proof that hidden value satisfies condition ("spend < $200") without revealing
actual value. Solves GDPR vs non-repudiation paradox.

**Homomorphic Spend Tracking** — Cross-gateway spend verification without revealing
individual transaction amounts. Each gateway proves "my total is under X" without
sharing line items.

---

## Trust Architecture

**Notary Pattern / Witnessed Receipts** — Separate receipt signer from action
executor. Gateway executes, independent witness attests. Receipt carries both
executorSignature and witnessSignature. Eliminates the trust assumption that the
entity with the most power (gateway) also controls the audit trail. Can be
implemented with TEE enclaves (Intel SGX, AWS Nitro) for mathematical isolation.

**State Channels for Spend** — Lightning Network pattern. Lock delegation params
into cryptographic channel at session start. Exchange off-chain micro-receipts
in memory (millisecond latency, no DB writes). Settle only final net state to
the ledger. Reduces DB I/O by orders of magnitude. Eliminates async race
conditions entirely.

**Certificate Transparency Model** — Append-only Merkle tree with consistency
proofs between snapshots. External monitors can detect equivocation (gateway
showing different histories to different parties). Stronger than signed snapshots
alone. The checkpoint chain should evolve toward this model.

**Audit Games / Mechanism Design** — Blocki et al. 2013. Design incentives so
expected cost of cheating exceeds expected benefit. Principals randomly audit
receipt chains. Detected omission = penalty P. Optimal strategy for rational
gateway operator = honesty when P × detection_probability > cheating_benefit.

---

## Decision Theory & Routing

**Thompson Sampling** — Thompson 1933, proven optimal by Agrawal & Goyal 2012.
For task routing (Module 16): when multiple agents can handle a task, sample
from each agent's Beta/Gaussian reputation distribution. Naturally balances
exploration (high-sigma agents sampled occasionally) with exploitation (high-mu
agents sampled often). Directly applicable to delegation-aware task assignment.

---

## Information Flow Control

**Security Lattices (LBAC)** — Denning 1976. Attach mathematical security labels
to data payloads. Labels form a bounded lattice. Cross-agent data flow computes
Least Upper Bound. Prevents authority laundering (Agent A reads financial data,
passes to Agent B who sends email) mathematically rather than heuristically.
Gateway enforces: execution scope must dominate payload LUB.

---

## Event Sourcing & CQRS

**Full Event Sourcing** — Receipts, revocations, demotions, key rotations as
immutable events. Spend, reputation, delegation status as derived projections.
Replay events to reconstruct any historical state. Different consumers (audit,
analytics, compliance) maintain own projections. Not required for v1 but the
schema should separate event tables from state tables to enable this later.

---

## Implementation Priority (when scale demands it)

| Priority | Primitive | Trigger |
|----------|-----------|---------|
| 1 | Witnessed receipts (notary) | First enterprise customer |
| 2 | CT-style checkpoint chain | Multi-gateway deployment |
| 3 | Vector clocks + OR-Set | Cross-gateway revocation |
| 4 | CRDT spend counters | Multi-gateway spend |
| 5 | Merkle state roots | Auditor-facing product |
| 6 | Cryptographic accumulators | >1M revocations |
| 7 | Pedersen commitments | GDPR-sensitive deployments |
| 8 | Thompson Sampling routing | Task marketplace feature |
| 9 | Security lattice IFC | Multi-agent pipeline product |
| 10 | State channels | High-frequency agent commerce |
