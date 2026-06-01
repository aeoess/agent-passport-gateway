// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Event-spine integration seam for modes + simulation
// ══════════════════════════════════════════════════════════════════
// G-D1 produces two kinds of auditable facts that belong on the historical
// event spine: (1) a mode observation (a would-have-been-denied or a real
// block under a given mode), and (2) a completed policy simulation run. Both
// should become leaves in the G-A1 Merkle aggregation egress so they are
// anchored alongside the rest of the gateway's decision history.
//
// G-A1 (gw-a1-event-merkle) is NOT merged into this base commit. Its public
// egress surface lives at gw-a1-event-merkle/src/gateway/egress/index.ts and
// exposes storeLeaves / MerkleAggregator / egressCommittedBatch. We integrate
// against that PUBLIC surface only, and stub it behind a typed seam until the
// merge lands. We never reach into G-A1 internals.
//
// Until the merge, the seam degrades to the existing local event bus, so mode
// and simulation facts are still observable in this build (via SSE) without
// the Merkle anchoring path.
// ══════════════════════════════════════════════════════════════════

import { getEventBus } from '../events.js'

// ── G-A1 seam ──────────────────────────────────────────────────────
// TODO(G-A1 / gw-a1-event-merkle): once G-A1 is merged into main, replace the
// local-bus fallback below with a real append to the Merkle leaf outbox. The
// public entry points to wire are, from src/gateway/egress/index.ts:
//   - storeLeaves(tenantId, batchId, leaves)   // append D1 facts as leaves
//   - new MerkleAggregator(...).add(receipt)    // include in the next batch
//   - egressCommittedBatch(tenantId, committed, sink)  // anchor + dispatch
// Leaf shape should be the public-safe projection (merkle_root / period /
// timestamp / receipt_hash / schema_version) per projectPublicBatch; counts and
// scope detail must NOT cross the egress boundary. Integration point:
// emitToEventSpine() is the single call site, so only this function changes.
//
// Typed seam interface mirrors the slice of G-A1's egress we depend on. When
// the real module is present, this interface is satisfied by its exports.
interface EventSpineLeafSink {
  storeLeaves(tenantId: string, batchId: string, leaves: Array<{ leafHash: string; payload: Record<string, unknown> }>): void
}

// Holder for the injected G-A1 sink. Stays null until the merge wires it in.
let _leafSink: EventSpineLeafSink | null = null

/**
 * Injection point for the G-A1 leaf sink. Called once during server boot AFTER
 * the G-A1 merge, passing the egress module's storeLeaves-backed sink. Until
 * then it is never called and emitToEventSpine falls back to the local bus.
 */
export function registerEventSpineSink(sink: EventSpineLeafSink): void {
  _leafSink = sink
}

export type SpineFactType = 'mode_observation' | 'policy_simulation'

/**
 * Emit a G-D1 fact to the event spine. Best-effort and non-blocking: a spine
 * failure must never break enforcement or a simulation response.
 *
 * Behaviour:
 *   - If the G-A1 sink is registered (post-merge), append as a Merkle leaf.
 *   - Otherwise, fall back to the local event bus so the fact is still
 *     observable over SSE in this base build.
 */
export function emitToEventSpine(
  tenantId: string,
  factType: SpineFactType,
  data: Record<string, unknown>,
): void {
  // Local-bus path (always runs so SSE consumers see the fact today).
  try {
    getEventBus().emit(tenantId, { type: 'evaluation', data: { spine_fact: factType, ...data } })
  } catch { /* bus failure must not break the caller */ }

  // G-A1 leaf path (only once the merge has registered a sink).
  if (_leafSink) {
    try {
      // TODO(G-A1 / gw-a1-event-merkle): compute the real leaf hash via the
      // gateway receipt-hash helper and project to the public-safe body before
      // handing to storeLeaves. Placeholder batchId groups by fact type + day.
      const batchId = `d1-${factType}-${new Date().toISOString().slice(0, 10)}`
      _leafSink.storeLeaves(tenantId, batchId, [{ leafHash: '', payload: { fact_type: factType, ...data } }])
    } catch (e) {
      console.error('[d1-spine] leaf append failed:', (e as Error).message)
    }
  }
}
