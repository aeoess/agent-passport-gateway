// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Merkle aggregation egress, public surface
// ══════════════════════════════════════════════════════════════════
// Ties the aggregator, leaf outbox, summary matrix, dispatcher, and rekor
// batch anchoring into one orchestration entry point and the public-safe
// projection of a batch envelope.
//
// Foundation for A3, C1, D1. Internal plumbing.
// ══════════════════════════════════════════════════════════════════

import { getEventBus } from '../events.js'
import { projectPublicBody } from '../receipt-projection.js'
import { anchorMerkleRoot } from '../rekor.js'
import { fetchLeaves, fetchLeafHashes, type LeafRecord } from './leaf-outbox.js'
import { EgressDispatcher, type EgressEnvelope, type EgressSink, type DispatchResult } from './dispatcher.js'
import { MerkleAggregator, markCommittedAnchored, type CommittedBatch } from './aggregator.js'
import type { AnchorMetadata } from 'agent-passport-system'

export {
  MerkleAggregator,
  proveLeafInBatch,
  verifyLeafProof,
  markCommittedAnchored,
} from './aggregator.js'
export type { PendingReceipt, CommittedBatch, AggregatorOptions } from './aggregator.js'
export {
  EgressDispatcher,
  DEFAULT_RETRY_POLICY,
  backoffDelay,
} from './dispatcher.js'
export type { EgressEnvelope, EgressSink, RetryPolicy, DeadLetter, DispatchResult } from './dispatcher.js'
export {
  initLeafOutbox,
  storeLeaves,
  fetchLeaves,
  fetchLeafHashes,
  leafCount,
} from './leaf-outbox.js'
export type { LeafRecord } from './leaf-outbox.js'
export {
  buildSummaryMatrix,
  summaryMatrixConsistent,
} from './summary-matrix.js'
export type { SummaryMatrix, SummaryInput } from './summary-matrix.js'
export {
  computeContributorSettlement,
  contributorSettlementAvailable,
} from './settlement-w2-stub.js'
export type { ContributorLeaf, ContributorSettlementResult } from './settlement-w2-stub.js'

/**
 * Project a committed batch envelope to its public-safe body. Routes through
 * the shared receipt-projection whitelist gate using the existing
 * settlement whitelist, so only merkle_root / period / timestamp /
 * receipt_hash / schema_version cross an unauthenticated surface. Counts and
 * leaf references never leak.
 */
export function projectPublicBatch(envelope: EgressEnvelope): Record<string, unknown> {
  const parsed = {
    schema_version: 'gem_batch_v1',
    merkle_root: envelope.merkleRoot,
    period: `epoch:${envelope.epoch}`,
    timestamp: envelope.committedAt,
    receipt_hash: envelope.merkleRoot,
  }
  const row = { id: envelope.batchId, created_at: envelope.committedAt }
  return projectPublicBody('settlement', row, parsed)
}

/**
 * Anchor a committed batch's root to the transparency log and advance its
 * anchor metadata. Emits anchor_submitted. The root is what gets anchored,
 * not the leaves, so one batch is one transparency entry.
 */
export function anchorCommittedBatch(
  tenantId: string,
  committed: CommittedBatch,
): { anchor: AnchorMetadata; anchorId: string } {
  const result = anchorMerkleRoot(tenantId, committed.batch.batchId, committed.batch.merkleRoot)
  const anchor = markCommittedAnchored(committed.anchor, `rekor:${result.anchorId}`, 'rekor')
  try {
    getEventBus().emit(tenantId, {
      type: 'anchor_submitted',
      data: {
        batch_id: committed.batch.batchId,
        merkle_root: committed.batch.merkleRoot,
        anchor_id: result.anchorId,
        status: result.status,
      },
    })
  } catch { /* bus failure must not break anchoring */ }
  return { anchor, anchorId: result.anchorId }
}

/**
 * Out-of-band leaf fetch for an anomaly investigation. Emits leaf_fetch so
 * the access itself is observable. Returns the exact stored leaves for the
 * batch, scoped to the tenant.
 */
export function fetchBatchLeaves(tenantId: string, batchId: string, reason: string = 'anomaly_flagged'): LeafRecord[] {
  const leaves = fetchLeaves(tenantId, batchId)
  try {
    getEventBus().emit(tenantId, {
      type: 'leaf_fetch',
      data: { batch_id: batchId, leaf_count: leaves.length, reason },
    })
  } catch { /* bus failure must not break the fetch */ }
  return leaves
}

/** Re-expose hashes-only fetch for callers that just need to recompute. */
export { fetchLeafHashes as fetchBatchLeafHashes }

/**
 * One-shot orchestration: anchor the batch root, then dispatch the root +
 * summary envelope downstream with retry / dead-letter. The granular leaves
 * are already in the outbox; only the small envelope travels.
 */
export async function egressCommittedBatch(
  tenantId: string,
  committed: CommittedBatch,
  sink: EgressSink,
  dispatcher: EgressDispatcher = new EgressDispatcher(),
): Promise<{ anchorId: string; dispatch: DispatchResult }> {
  const { anchorId } = anchorCommittedBatch(tenantId, committed)
  const dispatch = await dispatcher.dispatch(tenantId, sink, committed.envelope)
  return { anchorId, dispatch }
}
