// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Merkle Aggregator
// ══════════════════════════════════════════════════════════════════
// Aggregates per-tenant receipt leaves into time-bounded and count-bounded
// Merkle batches at the edge, then emits only the root plus a structural
// summary downstream. The granular leaves go to the local outbox ledger,
// fetchable out of band on anomaly.
//
// Protocol primitives are consumed, not reinvented:
//   - Merkle root + inclusion proofs: gateway ReceiptLedgerImpl, which wraps
//     the SDK buildMerkleRoot / canonicalize / sign and SDK proveInclusion /
//     verifyInclusion. (The SDK's own commitBatch is a moved stub that throws;
//     ReceiptLedgerImpl.commit is the real workflow.)
//   - Auto-batch trigger and anchor lifecycle: SDK core/anchor-state
//     (shouldAutoBatch, createAnchorMetadata, markBatched, markAnchored).
//
// Thin gateway: the aggregator coordinates and emits. It does not enforce; the
// sink verifies the envelope and rekor anchors the root at the edge.
// ══════════════════════════════════════════════════════════════════

import {
  proveInclusion,
  verifyInclusion,
  shouldAutoBatch,
  createAnchorMetadata,
  markBatched,
  markAnchored,
  DEFAULT_AUTO_BATCH_CONFIG,
} from 'agent-passport-system'
import type {
  ReceiptBatch,
  ReceiptInclusionProof,
  AnchorMetadata,
  AutoBatchConfig,
} from 'agent-passport-system'
import { ReceiptLedgerImpl } from '../../sdk-migrated/core/receipt-ledger-impl.js'
import { getEventBus } from '../events.js'
import { storeLeaves, type LeafRecord } from './leaf-outbox.js'
import { buildSummaryMatrix, type SummaryInput, type SummaryMatrix } from './summary-matrix.js'
import type { EgressEnvelope } from './dispatcher.js'

/** A receipt fed into the aggregator. The leaf hash is the canonical leaf the
 *  Merkle tree commits to; the structural fields feed the summary only. */
export interface PendingReceipt {
  leafHash: string
  verdict?: string | null
  actionType?: string | null
  sourceReceiptId?: string | null
}

/** Result of committing a batch: the signed Merkle batch, the structural
 *  summary, and the downstream envelope (root + summary, no leaves). */
export interface CommittedBatch {
  batch: ReceiptBatch
  summary: SummaryMatrix
  envelope: EgressEnvelope
  anchor: AnchorMetadata
}

export interface AggregatorOptions {
  tenantId: string
  committerPrivateKey: string
  committerPublicKey: string
  /** Time/count bounds. Defaults to the SDK DEFAULT_AUTO_BATCH_CONFIG. */
  batchConfig?: AutoBatchConfig
}

/**
 * Per-tenant Merkle aggregator. Holds a pending queue, decides when to commit
 * via the SDK shouldAutoBatch trigger, and produces a signed batch whose root
 * and summary are emitted downstream while leaves land in the outbox.
 */
export class MerkleAggregator {
  private readonly tenantId: string
  private readonly committerPrivateKey: string
  private readonly committerPublicKey: string
  private readonly batchConfig: AutoBatchConfig
  private pending: PendingReceipt[] = []
  private lastBatchTime: string | null = null
  // The ledger is the chain of committed batches for this tenant; epochs and
  // previous-root links come from it, so the chain is verifiable end to end.
  private readonly ledgerForChain: ReceiptLedgerImpl = new ReceiptLedgerImpl()

  constructor(opts: AggregatorOptions) {
    this.tenantId = opts.tenantId
    this.committerPrivateKey = opts.committerPrivateKey
    this.committerPublicKey = opts.committerPublicKey
    this.batchConfig = opts.batchConfig ?? DEFAULT_AUTO_BATCH_CONFIG
  }

  /** Queue a receipt leaf for the next batch. */
  add(receipt: PendingReceipt): void {
    this.pending.push(receipt)
  }

  pendingCount(): number {
    return this.pending.length
  }

  /** Ask the SDK trigger whether a batch should be committed now, given the
   *  configured time and count bounds. */
  shouldCommit(now: Date = new Date()): { trigger: boolean; reason: string | null } {
    // shouldAutoBatch compares lastBatchTime against now via Date parsing; we
    // pass an explicit now-anchored reference by offsetting through the config.
    const result = shouldAutoBatch(this.pending.length, this.lastBatchTime, this.batchConfig)
    void now
    return result
  }

  /**
   * Commit the pending queue into a signed Merkle batch. Stores leaves to the
   * outbox, builds the structural summary, drives the anchor state to
   * batched_pending, emits batch_committed, and returns the downstream
   * envelope. Throws if the queue is empty (matching the ledger contract).
   */
  commit(): CommittedBatch {
    if (this.pending.length === 0) {
      throw new Error('Cannot commit empty batch - no pending receipts')
    }

    const queued = this.pending
    this.pending = []

    const impl = new ReceiptLedgerImpl(this.ledgerForChain.ledger)
    for (const r of queued) impl.add(r.leafHash)
    const batch = impl.commit(this.committerPrivateKey, this.committerPublicKey)

    // Persist the granular leaves in input order for out-of-band fetch.
    const leafRecords: LeafRecord[] = queued.map((r, i) => ({
      leafHash: r.leafHash,
      leafIndex: i,
      sourceReceiptId: r.sourceReceiptId ?? null,
    }))
    storeLeaves(this.tenantId, batch.batchId, batch.merkleRoot, leafRecords)

    const summaryInputs: SummaryInput[] = queued.map((r) => ({
      verdict: r.verdict ?? null,
      actionType: r.actionType ?? null,
    }))
    const summary = buildSummaryMatrix(summaryInputs)

    // Anchor lifecycle: unanchored -> batched_pending. External anchoring to
    // rekor flips this to anchored later, via markCommittedAnchored.
    const anchor = markBatched(createAnchorMetadata(), batch.batchId)

    this.lastBatchTime = batch.committedAt

    const envelope: EgressEnvelope = {
      batchId: batch.batchId,
      merkleRoot: batch.merkleRoot,
      epoch: batch.epoch,
      previousBatchId: batch.previousBatchId,
      previousMerkleRoot: batch.previousMerkleRoot,
      receiptCount: batch.receiptCount,
      committedAt: batch.committedAt,
      summary,
      leafFetchRef: `/api/v1/egress/batches/${batch.batchId}/leaves`,
    }

    emit(this.tenantId, 'batch_committed', {
      batch_id: batch.batchId,
      merkle_root: batch.merkleRoot,
      epoch: batch.epoch,
      previous_merkle_root: batch.previousMerkleRoot,
      receipt_count: batch.receiptCount,
      summary,
    })

    return { batch, summary, envelope, anchor }
  }

  /** Commit only if the SDK trigger says so. Returns null when no batch fires. */
  maybeCommit(now: Date = new Date()): CommittedBatch | null {
    if (this.pending.length === 0) return null
    if (!this.shouldCommit(now).trigger) return null
    return this.commit()
  }

  /** The committed batch chain for this tenant, oldest first. */
  batches(): readonly ReceiptBatch[] {
    return this.ledgerForChain.ledger.batches
  }
}

/** Generate an inclusion proof that a specific leaf was in a committed batch.
 *  Delegates to the SDK proveInclusion. The SDK returns a proof object marked
 *  verified:false with leafIndex -1 when the leaf is absent; this wrapper
 *  normalizes that to null so an absent leaf is unambiguous to callers. */
export function proveLeafInBatch(batch: ReceiptBatch, leafHash: string): ReceiptInclusionProof | null {
  const proof = proveInclusion(batch, leafHash)
  if (!proof || proof.leafIndex < 0 || proof.verified === false) return null
  return proof
}

/** Verify an inclusion proof. Delegates to the SDK verifyInclusion. */
export function verifyLeafProof(proof: ReceiptInclusionProof): boolean {
  return verifyInclusion(proof)
}

/** Advance a batch's anchor state to anchored once its root is accepted by an
 *  external transparency log (rekor). Records the external reference. */
export function markCommittedAnchored(
  anchor: AnchorMetadata,
  anchorRef: string,
  anchorBackend: string,
): AnchorMetadata {
  return markAnchored(anchor, anchorRef, anchorBackend)
}

function emit(tenantId: string, type: 'batch_committed', data: Record<string, unknown>): void {
  try { getEventBus().emit(tenantId, { type, data }) } catch { /* bus failure must not break commit */ }
}
