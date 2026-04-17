// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// ReceiptLedgerImpl — stateful batch commit workflow
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). The SDK retains pure
// primitives (createReceiptLedger, addReceipt, proveInclusion,
// verifyInclusion, verifyBatch, verifyBatchChain) plus the ReceiptBatch
// type. The commit workflow that signs a batch from the pending queue,
// chains epochs, and mutates ledger state lives here.
// ══════════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import {
  canonicalize, sign,
  createReceiptLedger, addReceipt,
  verifyBatch, verifyBatchChain,
  proveInclusion, verifyInclusion,
  buildMerkleRoot,
} from 'agent-passport-system'
import type { ReceiptBatch, ReceiptLedger } from 'agent-passport-system'

export interface CommitBatchOptions {
  ledger: ReceiptLedger
  committerPrivateKey: string
  committerPublicKey: string
}

/**
 * Commit pending receipts as a Merkle-rooted, signed batch and append it
 * to the ledger. Mutates ledger.batches and clears ledger.pendingReceipts.
 */
export function commitBatch(opts: CommitBatchOptions): ReceiptBatch {
  const { ledger, committerPrivateKey, committerPublicKey } = opts

  if (ledger.pendingReceipts.length === 0) {
    throw new Error('Cannot commit empty batch — no pending receipts')
  }

  const now = new Date().toISOString()
  const batchId = 'batch_' + uuidv4().slice(0, 12)
  const receiptHashes = [...ledger.pendingReceipts]
  const merkleRoot = buildMerkleRoot(receiptHashes)

  const lastBatch = ledger.batches.length > 0
    ? ledger.batches[ledger.batches.length - 1]
    : null

  const epoch = lastBatch ? lastBatch.epoch + 1 : 0
  const previousBatchId = lastBatch ? lastBatch.batchId : null
  const previousMerkleRoot = lastBatch ? lastBatch.merkleRoot : null

  const signable = {
    batchId, merkleRoot, receiptCount: receiptHashes.length,
    epoch, previousBatchId, previousMerkleRoot,
    committedAt: now, committedBy: committerPublicKey,
  }

  const canonical = canonicalize(signable)
  const signature = sign(canonical, committerPrivateKey)

  const batch: ReceiptBatch = {
    batchId, merkleRoot, receiptCount: receiptHashes.length,
    receiptHashes, epoch, previousBatchId, previousMerkleRoot,
    committedAt: now, committedBy: committerPublicKey, signature,
  }

  ledger.batches.push(batch)
  ledger.pendingReceipts = []
  return batch
}

/**
 * Stateful object-style wrapper around the SDK ledger primitives.
 * Holds a ReceiptLedger and exposes the commit workflow as a method.
 */
export class ReceiptLedgerImpl {
  readonly ledger: ReceiptLedger

  constructor(initial?: ReceiptLedger) {
    this.ledger = initial ?? createReceiptLedger()
  }

  add(receiptHash: string): void {
    addReceipt(this.ledger, receiptHash)
  }

  commit(committerPrivateKey: string, committerPublicKey: string): ReceiptBatch {
    return commitBatch({ ledger: this.ledger, committerPrivateKey, committerPublicKey })
  }

  prove(batch: ReceiptBatch, receiptHash: string) {
    return proveInclusion(batch, receiptHash)
  }

  verify(batch: ReceiptBatch, previous?: ReceiptBatch | null) {
    return verifyBatch(batch, previous)
  }

  verifyChain() {
    return verifyBatchChain(this.ledger.batches)
  }

  static verifyInclusionProof = verifyInclusion
}
