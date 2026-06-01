// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Leaf Outbox Ledger
// ══════════════════════════════════════════════════════════════════
// The cost-at-scale answer. Streaming every receipt into a customer SIEM is
// expensive, so downstream egress carries only the Merkle root plus a
// structural summary. The granular per-receipt leaves stay here in a local
// ledger and are fetched out of band only when an anomaly is flagged on a
// batch. A leaf plus its inclusion proof shows a specific receipt was in the
// aggregated batch the gateway emitted.
//
// This is a store of record for leaves, not a second event bus. It is keyed
// by batchId (the Merkle batch) and per tenant.
// ══════════════════════════════════════════════════════════════════

import { getDB } from '../../db/schema.js'

export interface LeafRecord {
  /** Leaf digest exactly as it was fed into the Merkle tree, e.g. sha256:... */
  leafHash: string
  /** Position of the leaf in the batch's input ordering (pre-sort). */
  leafIndex: number
  /** Optional opaque source receipt id for out-of-band correlation. */
  sourceReceiptId?: string | null
}

/** Create the outbox table. Idempotent. Uses the gateway's existing
 *  CREATE TABLE IF NOT EXISTS idiom so it composes with schema bootstrap. */
export function initLeafOutbox(): void {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS gem_leaf_outbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      batch_id TEXT NOT NULL,
      merkle_root TEXT NOT NULL,
      leaf_hash TEXT NOT NULL,
      leaf_index INTEGER NOT NULL,
      source_receipt_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `)
  db.exec(`CREATE INDEX IF NOT EXISTS idx_gem_leaf_outbox_batch ON gem_leaf_outbox(tenant_id, batch_id)`)
}

/** Persist the granular leaves of a committed batch. Idempotent per
 *  (tenant, batch): re-storing the same batch is a no-op so a retried commit
 *  does not duplicate leaves. */
export function storeLeaves(
  tenantId: string,
  batchId: string,
  merkleRoot: string,
  leaves: readonly LeafRecord[],
): number {
  const db = getDB()
  const existing = db.prepare(
    'SELECT COUNT(*) AS c FROM gem_leaf_outbox WHERE tenant_id = ? AND batch_id = ?',
  ).get(tenantId, batchId) as { c: number }
  if (existing.c > 0) return 0

  const insert = db.prepare(
    `INSERT INTO gem_leaf_outbox (tenant_id, batch_id, merkle_root, leaf_hash, leaf_index, source_receipt_id)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
  const txn = db.transaction((rows: readonly LeafRecord[]) => {
    for (const r of rows) {
      insert.run(tenantId, batchId, merkleRoot, r.leafHash, r.leafIndex, r.sourceReceiptId ?? null)
    }
  })
  txn(leaves)
  return leaves.length
}

/** Out-of-band leaf fetch. Returns the exact leaves stored for a batch, in
 *  their original input order. Scoped to the tenant so one tenant cannot read
 *  another's leaves. Returns an empty array for an unknown batch. */
export function fetchLeaves(tenantId: string, batchId: string): LeafRecord[] {
  const db = getDB()
  const rows = db.prepare(
    `SELECT leaf_hash AS leafHash, leaf_index AS leafIndex, source_receipt_id AS sourceReceiptId
     FROM gem_leaf_outbox
     WHERE tenant_id = ? AND batch_id = ?
     ORDER BY leaf_index ASC`,
  ).all(tenantId, batchId) as LeafRecord[]
  return rows
}

/** Return just the leaf hashes for a batch in input order. Handy for
 *  recomputing the root or building an inclusion proof out of band. */
export function fetchLeafHashes(tenantId: string, batchId: string): string[] {
  return fetchLeaves(tenantId, batchId).map((r) => r.leafHash)
}

/** Count leaves held for a batch. */
export function leafCount(tenantId: string, batchId: string): number {
  const db = getDB()
  const row = db.prepare(
    'SELECT COUNT(*) AS c FROM gem_leaf_outbox WHERE tenant_id = ? AND batch_id = ?',
  ).get(tenantId, batchId) as { c: number }
  return row.c
}
