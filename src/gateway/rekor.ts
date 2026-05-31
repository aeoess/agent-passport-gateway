// ══════════════════════════════════════════════════════════════════
// Rekor Anchoring - Transparency Log Integration
// ══════════════════════════════════════════════════════════════════
// Submits receipt hashes to Sigstore Rekor for independent temporal proof.
// Source: desiorac on A2A#1672
// ══════════════════════════════════════════════════════════════════

import { Router } from 'express'
import { createHash } from 'node:crypto'
import { getDB } from '../db/schema.js'
import { canonicalize } from 'agent-passport-system'

export const rekorRouter = Router()

const REKOR_API = 'https://rekor.sigstore.dev/api/v1'

interface AnchorRecord {
  receipt_id: string
  receipt_hash: string
  agent_did: string
  rekor_log_index: number | null
  rekor_entry_uuid: string | null
  status: 'pending' | 'anchored' | 'failed'
  error?: string
  anchored_at: string
}

// Init anchor storage table
export function initAnchorTable() {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS rekor_anchors (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      receipt_hash TEXT NOT NULL,
      agent_did TEXT,
      rekor_log_index INTEGER,
      rekor_entry_uuid TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      error TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      anchored_at TEXT
    )
  `)
}

/**
 * POST /api/v1/anchor
 * Submit a receipt to Rekor transparency log.
 * Body: { receipt_id: string }
 */
rekorRouter.post('/anchor', async (req, res) => {
  const { receipt_id } = req.body
  if (!receipt_id) return res.status(400).json({ error: 'Required: receipt_id' })

  const tenantId = (req as any).tenant?.id
  const db = getDB()

  // Find the receipt across tables
  const tables = ['receipts', 'access_receipts', 'derivations', 'settlements']
  let receipt: any = null
  let receiptType = ''

  for (const table of tables) {
    try {
      const row = db.prepare(`SELECT * FROM ${table} WHERE id = ? AND tenant_id = ?`).get(receipt_id, tenantId)
      if (row) { receipt = row; receiptType = table; break }
    } catch { continue }
  }

  if (!receipt) return res.status(404).json({ error: 'Receipt not found' })

  // Compute receipt hash
  const { tenant_id, ...publicFields } = receipt
  const receiptHash = `sha256:${createHash('sha256')
    .update(canonicalize(publicFields))
    .digest('hex')}`

  const anchorId = `anc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`

  // Submit to Rekor
  try {
    const payload = {
      receipt_hash: receiptHash,
      agent_did: receipt.agent_id || 'unknown',
      issuer: 'https://gateway.aeoess.com',
      anchored_at: new Date().toISOString(),
    }

    // Rekor hashedrekord entry
    const rekorBody = {
      apiVersion: '0.0.1',
      kind: 'hashedrekord',
      spec: {
        data: {
          hash: { algorithm: 'sha256', value: receiptHash.replace('sha256:', '') },
        },
        signature: {
          content: Buffer.from(receipt.signature || '').toString('base64'),
          publicKey: { content: '' }, // Gateway public key would go here
        },
      },
    }

    // Store as pending (actual Rekor submission is async)
    // In production, this would call fetch(REKOR_API + '/log/entries', ...)
    // For now, store the anchor record for batch submission
    db.prepare(`
      INSERT INTO rekor_anchors (id, tenant_id, receipt_id, receipt_hash, agent_did, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'pending', datetime('now'))
    `).run(anchorId, tenantId, receipt_id, receiptHash, receipt.agent_id || 'unknown')

    res.status(201).json({
      anchor_id: anchorId,
      receipt_id,
      receipt_type: receiptType,
      receipt_hash: receiptHash,
      status: 'pending',
      message: 'Anchor record created. Will be submitted to Rekor in next batch.',
      payload,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

/**
 * GET /api/v1/anchors
 * List anchor records for this tenant.
 */
rekorRouter.get('/anchors', (req, res) => {
  const tenantId = (req as any).tenant?.id
  const db = getDB()
  const anchors = db.prepare(
    'SELECT * FROM rekor_anchors WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100'
  ).all(tenantId)
  res.json({ anchors, count: anchors.length })
})

// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Merkle batch-root anchoring
// ══════════════════════════════════════════════════════════════════
// The Rekor flow above anchors a single receipt hash. GEM aggregates many
// receipts into one Merkle batch and anchors only the batch root, so the
// transparency log carries one entry per batch instead of one per receipt.
// This reuses the same rekor_anchors table and pending/anchored lifecycle;
// the batch root is stored in the receipt_hash column with a stable
// batch: prefix in receipt_id so the two anchor kinds do not collide.

export interface MerkleRootAnchor {
  anchorId: string
  batchId: string
  merkleRoot: string
  status: 'pending' | 'anchored' | 'failed'
}

/**
 * Anchor a Merkle batch root to the transparency log. Idempotent per
 * (tenant, batch): a repeated call returns the existing anchor record rather
 * than creating a duplicate. Network submission to Rekor stays staged as
 * pending exactly like the per-receipt path; an out-of-band batch submitter
 * promotes pending -> anchored.
 */
export function anchorMerkleRoot(
  tenantId: string,
  batchId: string,
  merkleRoot: string,
  agentDid: string = 'gateway',
): MerkleRootAnchor {
  const db = getDB()
  const receiptId = `batch:${batchId}`
  const receiptHash = merkleRoot.startsWith('sha256:') ? merkleRoot : `sha256:${merkleRoot}`

  const existing = db.prepare(
    'SELECT id, status FROM rekor_anchors WHERE tenant_id = ? AND receipt_id = ?',
  ).get(tenantId, receiptId) as { id: string; status: MerkleRootAnchor['status'] } | undefined
  if (existing) {
    return { anchorId: existing.id, batchId, merkleRoot, status: existing.status }
  }

  const anchorId = `anc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
  db.prepare(`
    INSERT INTO rekor_anchors (id, tenant_id, receipt_id, receipt_hash, agent_did, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', datetime('now'))
  `).run(anchorId, tenantId, receiptId, receiptHash, agentDid)

  return { anchorId, batchId, merkleRoot, status: 'pending' }
}

/** Look up the anchor record for a batch root, if any. */
export function getMerkleRootAnchor(tenantId: string, batchId: string): MerkleRootAnchor | null {
  const db = getDB()
  const row = db.prepare(
    'SELECT id, receipt_hash, status FROM rekor_anchors WHERE tenant_id = ? AND receipt_id = ?',
  ).get(tenantId, `batch:${batchId}`) as { id: string; receipt_hash: string; status: MerkleRootAnchor['status'] } | undefined
  if (!row) return null
  return { anchorId: row.id, batchId, merkleRoot: row.receipt_hash, status: row.status }
}
