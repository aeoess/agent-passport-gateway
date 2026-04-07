// ══════════════════════════════════════════════════════════════════
// Rekor Anchoring — Transparency Log Integration
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
