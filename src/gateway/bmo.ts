// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Behavioral Memory Object (BMO) Storage — Bring Your Own Memory
 *
 * POST   /bmo                — store a BMO (signature + retention check)
 * GET    /bmo/:principalId   — list BMOs for a principal
 * DELETE /bmo/:id            — principal-only deletion with receipt
 */

import { Router } from 'express'
import { randomUUID, createHash } from 'node:crypto'
import { getDB } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'

export const bmoRouter = Router()

// ── POST /bmo ───────────────────────────────────────────────
// Store a Behavioral Memory Object.
// Validates: signature present, issuer has delegation with retention_permitted scope.
bmoRouter.post('/bmo', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const {
      principal_id, issuer_id, pattern_category, pattern_description,
      confidence, observation_count,
      observation_window_start, observation_window_end,
      derivation_source, retention_ttl, expires_at,
      relational_entities, portable, issuer_signature,
    } = req.body

    // Required fields
    if (!principal_id || !issuer_id || !pattern_category || !pattern_description) {
      return res.status(400).json({ error: 'Required: principal_id, issuer_id, pattern_category, pattern_description' })
    }
    if (!observation_window_start || !observation_window_end) {
      return res.status(400).json({ error: 'Required: observation_window_start, observation_window_end' })
    }
    if (!derivation_source) {
      return res.status(400).json({ error: 'Required: derivation_source' })
    }
    if (!issuer_signature) {
      return res.status(400).json({ error: 'Required: issuer_signature (Ed25519 over canonical BMO)' })
    }

    // Validate confidence range
    const conf = typeof confidence === 'number' ? confidence : 0.5
    if (conf < 0 || conf > 1) {
      return res.status(400).json({ error: 'confidence must be between 0 and 1' })
    }

    // Check that the issuer has an active delegation with retention_permitted scope
    // The scope field is comma-separated; we check for 'bmo:write' or 'data:retention' or '*'
    const delegation = db.prepare(`
      SELECT id, scope FROM delegations
      WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
      ORDER BY created_at DESC LIMIT 1
    `).get(tenant.id, issuer_id) as any

    if (!delegation) {
      return res.status(403).json({
        error: `Issuer "${issuer_id}" has no active delegation`,
        hint: 'The issuing agent must have a delegation with bmo:write or data:retention scope',
      })
    }

    const scopes = (delegation.scope || '').split(',').map((s: string) => s.trim())
    const retentionPermitted = scopes.some((s: string) =>
      s === '*' || s === 'bmo:write' || s === 'data:retention' ||
      s === 'bmo:*' || s === 'data:*'
    )
    if (!retentionPermitted) {
      return res.status(403).json({
        error: `Delegation for "${issuer_id}" does not grant retention rights`,
        required_scope: 'bmo:write or data:retention',
        actual_scope: scopes,
      })
    }

    const id = randomUUID()
    const relEntities = Array.isArray(relational_entities)
      ? JSON.stringify(relational_entities)
      : (relational_entities || '[]')

    db.prepare(`
      INSERT INTO behavioral_memory_objects (
        id, tenant_id, principal_id, issuer_id, pattern_category, pattern_description,
        confidence, observation_count, observation_window_start, observation_window_end,
        derivation_source, retention_ttl, expires_at, relational_entities,
        portable, issuer_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id, tenant.id, principal_id, issuer_id, pattern_category, pattern_description,
      conf, observation_count || 1,
      observation_window_start, observation_window_end,
      derivation_source, retention_ttl || null, expires_at || null,
      relEntities, portable ? 1 : 0, issuer_signature,
    )

    return res.status(201).json({
      bmo_id: id,
      principal_id,
      issuer_id,
      pattern_category,
      delegation_id: delegation.id,
      stored: true,
    })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Duplicate BMO' })
    }
    console.error('[bmo] POST failed:', e.message)
    return res.status(500).json({ error: 'BMO storage failed' })
  }
})

// ── GET /bmo/:principalId ───────────────────────────────────
// List all BMOs for a principal, filtering expired entries.
bmoRouter.get('/bmo/:principalId', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { principalId } = req.params
    const includeExpired = req.query.include_expired === 'true'

    let query = `SELECT * FROM behavioral_memory_objects WHERE tenant_id = ? AND principal_id = ?`
    const params: any[] = [tenant.id, principalId]

    if (!includeExpired) {
      query += ` AND (expires_at IS NULL OR expires_at > datetime('now'))`
    }

    query += ` ORDER BY created_at DESC`
    const rows = db.prepare(query).all(...params) as any[]

    const bmos = rows.map((r: any) => ({
      ...r,
      relational_entities: JSON.parse(r.relational_entities || '[]'),
      portable: !!r.portable,
    }))

    return res.json({ bmos, count: bmos.length, principal_id: principalId })
  } catch (e: any) {
    console.error('[bmo] GET failed:', e.message)
    return res.status(500).json({ error: 'BMO retrieval failed' })
  }
})

// ── DELETE /bmo/:id ─────────────────────────────────────────
// Principal-only deletion. Creates a deletion receipt for audit trail.
bmoRouter.delete('/bmo/:id', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { id } = req.params
    const { principal_id } = req.body || {}

    if (!principal_id) {
      return res.status(400).json({ error: 'Required: principal_id in request body' })
    }

    // Fetch the BMO
    const bmo = db.prepare(
      `SELECT * FROM behavioral_memory_objects WHERE id = ? AND tenant_id = ?`
    ).get(id, tenant.id) as any

    if (!bmo) {
      return res.status(404).json({ error: 'BMO not found' })
    }

    // Only the principal can delete their own BMO
    if (bmo.principal_id !== principal_id) {
      return res.status(403).json({
        error: 'Only the principal can delete their own BMOs',
        bmo_principal: bmo.principal_id,
        requesting_principal: principal_id,
      })
    }

    // Create deletion receipt before removing
    const receiptId = randomUUID()
    const deletionReceipt = {
      receipt_id: receiptId,
      bmo_id: id,
      principal_id,
      issuer_id: bmo.issuer_id,
      pattern_category: bmo.pattern_category,
      deleted_at: new Date().toISOString(),
      content_hash: createHash('sha256')
        .update(JSON.stringify({
          id: bmo.id, principal_id: bmo.principal_id,
          pattern_category: bmo.pattern_category,
          pattern_description: bmo.pattern_description,
        }))
        .digest('hex'),
    }

    // Store deletion receipt in alerts for audit trail
    db.prepare(
      `INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`
    ).run(
      receiptId, tenant.id, 'bmo_deletion', 'info',
      JSON.stringify(deletionReceipt),
    )

    // Delete the BMO
    db.prepare(`DELETE FROM behavioral_memory_objects WHERE id = ? AND tenant_id = ?`)
      .run(id, tenant.id)

    return res.json({
      deleted: true,
      deletion_receipt: deletionReceipt,
    })
  } catch (e: any) {
    console.error('[bmo] DELETE failed:', e.message)
    return res.status(500).json({ error: 'BMO deletion failed' })
  }
})
