// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * BMO Evidence Bridge — export behavioral memory as MolTrust evidence
 *
 * POST /bmo/:id/export-evidence — export a BMO as MolTrust evidence
 */

import { Router } from 'express'
import { getDB } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'

export const bmoEvidenceRouter = Router()

bmoEvidenceRouter.post('/bmo/:id/export-evidence', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { id } = req.params
  const db = getDB()

  // Look up BMO
  const bmo = db.prepare(
    `SELECT * FROM behavioral_memory_objects WHERE id = ? AND tenant_id = ?`
  ).get(id, tenant.id) as any

  if (!bmo) {
    return res.status(404).json({ error: `BMO "${id}" not found` })
  }

  // Only the principal who owns the BMO can trigger export
  const { principal_id } = req.body
  if (!principal_id) {
    return res.status(400).json({ error: 'Required: principal_id (the BMO owner requesting export)' })
  }
  if (bmo.principal_id !== principal_id) {
    return res.status(403).json({ error: 'Only the BMO principal can trigger evidence export' })
  }

  // Check portability
  if (!bmo.portable) {
    return res.status(403).json({ error: 'BMO is not portable — export not permitted by derivation_rights' })
  }

  // Check expiry
  if (bmo.expires_at && new Date(bmo.expires_at) < new Date()) {
    return res.status(410).json({ error: 'BMO has expired — cannot export' })
  }

  // Format for MolTrust evidence system
  const evidencePayload = {
    did: bmo.issuer_id,
    evidence_type: 'behavioral',
    payload: {
      category: bmo.pattern_category,
      confidence: bmo.confidence,
      observation_count: bmo.observation_count,
      observation_window: {
        start: bmo.observation_window_start,
        end: bmo.observation_window_end,
      },
    },
    signature: bmo.issuer_signature,
    retention_ttl: bmo.retention_ttl,
    relational_scope: bmo.relational_entities === 1 || bmo.relational_entities === '1' || bmo.relational_entities === true
      ? 'contains_third_party'
      : 'individual_only',
  }

  // POST to MolTrust evidence endpoint
  try {
    const moltrustRes = await fetch('https://api.moltrust.ch/evidence/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(evidencePayload),
      signal: AbortSignal.timeout(5000),
    })

    if (moltrustRes.ok) {
      const result = await moltrustRes.json() as any
      res.json({
        exported: true,
        bmo_id: id,
        moltrust_evidence_id: result.evidence_id || result.id || null,
        relational_scope: evidencePayload.relational_scope,
        timestamp: new Date().toISOString(),
      })
    } else {
      const errText = await moltrustRes.text().catch(() => 'unknown')
      res.status(502).json({
        exported: false,
        bmo_id: id,
        error: `MolTrust returned HTTP ${moltrustRes.status}`,
        detail: errText.slice(0, 200),
      })
    }
  } catch (e) {
    // MolTrust unreachable — return the formatted payload for manual submission
    res.json({
      exported: false,
      bmo_id: id,
      error: `MolTrust unreachable: ${(e as Error).message}`,
      evidence_payload: evidencePayload,
      note: 'MolTrust endpoint not available. Evidence payload included for manual submission.',
      timestamp: new Date().toISOString(),
    })
  }
})
