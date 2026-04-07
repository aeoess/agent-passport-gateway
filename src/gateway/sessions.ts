// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Agent Session Persistence -- reconstructable state after crash
 * Nate B Jones Primitive #3: Session persistence that survives crashes
 *
 * PUT    /sessions/:agentId  -- checkpoint session state
 * GET    /sessions/:agentId  -- reconstruct (stored + live delta)
 * DELETE /sessions/:agentId  -- clear on clean shutdown
 * GET    /sessions           -- list active sessions for tenant
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getDB } from '../db/schema.js'
import { PLAN_LIMITS } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'

export const sessionsRouter = Router()

// ── PUT /sessions/:agentId ──────────────────────────────────
// Upsert: store the full session state as JSON
sessionsRouter.put('/sessions/:agentId', (req, res) => {
  try {
    const tenant: Tenant = (req as any).tenant
    const { agentId } = req.params
    const sessionData = req.body

    if (!sessionData || typeof sessionData !== 'object') {
      return res.status(400).json({ error: 'Body must be a JSON object' })
    }

    // Validate it serializes cleanly
    let serialized: string
    try {
      serialized = JSON.stringify(sessionData)
    } catch {
      return res.status(400).json({ error: 'Body must be valid JSON' })
    }

    const db = getDB()
    const now = new Date().toISOString()

    const stmt = db.prepare(`
      INSERT INTO agent_sessions (id, tenant_id, agent_id, session_data, created_at, updated_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
        session_data = excluded.session_data,
        updated_at = excluded.updated_at,
        expires_at = excluded.expires_at
    `)

    const expiresAt = sessionData.expires_at || null
    stmt.run(randomUUID(), tenant.id, agentId, serialized, now, now, expiresAt)

    return res.json({ ok: true, updated_at: now })
  } catch (err: any) {
    return res.status(500).json({ error: err.message })
  }
})

// ── GET /sessions/:agentId ──────────────────────────────────
// Reconstruct: stored checkpoint + live delta since last update
sessionsRouter.get('/sessions/:agentId', (req, res) => {
  try {
    const tenant: Tenant = (req as any).tenant
    const { agentId } = req.params
    const db = getDB()

    const row = db.prepare(
      `SELECT * FROM agent_sessions WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any

    if (!row) {
      return res.status(404).json({ error: 'No session found for this agent' })
    }

    // Check expiry
    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      // Expired -- clean up and 404
      db.prepare(`DELETE FROM agent_sessions WHERE id = ?`).run(row.id)
      return res.status(404).json({ error: 'Session expired' })
    }

    const stored = JSON.parse(row.session_data)
    const checkpointTime = row.updated_at

    // Live delta: evaluations since checkpoint
    const evalsSince = db.prepare(`
      SELECT COUNT(*) as count FROM policy_evaluations
      WHERE tenant_id = ? AND agent_id = ? AND created_at > ?
    `).get(tenant.id, agentId, checkpointTime) as any

    // Live delta: alerts since checkpoint
    const alertsSince = db.prepare(`
      SELECT id, alert_type, severity, message, created_at FROM alerts
      WHERE tenant_id = ? AND created_at > ?
      ORDER BY created_at DESC LIMIT 20
    `).all(tenant.id, checkpointTime) as any[]

    // Live delta: current posture
    const latestPosture = db.prepare(`
      SELECT new_status, restricted_scopes, reason, created_at FROM posture_events
      WHERE tenant_id = ? AND agent_id = ?
      ORDER BY created_at DESC LIMIT 1
    `).get(tenant.id, agentId) as any

    // Live delta: delegation status (some may have been revoked)
    const activeDelegations = db.prepare(`
      SELECT id, scope, spend_limit, spend_used, status, revoked_at
      FROM delegations
      WHERE tenant_id = ? AND (parent_agent_id = ? OR child_agent_id = ?)
    `).all(tenant.id, agentId, agentId) as any[]

    // Health: denial rate and last eval
    const recentEvals = db.prepare(`
      SELECT verdict, created_at FROM policy_evaluations
      WHERE tenant_id = ? AND agent_id = ?
      ORDER BY created_at DESC LIMIT 50
    `).all(tenant.id, agentId) as any[]

    const denials = recentEvals.filter((e: any) => e.verdict === 'deny').length
    const denialRate = recentEvals.length > 0 ? denials / recentEvals.length : 0
    const lastEvalAt = recentEvals.length > 0 ? recentEvals[0].created_at : null

    return res.json({
      // Stored checkpoint
      checkpoint: stored,
      checkpoint_at: checkpointTime,

      // Live delta since checkpoint
      since_checkpoint: {
        evaluations_count: evalsSince?.count || 0,
        alerts: alertsSince,
        current_posture: latestPosture || null,
        delegation_status: activeDelegations.map((d: any) => ({
          delegation_id: d.id,
          scope: d.scope,
          spend_limit: d.spend_limit,
          spend_used: d.spend_used,
          status: d.status,
          revoked_at: d.revoked_at,
        })),
      },

      // Health summary
      health: {
        denial_rate: Math.round(denialRate * 100) / 100,
        last_eval_at: lastEvalAt,
        recent_eval_count: recentEvals.length,
      },
    })
  } catch (err: any) {
    return res.status(500).json({ error: err.message })
  }
})

// ── DELETE /sessions/:agentId ───────────────────────────────
// Clean shutdown: remove session
sessionsRouter.delete('/sessions/:agentId', (req, res) => {
  try {
    const tenant: Tenant = (req as any).tenant
    const { agentId } = req.params
    const db = getDB()

    const result = db.prepare(
      `DELETE FROM agent_sessions WHERE tenant_id = ? AND agent_id = ?`
    ).run(tenant.id, agentId)

    if (result.changes === 0) {
      return res.status(404).json({ error: 'No session found for this agent' })
    }

    return res.json({ ok: true, deleted: true })
  } catch (err: any) {
    return res.status(500).json({ error: err.message })
  }
})

// ── GET /sessions ───────────────────────────────────────────
// List all active sessions for this tenant
sessionsRouter.get('/sessions', (req, res) => {
  try {
    const tenant: Tenant = (req as any).tenant
    const db = getDB()

    const rows = db.prepare(`
      SELECT agent_id, session_data, updated_at, expires_at
      FROM agent_sessions
      WHERE tenant_id = ?
      ORDER BY updated_at DESC
    `).all(tenant.id) as any[]

    const now = new Date()
    const sessions = rows
      .filter((r: any) => !r.expires_at || new Date(r.expires_at) >= now)
      .map((r: any) => {
        let parsed: any = {}
        try { parsed = JSON.parse(r.session_data) } catch {}
        return {
          agent_id: r.agent_id,
          updated_at: r.updated_at,
          expires_at: r.expires_at,
          framework: parsed.framework || null,
          step: parsed.workflow?.step || null,
        }
      })

    return res.json({ sessions, count: sessions.length })
  } catch (err: any) {
    return res.status(500).json({ error: err.message })
  }
})
