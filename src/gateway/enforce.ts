// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Gateway Enforcement API — the revenue product.
 *
 * POST /api/v1/evaluate   — policy evaluation (the billable unit)
 * POST /api/v1/receipt     — store signed receipt
 * POST /api/v1/revoke      — cascade revocation
 * GET  /api/v1/agents      — list agents
 * GET  /api/v1/delegations — list delegations
 * GET  /api/v1/audit       — audit trail
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getDB, PLAN_LIMITS } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'

export const gatewayRouter = Router()

// ═══════════════════════════════════════
// Usage check middleware
// ═══════════════════════════════════════

function checkUsageLimit(tenant: Tenant): { allowed: boolean; reason?: string } {
  const db = getDB()
  const period = new Date().toISOString().slice(0, 7) // YYYY-MM
  const usage = db.prepare(`SELECT evaluations FROM usage WHERE tenant_id = ? AND period = ?`)
    .get(tenant.id, period) as { evaluations: number } | undefined
  const current = usage?.evaluations || 0
  const limit = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS].evaluationsPerMonth
  if (limit > 0 && current >= limit) {
    return { allowed: false, reason: `Monthly limit reached: ${current}/${limit}. Upgrade at aeoess.com/pricing` }
  }
  return { allowed: true }
}

function incrementUsage(tenantId: string) {
  const db = getDB()
  const period = new Date().toISOString().slice(0, 7)
  const existing = db.prepare(`SELECT id FROM usage WHERE tenant_id = ? AND period = ?`).get(tenantId, period)
  if (existing) {
    db.prepare(`UPDATE usage SET evaluations = evaluations + 1, updated_at = datetime('now') WHERE tenant_id = ? AND period = ?`).run(tenantId, period)
  } else {
    db.prepare(`INSERT INTO usage (tenant_id, period, evaluations) VALUES (?, ?, 1)`).run(tenantId, period)
  }
}

// ═══════════════════════════════════════
// POST /api/v1/evaluate — Policy Evaluation
// ═══════════════════════════════════════

gatewayRouter.post('/evaluate', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const start = Date.now()

  // Usage check
  const usageCheck = checkUsageLimit(tenant)
  if (!usageCheck.allowed) {
    return res.status(429).json({ error: usageCheck.reason })
  }

  const { agent_id, action_type, action_target, scope_required, estimated_cost } = req.body
  if (!agent_id || !action_type || !scope_required) {
    return res.status(400).json({ error: 'Required: agent_id, action_type, scope_required' })
  }

  const db = getDB()

  // Check agent exists and is active
  const agent = db.prepare(`SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`)
    .get(tenant.id, agent_id) as any
  if (!agent) {
    return res.status(404).json({ error: `Agent "${agent_id}" not found or inactive` })
  }

  // Check delegation scope
  const delegation = db.prepare(`
    SELECT * FROM delegations 
    WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
    ORDER BY created_at DESC LIMIT 1
  `).get(tenant.id, agent_id) as any

  let verdict = 'permit'
  let reason = ''
  const violations: string[] = []

  if (!delegation) {
    verdict = 'deny'
    violations.push('No active delegation for agent')
  } else {
    // Scope check
    const allowedScopes = delegation.scope.split(',').map((s: string) => s.trim())
    const scopeMatch = allowedScopes.some((s: string) =>
      s === scope_required || s === '*' ||
      (s.endsWith(':*') && scope_required.startsWith(s.slice(0, -1)))
    )
    if (!scopeMatch) {
      verdict = 'deny'
      violations.push(`Scope "${scope_required}" not in [${delegation.scope}]`)
    }


    // Spend limit check
    if (estimated_cost && delegation?.spend_limit) {
      const remaining = delegation.spend_limit - (delegation.spend_used || 0)
      if (estimated_cost > remaining) {
        verdict = 'deny'
        violations.push(`Cost $${estimated_cost} exceeds remaining budget $${remaining.toFixed(2)}`)
      }
    }
  }

  reason = verdict === 'permit'
    ? `Permitted: scope "${scope_required}" authorized`
    : `Denied: ${violations.join('; ')}`

  const durationMs = Date.now() - start
  const evalId = randomUUID()

  // Record evaluation
  db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, verdict, reason, durationMs)

  incrementUsage(tenant.id)

  // Update spend if permitted
  if (verdict === 'permit' && estimated_cost && delegation) {
    db.prepare(`UPDATE delegations SET spend_used = spend_used + ? WHERE id = ?`)
      .run(estimated_cost, delegation.id)
  }

  // Check for spend alerts (80% threshold)
  if (delegation?.spend_limit && delegation.spend_used > delegation.spend_limit * 0.8) {
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenant.id, 'spend_threshold', 'warning',
        `Agent "${agent_id}" at ${((delegation.spend_used / delegation.spend_limit) * 100).toFixed(0)}% of spend limit`)
  }

  res.json({
    evaluation_id: evalId,
    verdict,
    reason,
    violations: violations.length > 0 ? violations : undefined,
    duration_ms: durationMs,
    agent_id,
    action: { type: action_type, target: action_target, scope_required },
  })
})

// ═══════════════════════════════════════
// POST /api/v1/receipt — Store Signed Receipt
// ═══════════════════════════════════════

gatewayRouter.post('/receipt', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { evaluation_id, agent_id, action_type, verdict, execution_result, signature, payload } = req.body
  if (!agent_id || !signature || !payload) {
    return res.status(400).json({ error: 'Required: agent_id, signature, payload' })
  }

  const db = getDB()
  const receiptId = randomUUID()
  db.prepare(`INSERT INTO receipts (id, tenant_id, evaluation_id, agent_id, action_type, verdict, execution_result, signature, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(receiptId, tenant.id, evaluation_id || null, agent_id, action_type || '', verdict || '', execution_result || '', signature, typeof payload === 'string' ? payload : JSON.stringify(payload))

  res.status(201).json({ receipt_id: receiptId, stored: true })
})

// ═══════════════════════════════════════
// POST /api/v1/revoke — Cascade Revocation
// ═══════════════════════════════════════

gatewayRouter.post('/revoke', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { target_type, target_id, revoked_by } = req.body
  if (!target_type || !target_id) {
    return res.status(400).json({ error: 'Required: target_type (agent|delegation), target_id' })
  }

  const db = getDB()
  let cascadeCount = 0

  if (target_type === 'agent') {
    // Revoke agent and all their delegations
    db.prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenant.id, target_id)
    const result = db.prepare(`UPDATE delegations SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND (child_agent_id = ? OR parent_agent_id = ?)`)
      .run(tenant.id, target_id, target_id)
    cascadeCount = result.changes
  } else if (target_type === 'delegation') {
    // Revoke specific delegation and downstream
    db.prepare(`UPDATE delegations SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND id = ?`)
      .run(tenant.id, target_id)
    cascadeCount = 1
  }

  const revocationId = randomUUID()
  db.prepare(`INSERT INTO revocations (id, tenant_id, target_type, target_id, cascade_count, revoked_by) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(revocationId, tenant.id, target_type, target_id, cascadeCount, revoked_by || 'api')

  db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenant.id, 'revocation', 'critical',
      `${target_type} "${target_id}" revoked. ${cascadeCount} downstream items affected.`)

  res.json({ revocation_id: revocationId, target_type, target_id, cascade_count: cascadeCount })
})

// ═══════════════════════════════════════
// GET /api/v1/agents — List Agents
// ═══════════════════════════════════════

gatewayRouter.get('/agents', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const agents = db.prepare(`SELECT agent_id, public_key, did, name, status, created_at FROM agents WHERE tenant_id = ?`).all(tenant.id)
  res.json({ agents, count: agents.length })
})

// POST /api/v1/agents — Register Agent
gatewayRouter.post('/agents', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { agent_id, public_key, did, name } = req.body
  if (!agent_id || !public_key) {
    return res.status(400).json({ error: 'Required: agent_id, public_key' })
  }
  const limit = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS].maxAgents
  if (limit > 0) {
    const count = db.prepare(`SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
    if (count.c >= limit) {
      return res.status(429).json({ error: `Agent limit reached: ${count.c}/${limit}. Upgrade at aeoess.com/pricing` })
    }
  }
  const id = randomUUID()
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, did, name) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, agent_id, public_key, did || null, name || null)
  res.status(201).json({ id, agent_id, status: 'active' })
})

// POST /api/v1/delegations — Create Delegation
gatewayRouter.post('/delegations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { parent_agent_id, child_agent_id, scope, spend_limit, max_depth } = req.body
  if (!parent_agent_id || !child_agent_id || !scope) {
    return res.status(400).json({ error: 'Required: parent_agent_id, child_agent_id, scope' })
  }
  const id = randomUUID()
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, spend_limit, max_depth) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, parent_agent_id, child_agent_id, Array.isArray(scope) ? scope.join(',') : scope, spend_limit || null, max_depth || 3)
  res.status(201).json({ id, status: 'active' })
})

// GET /api/v1/delegations — List Delegations
gatewayRouter.get('/delegations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const delegations = db.prepare(`SELECT * FROM delegations WHERE tenant_id = ? ORDER BY created_at DESC`).all(tenant.id)
  res.json({ delegations, count: delegations.length })
})

// GET /api/v1/audit — Audit Trail
gatewayRouter.get('/audit', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = parseInt(req.query.limit as string) || 100
  const offset = parseInt(req.query.offset as string) || 0
  const agent = req.query.agent_id as string

  let query = `SELECT e.*, r.signature, r.execution_result FROM policy_evaluations e LEFT JOIN receipts r ON r.evaluation_id = e.id WHERE e.tenant_id = ?`
  const params: any[] = [tenant.id]
  if (agent) { query += ` AND e.agent_id = ?`; params.push(agent) }
  query += ` ORDER BY e.created_at DESC LIMIT ? OFFSET ?`
  params.push(limit, offset)

  const entries = db.prepare(query).all(...params)
  const total = db.prepare(`SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ?`).get(tenant.id) as any
  res.json({ entries, total: total.c, limit, offset })
})

// GET /api/v1/dashboard — Dashboard Summary
gatewayRouter.get('/dashboard', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const period = new Date().toISOString().slice(0, 7)

  const agents = db.prepare(`SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
  const delegations = db.prepare(`SELECT COUNT(*) as c FROM delegations WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
  const usage = db.prepare(`SELECT evaluations FROM usage WHERE tenant_id = ? AND period = ?`).get(tenant.id, period) as any
  const receipts = db.prepare(`SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ?`).get(tenant.id) as any
  const alerts = db.prepare(`SELECT * FROM alerts WHERE tenant_id = ? AND acknowledged_at IS NULL ORDER BY created_at DESC LIMIT 10`).all(tenant.id)
  const limit = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS]

  const recentDenials = db.prepare(`SELECT agent_id, action_type, reason, created_at FROM policy_evaluations WHERE tenant_id = ? AND verdict = 'deny' ORDER BY created_at DESC LIMIT 5`).all(tenant.id)

  res.json({
    plan: tenant.plan,
    agents: { active: agents.c, limit: limit.maxAgents },
    delegations: { active: delegations.c },
    usage: {
      evaluations_this_month: usage?.evaluations || 0,
      limit: limit.evaluationsPerMonth,
      utilization: limit.evaluationsPerMonth > 0
        ? ((usage?.evaluations || 0) / limit.evaluationsPerMonth * 100).toFixed(1) + '%'
        : 'unlimited',
    },
    receipts: { total: receipts.c },
    alerts: { unacknowledged: alerts.length, items: alerts },
    recent_denials: recentDenials,
    compliance_reports_available: limit.complianceReports,
  })
})

// GET /api/v1/usage — Usage History
gatewayRouter.get('/usage', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const history = db.prepare(`SELECT * FROM usage WHERE tenant_id = ? ORDER BY period DESC LIMIT 12`).all(tenant.id)
  res.json({ usage: history })
})

// POST /api/v1/alerts/:id/acknowledge — Acknowledge Alert
gatewayRouter.post('/alerts/:id/acknowledge', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  db.prepare(`UPDATE alerts SET acknowledged_at = datetime('now') WHERE id = ? AND tenant_id = ?`)
    .run(req.params.id, tenant.id)
  res.json({ acknowledged: true })
})
