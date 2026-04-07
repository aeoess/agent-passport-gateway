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
import { randomUUID, createHash } from 'node:crypto'
import { getDB, PLAN_LIMITS } from '../db/schema.js'
import { getGatewayIdentity } from './identity.js'
import type { Tenant } from '../auth/api-keys.js'
import { computeLineageLinks, storeAndCluster, getClusterRisk } from './lineage.js'
import { getEventBus } from './events.js'

function safeError(e: any, context: string): { error: string; ref: string } {
  const ref = randomUUID().slice(0, 8)
  console.error(`[ERR:${ref}] ${context}:`, e.message || e)
  return { error: `Internal error (ref: ${ref}). Contact support.`, ref }
}

// ── Auto-Mint Evaluation Receipts ──
// Non-blocking: logs failures but never blocks the evaluation response.
// Denials are signed (proof of restraint). Permits are unsigned (routine).

function canonicalJsonStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(canonicalJsonStringify).join(',') + ']'
  const keys = Object.keys(v as Record<string, unknown>).sort()
  return '{' + keys.map(k =>
    JSON.stringify(k) + ':' + canonicalJsonStringify((v as Record<string, unknown>)[k])
  ).join(',') + '}'
}

function mintEvaluationReceipt(opts: {
  tenantId: string; agentId: string; evaluationId: string;
  verdict: string; actionType: string; scopeRequired: string;
  reason: string; delegationId: string | null;
}) {
  try {
    const db = getDB()
    const scopeJson = JSON.stringify(
      (opts.scopeRequired || '').split(',').map(s => s.trim()).filter(Boolean).sort()
    )
    const policyHash = createHash('sha256')
      .update('floor-v1-scope-spend-depth-delegation')
      .digest('hex').slice(0, 16)

    const receiptData: Record<string, unknown> = {
      tenant_id: opts.tenantId,
      agent_id: opts.agentId,
      evaluation_id: opts.evaluationId,
      event_type: opts.verdict === 'permit' ? 'authorization_permit' : 'authorization_deny',
      decision_stage: 'gateway_authorization',
      action_type: opts.actionType,
      scope_requested_json: scopeJson,
      verdict: opts.verdict === 'permit' ? 'permit' : 'deny',
      reason_code: opts.verdict !== 'permit' ? (opts.reason || 'policy_deny') : null,
      delegation_id: opts.delegationId,
      policy_hash: policyHash,
      schema_version: '1.0.0',
    }

    const receiptHash = createHash('sha256')
      .update(canonicalJsonStringify(receiptData))
      .digest('hex')

    // Only sign denials (proof of restraint)
    let gatewaySignature: string | null = null
    if (opts.verdict !== 'permit') {
      try {
        const identity = getGatewayIdentity()
        gatewaySignature = identity.sign({ ...receiptData, receipt_hash: receiptHash })
      } catch { /* signing optional, log below */ }
    }

    db.prepare(`
      INSERT INTO evaluation_receipts (
        tenant_id, agent_id, evaluation_id, event_type, decision_stage,
        action_type, scope_requested_json, verdict, reason_code,
        delegation_id, policy_hash, schema_version, receipt_hash, gateway_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      receiptData.tenant_id, receiptData.agent_id, receiptData.evaluation_id,
      receiptData.event_type, receiptData.decision_stage,
      receiptData.action_type, receiptData.scope_requested_json,
      receiptData.verdict, receiptData.reason_code,
      receiptData.delegation_id, receiptData.policy_hash,
      receiptData.schema_version, receiptHash, gatewaySignature,
    )
    maybeAutoSeal()
  } catch (e: any) {
    console.error('[receipt-mint] FAILED:', opts.agentId, e.message)
  }
}

// SDK scope matching — respects monotonic narrowing invariant
let _scopeAuthorizes: ((scopes: string[], required: string) => boolean) | null = null
async function getScopeAuthorizes() {
  if (!_scopeAuthorizes) {
    try {
      const sdk = await import('agent-passport-system')
      _scopeAuthorizes = sdk.scopeAuthorizes
    } catch {
      // Fallback if SDK not available — manual match
      _scopeAuthorizes = (scopes: string[], required: string) =>
        scopes.some(s => s === required || s === '*' ||
          (s.endsWith(':*') && required.startsWith(s.slice(0, -1))))
    }
  }
  return _scopeAuthorizes
}

// SDK recovery evaluation — consulted on denials
let _evaluateRecovery: ((opts: any) => any) | null = null
async function getEvaluateRecovery() {
  if (!_evaluateRecovery) {
    try {
      const sdk: any = await import('agent-passport-system')
      if (typeof sdk.evaluateRecovery === 'function') {
        _evaluateRecovery = sdk.evaluateRecovery
      }
    } catch { /* SDK version may not have evaluateRecovery yet */ }
  }
  return _evaluateRecovery
}

// Map denial reason to SDK failure type
function mapFailureType(violations: string[]): string {
  const joined = violations.join(' ').toLowerCase()
  if (joined.includes('scope')) return 'scope_denied'
  if (joined.includes('budget') || joined.includes('spend') || joined.includes('cost')) return 'budget_exceeded'
  if (joined.includes('suspended')) return 'passport_expired'
  if (joined.includes('delegation')) return 'delegation_revoked'
  if (joined.includes('key')) return 'policy_violation'
  return 'unknown'
}

export const gatewayRouter = Router()

// ═══════════════════════════════════════
// Lexical similarity utilities (reusable)
// ═══════════════════════════════════════

function ngrams(text: string, n: number): Set<string> {
  const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w.length > 2)
  const grams = new Set<string>()
  for (let i = 0; i <= words.length - n; i++) grams.add(words.slice(i, i + n).join(' '))
  return grams
}

function jaccardOverlap(a: Set<string>, b: Set<string>): number {
  let shared = 0
  a.forEach(g => { if (b.has(g)) shared++ })
  const union = new Set([...a, ...b]).size
  return union > 0 ? shared / union : 0
}

function computeLexicalScore(sourceText: string, outputText: string) {
  const uni = jaccardOverlap(ngrams(sourceText, 1), ngrams(outputText, 1))
  const bi = jaccardOverlap(ngrams(sourceText, 2), ngrams(outputText, 2))
  const tri = jaccardOverlap(ngrams(sourceText, 3), ngrams(outputText, 3))
  const score = Math.round((uni * 0.2 + bi * 0.35 + tri * 0.45) * 10000) / 10000
  return {
    score, detail: { unigram: Math.round(uni * 10000) / 10000, bigram: Math.round(bi * 10000) / 10000, trigram: Math.round(tri * 10000) / 10000 },
    verdict: score > 0.3 ? 'high_overlap' as const : score > 0.1 ? 'moderate_overlap' as const : 'low_overlap' as const,
  }
}

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
  // Manual upsert — works regardless of UNIQUE constraint on table
  const existing = db.prepare(`SELECT id FROM usage WHERE tenant_id = ? AND period = ?`).get(tenantId, period) as any
  if (existing) {
    db.prepare(`UPDATE usage SET evaluations = evaluations + 1, updated_at = datetime('now') WHERE id = ?`).run(existing.id)
  } else {
    db.prepare(`INSERT INTO usage (tenant_id, period, evaluations) VALUES (?, ?, 1)`).run(tenantId, period)
  }
}

// ═══════════════════════════════════════
// POST /api/v1/evaluate — Policy Evaluation
// ═══════════════════════════════════════

gatewayRouter.post('/evaluate', async (req: any, res) => {
  try {
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

  // Check agent exists
  const agent = db.prepare(`SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`)
    .get(tenant.id, agent_id) as any
  if (!agent) {
    return res.status(404).json({ error: `Agent "${agent_id}" not found` })
  }

  // Posture enforcement: suspended → deny all, restricted → deny restricted scopes
  if (agent.status === 'suspended') {
    const evalId = randomUUID()
    const durationMs = Date.now() - start
    db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', 'Agent suspended', durationMs)
    mintEvaluationReceipt({
      tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
      verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
      reason: 'agent_suspended', delegationId: null,
    })
    return res.json({ evaluation_id: evalId, verdict: 'deny', reason: 'Agent suspended', violations: ['agent_suspended'], duration_ms: durationMs, agent_id, action: { type: action_type, target: action_target, scope_required } })
  }
  if (agent.status === 'restricted' && agent.restricted_scopes) {
    try {
      const restrictedScopes: string[] = JSON.parse(agent.restricted_scopes)
      if (restrictedScopes.includes(scope_required) || restrictedScopes.some(rs => scope_required.startsWith(rs + ':'))) {
        const evalId = randomUUID()
        const durationMs = Date.now() - start
        db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', `Scope "${scope_required}" restricted by posture`, durationMs)
        mintEvaluationReceipt({
          tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
          verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
          reason: 'scope_restricted', delegationId: null,
        })
        return res.json({ evaluation_id: evalId, verdict: 'deny', reason: `Scope "${scope_required}" restricted by posture`, violations: ['scope_restricted'], duration_ms: durationMs, agent_id, action: { type: action_type, target: action_target, scope_required } })
      }
    } catch { /* invalid JSON in restricted_scopes — proceed */ }
  }
  if (agent.status !== 'active' && agent.status !== 'restricted') {
    return res.status(404).json({ error: `Agent "${agent_id}" not active (status: ${agent.status})` })
  }

  // Key rotation enforcement: if request includes signing_key, check against retired keys.
  // A compromised old key MUST NOT authorize actions after rotation completes.
  const signingKey = req.body.signing_key as string | undefined
  if (signingKey) {
    const rotation = db.prepare(
      `SELECT old_key, new_key, state FROM key_rotations
       WHERE tenant_id = ? AND agent_id = ? AND state = 'activated'
       ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agent_id) as any
    if (rotation && rotation.old_key === signingKey) {
      const evalId = randomUUID()
      const durationMs = Date.now() - start
      db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', 'Key retired via rotation', durationMs)
      mintEvaluationReceipt({
        tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
        verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
        reason: 'key_retired', delegationId: null,
      })
      return res.json({
        evaluation_id: evalId, verdict: 'deny',
        reason: 'Key retired via rotation. Use the current key.',
        violations: ['key_retired'],
        duration_ms: durationMs, agent_id,
        action: { type: action_type, target: action_target, scope_required },
      })
    }
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
    // Scope check — uses SDK scopeAuthorizes() for monotonic narrowing
    const allowedScopes = delegation.scope.split(',').map((s: string) => s.trim())
    const scopeAuth = await getScopeAuthorizes()
    const scopeMatch = scopeAuth(allowedScopes, scope_required)
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

  // Emit SSE event
  try { getEventBus().emit(tenant.id, { type: verdict === 'permit' ? 'evaluation' : 'denial', agentId: agent_id, data: { evaluationId: evalId, action_type, scope_required, verdict, reason, duration_ms: durationMs } }) } catch {}

  // Auto-mint evaluation receipt (non-blocking)
  mintEvaluationReceipt({
    tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
    verdict, actionType: action_type, scopeRequired: scope_required,
    reason, delegationId: delegation?.id || null,
  })

  incrementUsage(tenant.id)

  // Update spend if permitted
  if (verdict === 'permit' && estimated_cost && delegation) {
    db.prepare(`UPDATE delegations SET spend_used = spend_used + ? WHERE id = ?`)
      .run(estimated_cost, delegation.id)
    try { getEventBus().emit(tenant.id, { type: 'spend_update', agentId: agent_id, data: { delegation_id: delegation.id, spend_used: (delegation.spend_used || 0) + estimated_cost, spend_limit: delegation.spend_limit } }) } catch {}
  }

  // Check for spend alerts (80% threshold)
  if (delegation?.spend_limit && delegation.spend_used > delegation.spend_limit * 0.8) {
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenant.id, 'spend_threshold', 'warning',
        `Agent "${agent_id}" at ${((delegation.spend_used / delegation.spend_limit) * 100).toFixed(0)}% of spend limit`)
    try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'spend_threshold', severity: 'warning' } }) } catch {}
  }

  // Recovery guidance on denial (backward compat: null when no policy)
  let recovery: any = null
  if (verdict === 'deny') {
    try {
      const policyRow = db.prepare(
        `SELECT policy_json FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
      ).get(tenant.id, agent_id) as any
      if (policyRow) {
        const evaluateRecovery = await getEvaluateRecovery()
        if (evaluateRecovery) {
          const policy = JSON.parse(policyRow.policy_json)
          const failureType = mapFailureType(violations)
          const result = evaluateRecovery({ policy, failureType })
          recovery = {
            strategy: result.strategy,
            rule: result.rule?.name || null,
            maxRetries: result.rule?.maxRetries || null,
            initialBackoffMs: result.rule?.initialBackoffMs || null,
            hardStop: result.hardStop,
          }
          // Store recovery event in audit trail (best-effort)
          try {
            db.prepare(
              `INSERT INTO recovery_events (id, tenant_id, agent_id, delegation_id, evaluation_id, failure_type, strategy_applied, attempt_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(randomUUID(), tenant.id, agent_id, delegation?.id || null, evalId, failureType, result.strategy, 1)
            try { getEventBus().emit(tenant.id, { type: 'recovery_event', agentId: agent_id, data: { failure_type: failureType, strategy: result.strategy } }) } catch {}
          } catch { /* best-effort */ }
        }
      }
    } catch { /* recovery lookup is best-effort, never blocks response */ }
  }

  res.json({
    evaluation_id: evalId,
    verdict,
    reason,
    violations: violations.length > 0 ? violations : undefined,
    recovery,
    duration_ms: durationMs,
    agent_id,
    action: { type: action_type, target: action_target, scope_required },
  })
  } catch (e) {
    const msg = (e as Error).message || String(e)
    const stack = (e as Error).stack || ''
    console.error('[EVALUATE ERROR]', msg)
    const err = safeError(e, 'evaluate')
    res.status(500).json(err)
  }
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

  try { getEventBus().emit(tenant.id, { type: 'receipt_stored', agentId: agent_id, data: { receiptId, evaluationId: evaluation_id, action_type, verdict } }) } catch {}

  res.status(201).json({ receipt_id: receiptId, stored: true })
})

// ═══════════════════════════════════════
// POST /api/v1/revoke — Cascade Revocation
// ═══════════════════════════════════════

gatewayRouter.post('/revoke', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { target_type, target_id, revoked_by } = req.body
  if (!target_type || !target_id) {
    return res.status(400).json({ error: 'Required: target_type (agent|delegation|data_source), target_id' })
  }

  const db = getDB()
  let cascadeCount = 0

  if (target_type === 'agent') {
    // Revoke agent and all their delegations
    db.prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenant.id, target_id)
    const result = db.prepare(`UPDATE delegations SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND (child_agent_id = ? OR parent_agent_id = ?)`)
      .run(tenant.id, target_id, target_id)
    // Freeze agent wallet as part of revocation cascade
    db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`)
      .run(tenant.id, target_id)
    cascadeCount = result.changes
  } else if (target_type === 'delegation') {
    // Revoke specific delegation and downstream
    db.prepare(`UPDATE delegations SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND id = ?`)
      .run(tenant.id, target_id)
    cascadeCount = 1
  } else if (target_type === 'data_source') {
    // Retract a data source — no more access receipts will be generated
    db.prepare(`UPDATE data_sources SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND source_id = ?`)
      .run(tenant.id, target_id)
    // Count affected agents (who consumed this source)
    const affected = db.prepare(`SELECT COUNT(DISTINCT agent_id) as c FROM access_receipts WHERE tenant_id = ? AND source_id = ?`)
      .get(tenant.id, target_id) as any
    cascadeCount = affected.c
  }

  const revocationId = randomUUID()
  db.prepare(`INSERT INTO revocations (id, tenant_id, target_type, target_id, cascade_count, revoked_by) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(revocationId, tenant.id, target_type, target_id, cascadeCount, revoked_by || 'api')

  db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenant.id, 'revocation', 'critical',
      `${target_type} "${target_id}" revoked. ${cascadeCount} downstream items affected.`)
  try { getEventBus().emit(tenant.id, { type: 'alert', data: { alert_type: 'revocation', severity: 'critical', target_type, target_id } }) } catch {}

  try { getEventBus().emit(tenant.id, { type: 'revocation', data: { revocationId, target_type, target_id, cascade_count: cascadeCount, revoked_by: revoked_by || 'api' } }) } catch {}

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
  try { getEventBus().emit(tenant.id, { type: 'agent_registered', agentId: agent_id, data: { public_key, name, did } }) } catch {}
  res.status(201).json({ id, agent_id, status: 'active' })
})

// ═══════════════════════════════════════
// POST /api/v1/issuance-dossier
// MCP server POSTs IssuanceContext after every passport issuance.
// Gateway stores the full evidence record privately.
// ═══════════════════════════════════════
gatewayRouter.post('/issuance-dossier', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const {
    passport_id, public_key_hash, passport_grade, flags,
    attestation_bundle_hash, observed_context,
    runtime_attestations, provider_attestations,
    self_declared_signals, derived_signals, prior_passport_ref
  } = req.body

  if (!passport_id || !public_key_hash) {
    return res.status(400).json({ error: 'Required: passport_id, public_key_hash' })
  }

  // Clamp grade to 0-3 — malicious MCP can't send passport_grade: 99
  const grade = Math.min(3, Math.max(0, Math.floor(passport_grade || 0)))
  const id = randomUUID()
  const obs = observed_context || {}

  try {
    db.prepare(`INSERT OR REPLACE INTO issuance_dossiers
      (id, tenant_id, passport_id, public_key_hash, passport_grade,
       flags, attestation_bundle_hash, observed_context,
       runtime_attestations, provider_attestations,
       self_declared_signals, derived_signals, prior_passport_ref,
       transport_type, issuance_velocity, connection_timing_ms,
       request_payload_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        id, tenant.id, passport_id, public_key_hash,
        grade,
        JSON.stringify(flags || []),
        attestation_bundle_hash || null,
        JSON.stringify(obs),
        JSON.stringify(runtime_attestations || []),
        JSON.stringify(provider_attestations || []),
        JSON.stringify(self_declared_signals || []),
        JSON.stringify(derived_signals || []),
        prior_passport_ref || null,
        obs.transportType || null,
        obs.issuanceVelocity ?? null,
        obs.connectionTimingMs ?? null,
        obs.requestPayloadFingerprint || null
      )

    // Check for velocity anomaly — many passports from same pubkey hash
    const velocityCheck = db.prepare(
      `SELECT COUNT(*) as c FROM issuance_dossiers
       WHERE tenant_id = ? AND public_key_hash = ?`
    ).get(tenant.id, public_key_hash) as any
    if (velocityCheck.c > 1) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'issuance_velocity', 'warning',
          `pubkey ${public_key_hash.slice(0, 12)}... has ${velocityCheck.c} dossiers. Possible re-issuance.`)
      try { getEventBus().emit(tenant.id, { type: 'alert', data: { alert_type: 'issuance_velocity', severity: 'warning', public_key_hash } }) } catch {}
    }

    // Compute lineage links and cluster risk
    const dossierRow = db.prepare(
      `SELECT * FROM issuance_dossiers WHERE id = ?`
    ).get(id) as any
    const links = computeLineageLinks(dossierRow)
    const cluster = storeAndCluster(tenant.id, id, passport_id, links)

    res.status(201).json({
      dossier_id: id,
      passport_id,
      grade,
      cluster_risk: cluster.risk,
      cluster_size: cluster.clusterSize,
      stored: true,
    })
  } catch (e: any) {
    res.status(500).json(safeError(e, 'issuance-dossier'))
  }
})

// ═══════════════════════════════════════
// GET /api/v1/passport/:agentId/trust-profile
// The presentation query API. One call, one JSON, one decision.
// This is what Nik's service (and every partner) actually calls.
// ═══════════════════════════════════════
gatewayRouter.get('/passport/:agentId/trust-profile', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { agentId } = req.params

  // Agent existence
  const agent = db.prepare(
    `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any
  if (!agent) {
    return res.status(404).json({ error: `Unknown agent: ${agentId}`, grade: 0, trust: 'unknown' })
  }

  // Delegation (endorsement proxy)
  const delegation = db.prepare(
    `SELECT * FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
  ).get(tenant.id, agentId) as any

  // Wallet
  const wallet = db.prepare(
    `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any

  // Activity stats
  const evalCount = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c
  const receiptCount = (db.prepare(
    `SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c
  const deniedCount = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND verdict = 'DENY'`
  ).get(tenant.id, agentId) as any).c

  // Data contribution receipts
  const contributionReceipts = (db.prepare(
    `SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c

  // Wallet transaction stats
  const txCount = wallet ? (db.prepare(
    `SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ? AND from_agent_id = ?`
  ).get(tenant.id, agentId) as any).c : 0
  const walletDenied = wallet ? (db.prepare(
    `SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ? AND from_agent_id = ? AND status = 'denied'`
  ).get(tenant.id, agentId) as any).c : 0

  // Destination convergence (farming detector)
  // How many OTHER agents sent to the same top destination in 24h?
  let destinationRisk: 'low' | 'medium' | 'high' = 'low'
  let convergenceCount = 0
  if (wallet) {
    const topDest = db.prepare(
      `SELECT to_address, COUNT(*) as c FROM wallet_transactions
       WHERE tenant_id = ? AND from_agent_id = ? AND status = 'confirmed'
       GROUP BY to_address ORDER BY c DESC LIMIT 1`
    ).get(tenant.id, agentId) as any
    if (topDest) {
      const convergence = db.prepare(
        `SELECT COUNT(DISTINCT from_agent_id) as c FROM wallet_transactions
         WHERE tenant_id = ? AND to_address = ? AND from_agent_id != ?
         AND status = 'confirmed' AND created_at > datetime('now', '-24 hours')`
      ).get(tenant.id, topDest.to_address, agentId) as any
      convergenceCount = convergence.c
      if (convergenceCount >= 10) destinationRisk = 'high'
      else if (convergenceCount >= 3) destinationRisk = 'medium'
    }
  }

  // Issuance dossier (if MCP server has sent one)
  const dossier = db.prepare(
    `SELECT * FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenant.id, agentId) as any

  // Compute coarse grade (0-3)
  // If dossier exists, use its grade (computed by SDK with full evidence model).
  // Otherwise fall back to SQL-based heuristic.
  let grade = 0
  if (dossier) {
    grade = dossier.passport_grade
  } else {
    if (agent.status === 'active') grade = 1
    if (delegation) grade = 2
    if (delegation && evalCount >= 10 && receiptCount >= 5) grade = 3
  }

  // Age
  const createdAt = new Date(agent.created_at)
  const ageDays = Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24))

  res.json({
    agent_id: agentId,
    grade,
    trust: grade >= 3 ? 'established' : grade >= 2 ? 'endorsed' : grade >= 1 ? 'registered' : 'unknown',
    age_days: ageDays,
    has_delegation: !!delegation,
    has_wallet: !!wallet,
    activity: {
      evaluations: evalCount,
      receipts: receiptCount,
      denials: deniedCount,
      contribution_receipts: contributionReceipts,
    },
    wallet_activity: wallet ? {
      transactions: txCount,
      denied: walletDenied,
      status: wallet.status,
    } : null,
    risk: {
      destination_convergence: destinationRisk,
      convergent_agents_24h: convergenceCount,
      denial_rate: evalCount > 0 ? Math.round((deniedCount / evalCount) * 100) / 100 : 0,
      lineage_cluster: dossier ? getClusterRisk(tenant.id, agentId).risk : 'no_dossier',
    },
    attestation: dossier ? {
      grade_source: 'sdk',
      transport_type: dossier.transport_type,
      issuance_velocity: dossier.issuance_velocity,
      has_runtime_attestation: JSON.parse(dossier.runtime_attestations || '[]').length > 0,
      has_provider_attestation: JSON.parse(dossier.provider_attestations || '[]').length > 0,
      flags: JSON.parse(dossier.flags || '[]'),
      attestation_bundle_hash: dossier.attestation_bundle_hash,
      dossier_created_at: dossier.created_at,
    } : { grade_source: 'heuristic' },
    queried_at: new Date().toISOString(),
  })
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
  try { getEventBus().emit(tenant.id, { type: 'delegation_created', data: { delegation_id: id, parent_agent_id, child_agent_id, scope, spend_limit } }) } catch {}
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
    evaluation_receipts: (() => {
      const stats = db.prepare(`
        SELECT COUNT(*) as total,
               SUM(CASE WHEN verdict='permit' THEN 1 ELSE 0 END) as permits,
               SUM(CASE WHEN verdict='deny' THEN 1 ELSE 0 END) as denials
        FROM evaluation_receipts WHERE tenant_id = ?
      `).get(tenant.id) as any
      return { total: stats?.total || 0, permits: stats?.permits || 0, denials: stats?.denials || 0 }
    })(),
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

// ═══════════════════════════════════════
// DATA ATTRIBUTION (The Pixel)
// ═══════════════════════════════════════

// Purpose weight multipliers — how much more valuable each usage type is
const DEFAULT_PURPOSE_WEIGHTS: Record<string, number> = {
  read: 1,
  summary: 2,
  citation: 1.5,
  editorial_research: 1.5,
  rag: 5,
  rag_embedding: 5,
  embedding: 5,
  training: 10,
  fine_tune: 10,
}

function getPurposeWeight(purpose: string, terms: any): number {
  // Terms can override default weights via compensation.purpose_weights
  const custom = terms?.compensation?.purpose_weights
  if (custom && typeof custom === 'object' && custom[purpose] !== undefined) {
    return custom[purpose]
  }
  return DEFAULT_PURPOSE_WEIGHTS[purpose] || 1
}

// POST /api/v1/data-sources — Register a Data Source
gatewayRouter.post('/data-sources', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { source_id, source_name, source_url, data_terms, owner_agent_id } = req.body
  if (!source_id || !source_name) {
    return res.status(400).json({ error: 'Required: source_id, source_name' })
  }
  const db = getDB()
  const id = randomUUID()
  try {
    db.prepare(`INSERT INTO data_sources (id, tenant_id, source_id, source_name, source_url, data_terms, owner_agent_id) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(id, tenant.id, source_id, source_name, source_url || null, JSON.stringify(data_terms || {}), owner_agent_id || null)
    try { getEventBus().emit(tenant.id, { type: 'data_source_registered', data: { source_id, source_name, owner_agent_id } }) } catch {}
    res.status(201).json({ id, source_id, status: 'active' })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Source already registered' })
    return res.status(500).json(safeError(e, 'data-source-register'))
  }
})

// GET /api/v1/data-sources — List Data Sources
gatewayRouter.get('/data-sources', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const sources = db.prepare(`SELECT * FROM data_sources WHERE tenant_id = ? ORDER BY created_at DESC`).all(tenant.id)
  res.json({ sources, count: sources.length })
})

// POST /api/v1/access-receipts — Record Data Access
gatewayRouter.post('/access-receipts', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { source_id, agent_id, purpose, signature } = req.body
  if (!source_id || !agent_id) {
    return res.status(400).json({ error: 'Required: source_id, agent_id' })
  }
  const db = getDB()

  // Verify source exists
  const src = db.prepare(`SELECT * FROM data_sources WHERE tenant_id = ? AND source_id = ? AND status = 'active'`)
    .get(tenant.id, source_id) as any
  if (!src) return res.status(404).json({ error: `Data source "${source_id}" not found or revoked` })

  const id = randomUUID()
  db.prepare(`INSERT INTO access_receipts (id, tenant_id, source_id, agent_id, purpose, terms_snapshot, signature) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, source_id, agent_id, purpose || 'read', src.data_terms, signature || null)
  try { getEventBus().emit(tenant.id, { type: 'access_receipt', agentId: agent_id, data: { source_id, purpose: purpose || 'read' } }) } catch {}

  // Upsert contribution ledger (purpose-weighted)
  const terms = JSON.parse(src.data_terms || '{}')
  const baseRate = terms?.compensation?.rate || 0
  const weight = getPurposeWeight(purpose || 'read', terms)
  const effectiveRate = baseRate * weight
  // Atomic upsert — no TOCTOU race on concurrent access receipts
  db.prepare(`INSERT INTO contributions (id, tenant_id, source_id, agent_id, access_count, amount, currency)
    VALUES (?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(tenant_id, source_id, agent_id)
    DO UPDATE SET access_count = access_count + 1, amount = amount + ?, updated_at = datetime('now')`)
    .run(randomUUID(), tenant.id, source_id, agent_id, effectiveRate,
      terms?.compensation?.currency || 'usd', effectiveRate)

  // ── Attribution Alerts (fire-and-forget) ──
  try {
    // Alert: high access rate (>50 in last hour from same agent)
    const hourAgo = new Date(Date.now() - 3600_000).toISOString().replace('T', ' ').slice(0, 19)
    const recentCount = db.prepare(
      `SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND created_at > ?`
    ).get(tenant.id, agent_id, hourAgo) as any
    if (recentCount.c > 50 && recentCount.c % 50 === 1) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'high_access_rate', 'warning',
          `Agent "${agent_id}" made ${recentCount.c} data accesses in the last hour`)
      try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'high_access_rate', severity: 'warning', count: recentCount.c } }) } catch {}
    }
    // Alert: training/fine-tune purpose (always notify — high-value event)
    if (purpose === 'training' || purpose === 'fine_tune') {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'training_access', 'info',
          `Agent "${agent_id}" accessed "${source_id}" for ${purpose} (${weight}x rate)`)
      try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'training_access', severity: 'info', source_id, purpose } }) } catch {}
    }
    // Alert: new agent first seen
    const agentHistory = db.prepare(
      `SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND id != ?`
    ).get(tenant.id, agent_id, id) as any
    if (agentHistory.c === 0) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'new_consumer', 'info',
          `New agent "${agent_id}" first accessed your data (source: "${source_id}", purpose: ${purpose || 'read'})`)
      try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'new_consumer', severity: 'info', source_id } }) } catch {}
    }
  } catch (_) { /* alerts are non-critical */ }

  res.status(201).json({ receipt_id: id, source_id, agent_id, purpose: purpose || 'read', weight, effective_rate: effectiveRate })
})

// GET /api/v1/attribution — Attribution Dashboard
gatewayRouter.get('/attribution', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()

  const sources = db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
  const totalAccess = db.prepare(`SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ?`).get(tenant.id) as any
  const uniqueAgents = db.prepare(`SELECT COUNT(DISTINCT agent_id) as c FROM access_receipts WHERE tenant_id = ?`).get(tenant.id) as any
  const totalOwed = db.prepare(`SELECT COALESCE(SUM(amount), 0) as total FROM contributions WHERE tenant_id = ?`).get(tenant.id) as any
  const derivationCount = db.prepare(`SELECT COUNT(*) as c FROM derivations WHERE tenant_id = ?`).get(tenant.id) as any

  // Top sources by access count
  const topSources = db.prepare(`
    SELECT ds.source_name, ds.source_id,
      (SELECT COUNT(*) FROM access_receipts ar WHERE ar.tenant_id = ds.tenant_id AND ar.source_id = ds.source_id) as accesses,
      (SELECT COALESCE(SUM(c.amount), 0) FROM contributions c WHERE c.tenant_id = ds.tenant_id AND c.source_id = ds.source_id) as owed
    FROM data_sources ds
    WHERE ds.tenant_id = ?
    ORDER BY accesses DESC LIMIT 10
  `).all(tenant.id)

  // Top consumers
  const topAgents = db.prepare(`
    SELECT agent_id, SUM(access_count) as accesses, SUM(amount) as total_owed
    FROM contributions WHERE tenant_id = ?
    GROUP BY agent_id ORDER BY accesses DESC LIMIT 10
  `).all(tenant.id)

  // Recent access receipts
  const recentAccess = db.prepare(`
    SELECT ar.agent_id, ar.source_id, ar.purpose, ar.created_at
    FROM access_receipts ar WHERE ar.tenant_id = ?
    ORDER BY ar.created_at DESC LIMIT 20
  `).all(tenant.id)

  // Time series: accesses per day (last 30 days)
  const timeSeries = db.prepare(`
    SELECT DATE(created_at) as day, COUNT(*) as accesses, COUNT(DISTINCT agent_id) as agents
    FROM access_receipts WHERE tenant_id = ? AND created_at > datetime('now', '-30 days')
    GROUP BY DATE(created_at) ORDER BY day ASC
  `).all(tenant.id)

  // Purpose breakdown
  const purposeBreakdown = db.prepare(`
    SELECT purpose, COUNT(*) as count FROM access_receipts WHERE tenant_id = ?
    GROUP BY purpose ORDER BY count DESC
  `).all(tenant.id)

  res.json({
    summary: {
      data_sources: sources.c,
      total_accesses: totalAccess.c,
      unique_agents: uniqueAgents.c,
      total_owed: Math.round(totalOwed.total * 10000) / 10000,
      derivations_declared: derivationCount.c,
    },
    top_sources: topSources,
    top_agents: topAgents,
    recent_access: recentAccess,
    time_series: timeSeries,
    purpose_breakdown: purposeBreakdown,
  })
})

// POST /api/v1/settlements — Generate Settlement
gatewayRouter.post('/settlements', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { period_start, period_end } = req.body
  if (!period_start || !period_end) {
    return res.status(400).json({ error: 'Required: period_start, period_end' })
  }
  const db = getDB()
  const contributions = db.prepare(`SELECT * FROM contributions WHERE tenant_id = ? AND amount > 0`).all(tenant.id) as any[]
  if (contributions.length === 0) {
    return res.status(404).json({ error: 'No contributions to settle' })
  }
  const lineItems = contributions.map((c: any) => ({
    source_id: c.source_id, agent_id: c.agent_id,
    accesses: c.access_count, amount: c.amount, currency: c.currency,
  }))
  const total = contributions.reduce((s: number, c: any) => s + c.amount, 0)
  const id = randomUUID()
  db.prepare(`INSERT INTO settlements (id, tenant_id, period_start, period_end, total_amount, line_items) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, period_start, period_end, total, JSON.stringify(lineItems))
  try { getEventBus().emit(tenant.id, { type: 'settlement_created', data: { settlement_id: id, period_start, period_end, total_amount: total, line_items_count: lineItems.length } }) } catch {}
  res.status(201).json({ settlement_id: id, period_start, period_end, total_amount: Math.round(total * 10000) / 10000, line_items: lineItems.length })
})

// GET /api/v1/settlements — List Settlements
gatewayRouter.get('/settlements', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const settlements = db.prepare(`SELECT id, period_start, period_end, total_amount, created_at FROM settlements WHERE tenant_id = ? ORDER BY created_at DESC`).all(tenant.id)
  res.json({ settlements, count: settlements.length })
})

// ═══════════════════════════════════════
// AGENT SELF-SERVICE (transparency — agents audit their own usage)
// ═══════════════════════════════════════

// GET /api/v1/my-consumption?agent_id=X — Agent views what they've consumed
gatewayRouter.get('/my-consumption', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const agent_id = req.query.agent_id as string
  if (!agent_id) {
    return res.status(400).json({ error: 'Required query param: agent_id' })
  }
  const db = getDB()

  // What sources this agent has accessed
  const sources = db.prepare(`
    SELECT source_id, purpose, COUNT(*) as accesses, MIN(created_at) as first_access, MAX(created_at) as last_access
    FROM access_receipts WHERE tenant_id = ? AND agent_id = ?
    GROUP BY source_id, purpose ORDER BY accesses DESC
  `).all(tenant.id, agent_id)

  // What this agent owes
  const contributions = db.prepare(`
    SELECT source_id, access_count, amount, currency, updated_at
    FROM contributions WHERE tenant_id = ? AND agent_id = ?
    ORDER BY amount DESC
  `).all(tenant.id, agent_id)

  const totalOwed: number = (contributions as any[]).reduce((s: number, c: any) => s + (c.amount || 0), 0)
  const totalAccesses: number = (sources as any[]).reduce((s: number, r: any) => s + r.accesses, 0)

  // Terms the agent should be aware of
  const sourceTerms = db.prepare(`
    SELECT source_id, source_name, data_terms FROM data_sources
    WHERE tenant_id = ? AND source_id IN (SELECT DISTINCT source_id FROM access_receipts WHERE tenant_id = ? AND agent_id = ?)
  `).all(tenant.id, tenant.id, agent_id)

  res.json({
    agent_id,
    summary: {
      total_accesses: totalAccesses,
      unique_sources: new Set((sources as any[]).map((s: any) => s.source_id)).size,
      total_owed: Math.round(totalOwed * 10000) / 10000,
    },
    access_by_source: sources,
    contributions,
    source_terms: sourceTerms.map((s: any) => ({
      source_id: s.source_id,
      source_name: s.source_name,
      terms: JSON.parse(s.data_terms || '{}'),
    })),
  })
})

// ═══════════════════════════════════════
// DERIVATIONS (agent-declared usage chain)
// ═══════════════════════════════════════

// POST /api/v1/derivations — Agent declares "I used these sources to produce this output"
gatewayRouter.post('/derivations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, source_ids, output_description, output_url, signature } = req.body
  if (!agent_id || !source_ids || !Array.isArray(source_ids) || source_ids.length === 0) {
    return res.status(400).json({ error: 'Required: agent_id, source_ids (array of source_id strings)' })
  }
  const db = getDB()
  const placeholders = source_ids.map(() => '?').join(',')
  const receipts = db.prepare(
    `SELECT id, source_id FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND source_id IN (${placeholders})`
  ).all(tenant.id, agent_id, ...source_ids) as any[]
  const id = randomUUID()
  db.prepare(`INSERT INTO derivations (id, tenant_id, agent_id, source_ids, output_description, output_url, access_receipt_ids, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, agent_id, JSON.stringify(source_ids), output_description || null, output_url || null, JSON.stringify(receipts.map((r: any) => r.id)), signature || null)
  try { getEventBus().emit(tenant.id, { type: 'derivation_created', agentId: agent_id, data: { derivation_id: id, source_count: source_ids.length } }) } catch {}
  db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenant.id, 'derivation_declared', 'info',
      `Agent "${agent_id}" declared usage of ${source_ids.length} source(s) for "${output_description || output_url || 'undescribed'}"`)
  try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'derivation_declared', severity: 'info' } }) } catch {}
  res.status(201).json({
    derivation_id: id, agent_id,
    sources_declared: source_ids.length,
    access_receipts_linked: receipts.length,
    coverage: source_ids.length > 0 ? Math.round((receipts.length / source_ids.length) * 100) + '%' : '0%',
  })
})

// GET /api/v1/derivations — List derivation declarations
gatewayRouter.get('/derivations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const agent = req.query.agent_id as string
  let query = `SELECT * FROM derivations WHERE tenant_id = ?`
  const params: any[] = [tenant.id]
  if (agent) { query += ` AND agent_id = ?`; params.push(agent) }
  query += ` ORDER BY created_at DESC LIMIT 50`
  const rows = db.prepare(query).all(...params)
  res.json({ derivations: (rows as any[]).map((d: any) => ({
    ...d, source_ids: JSON.parse(d.source_ids || '[]'), access_receipt_ids: JSON.parse(d.access_receipt_ids || '[]'),
  })), count: rows.length })
})


// POST /api/v1/reset-attribution — Clear all demo/test attribution data
gatewayRouter.post('/reset-attribution', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const ar = db.prepare(`DELETE FROM access_receipts WHERE tenant_id = ?`).run(tenant.id)
  const co = db.prepare(`DELETE FROM contributions WHERE tenant_id = ?`).run(tenant.id)
  const ds = db.prepare(`DELETE FROM data_sources WHERE tenant_id = ?`).run(tenant.id)
  const st = db.prepare(`DELETE FROM settlements WHERE tenant_id = ?`).run(tenant.id)
  const dv = db.prepare(`DELETE FROM derivations WHERE tenant_id = ?`).run(tenant.id)
  const al = db.prepare(`DELETE FROM alerts WHERE tenant_id = ?`).run(tenant.id)
  res.json({
    cleared: {
      access_receipts: ar.changes,
      contributions: co.changes,
      data_sources: ds.changes,
      settlements: st.changes,
      derivations: dv.changes,
      alerts: al.changes,
    },
    message: 'Attribution data cleared. Real data will flow once MCP tracking is live.',
  })
})


// POST /api/v1/compare-texts — Lexical similarity score (TF-IDF)
// The honest attribution signal: 80% accurate on hard negatives.
// Not derivation proof — lexical forensic evidence.
gatewayRouter.post('/compare-texts', (req: any, res) => {
  const { source_text, output_text, method } = req.body
  if (!source_text || !output_text) {
    return res.status(400).json({ error: 'Required: source_text, output_text' })
  }
  // Pluggable backend (future: bm25, custom). Default: tfidf/ngram_jaccard
  const lex = computeLexicalScore(source_text, output_text)
  res.json({
    method: method || 'ngram_jaccard',
    similarity_score: lex.score, detail: lex.detail, interpretation: lex.verdict,
    note: 'Lexical forensic evidence. Not derivation proof. Combine with access receipts and temporal ordering.',
  })
})


// ═══════════════════════════════════════════════════════════════
// VERIFIED SELF-DECLARATION (the core innovation)
// Agent declares sources, gateway verifies plausibility
// ═══════════════════════════════════════════════════════════════

gatewayRouter.post('/verify-declaration', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, output_text, declared_sources, output_url } = req.body

  if (!agent_id || !output_text || !declared_sources || !Array.isArray(declared_sources) || declared_sources.length === 0) {
    return res.status(400).json({ error: 'Required: agent_id, output_text, declared_sources (array of source_id strings)' })
  }

  const db = getDB()
  const id = randomUUID()

  // 1. Check access receipts for each declared source
  const receiptCheck = declared_sources.map((sourceId: string) => {
    const receipts = db.prepare(
      `SELECT id, created_at, purpose FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND source_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agent_id, sourceId) as any
    return { source_id: sourceId, receipt_exists: !!receipts, last_access: receipts?.created_at || null, purpose: receipts?.purpose || null }
  })


  // 2. Fetch source texts for lexical comparison
  const plausibility = receiptCheck.map((rc: any) => {
    const src = db.prepare(
      `SELECT source_name, source_url FROM data_sources WHERE tenant_id = ? AND source_id = ?`
    ).get(tenant.id, rc.source_id) as any

    // If source has stored text (via source_url or name), compute lexical overlap
    // For now, store the declaration and flag based on receipt status
    let lexical = null as any
    // Check if source content was provided inline
    const sourceContent = (req.body.source_texts || {})[rc.source_id]
    if (sourceContent) {
      lexical = computeLexicalScore(sourceContent, output_text)
    }

    // Classify evidence
    let evidence_class: string
    if (rc.receipt_exists && lexical && (lexical.verdict === 'high_overlap' || lexical.verdict === 'moderate_overlap')) {
      evidence_class = 'supported_usage'
    } else if (rc.receipt_exists && (!lexical || lexical.verdict === 'low_overlap')) {
      evidence_class = 'access_without_surface_carryover'
    } else if (!rc.receipt_exists && lexical && lexical.verdict !== 'low_overlap') {
      evidence_class = 'untracked_overlap'
    } else {
      evidence_class = 'no_observed_linkage'
    }


    let verdict: string
    if (rc.receipt_exists && (!lexical || lexical.score >= 0.05)) {
      verdict = 'plausible'
    } else if (!rc.receipt_exists) {
      verdict = 'no_receipt'
    } else if (lexical && lexical.score < 0.02) {
      verdict = 'implausible'
    } else {
      verdict = 'weak'
    }

    return {
      source_id: rc.source_id, source_name: src?.source_name || null,
      receipt_exists: rc.receipt_exists, last_access: rc.last_access, purpose: rc.purpose,
      lexical: lexical ? { score: lexical.score, detail: lexical.detail, verdict: lexical.verdict } : null,
      evidence_class, verdict,
    }
  })


  // 3. Generate flags
  const flags: string[] = []
  for (const p of plausibility) {
    if (p.verdict === 'implausible') flags.push(`Declared source ${p.source_id} shows near-zero lexical overlap with output`)
    if (p.verdict === 'no_receipt') flags.push(`No access receipt found for declared source ${p.source_id}`)
    if (p.evidence_class === 'untracked_overlap') flags.push(`High overlap with ${p.source_id} but no access receipt — possible untracked reuse`)
  }

  // 4. Check for undeclared sources with high overlap (if source_texts provided)
  const sources_accessed = db.prepare(
    `SELECT DISTINCT source_id FROM access_receipts WHERE tenant_id = ? AND agent_id = ?`
  ).all(tenant.id, agent_id) as any[]

  const declared_set = new Set(declared_sources)
  const sources_accessed_but_not_declared: string[] = []
  for (const sa of sources_accessed) {
    if (!declared_set.has(sa.source_id)) sources_accessed_but_not_declared.push(sa.source_id)
  }
  if (sources_accessed_but_not_declared.length > 0) {
    flags.push(`Agent accessed ${sources_accessed_but_not_declared.length} source(s) not included in declaration`)
  }


  // 5. Store the verified declaration as a derivation
  db.prepare(`INSERT INTO derivations (id, tenant_id, agent_id, source_ids, output_description, output_url, access_receipt_ids, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, agent_id, JSON.stringify(declared_sources), 'verified-declaration', output_url || null, JSON.stringify([]), 'gateway-verified')
  try { getEventBus().emit(tenant.id, { type: 'derivation_created', agentId: agent_id, data: { derivation_id: id, verified: true, source_count: declared_sources.length } }) } catch {}

  // 6. Fire alerts for anomalies
  if (flags.length > 0) {
    const anomalySeverity = flags.some(f => f.includes('untracked')) ? 'warning' : 'info'
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenant.id, 'declaration_anomaly', anomalySeverity,
        `Declaration from "${agent_id}": ${flags.join('; ')}`)
    try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'declaration_anomaly', severity: anomalySeverity, flags } }) } catch {}
  }

  // 7. Coverage scope
  const total_sources = (db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ?`).get(tenant.id) as any).c
  const total_receipts = (db.prepare(`SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agent_id) as any).c

  res.status(201).json({
    declaration_id: id, agent_id,
    plausibility,
    flags,
    sources_accessed_but_not_declared,
    coverage: {
      scope: 'gateway_tracked_only',
      registered_sources: total_sources,
      agent_total_accesses: total_receipts,
      note: 'No receipt does not prove no access. Coverage limited to gateway-tracked interactions.',
    },
    evidence_limits: 'Lexical overlap is forensic evidence, not derivation proof. Combined with receipts and temporal ordering for multi-factor attribution.',
  })
})


// ═══════════════════════════════════════════════════════════════
// PROVENANCE DOSSIER — full evidence bundle for an agent's outputs
// ═══════════════════════════════════════════════════════════════

gatewayRouter.get('/provenance-dossier', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const agent_id = req.query.agent_id as string
  if (!agent_id) return res.status(400).json({ error: 'Required: agent_id query parameter' })

  const db = getDB()

  // All access receipts for this agent
  const receipts = db.prepare(
    `SELECT ar.id, ar.source_id, ar.agent_id, ar.purpose, ar.created_at, ds.source_name
     FROM access_receipts ar LEFT JOIN data_sources ds ON ar.source_id = ds.source_id AND ar.tenant_id = ds.tenant_id
     WHERE ar.tenant_id = ? AND ar.agent_id = ? ORDER BY ar.created_at DESC LIMIT 100`
  ).all(tenant.id, agent_id) as any[]

  // All derivation declarations
  const derivations = db.prepare(
    `SELECT * FROM derivations WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 50`
  ).all(tenant.id, agent_id) as any[]


  // Contributions owed
  const contributions = db.prepare(
    `SELECT source_id, access_count, amount, currency, updated_at FROM contributions WHERE tenant_id = ? AND agent_id = ?`
  ).all(tenant.id, agent_id) as any[]

  // Source access frequency (longitudinal pattern)
  const sourceFrequency = db.prepare(
    `SELECT source_id, COUNT(*) as accesses, MIN(created_at) as first_access, MAX(created_at) as last_access,
     COUNT(DISTINCT date(created_at)) as distinct_days
     FROM access_receipts WHERE tenant_id = ? AND agent_id = ? GROUP BY source_id ORDER BY accesses DESC`
  ).all(tenant.id, agent_id) as any[]

  // Purpose breakdown
  const purposes = db.prepare(
    `SELECT purpose, COUNT(*) as count FROM access_receipts WHERE tenant_id = ? AND agent_id = ? GROUP BY purpose`
  ).all(tenant.id, agent_id) as any[]

  // Sources accessed but never declared
  const declared_source_ids = new Set<string>()
  for (const d of derivations) {
    for (const sid of JSON.parse(d.source_ids || '[]')) declared_source_ids.add(sid)
  }
  const accessed_source_ids = new Set(receipts.map((r: any) => r.source_id))
  const accessed_not_declared = [...accessed_source_ids].filter(s => !declared_source_ids.has(s))


  // Classify longitudinal patterns
  const patterns: string[] = []
  for (const sf of sourceFrequency) {
    if (sf.distinct_days >= 5) patterns.push(`habitual_consumer: ${sf.source_id} (${sf.accesses} accesses over ${sf.distinct_days} days)`)
    else if (sf.accesses >= 10) patterns.push(`heavy_consumer: ${sf.source_id} (${sf.accesses} accesses)`)
  }
  if (accessed_not_declared.length > 3) patterns.push(`low_declaration_rate: ${accessed_not_declared.length} sources accessed but never declared`)

  // Coverage
  const total_sources = (db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ?`).get(tenant.id) as any).c

  res.json({
    agent_id,
    generated_at: new Date().toISOString(),
    evidence: {
      access_receipts: { count: receipts.length, items: receipts.slice(0, 20) },
      declarations: { count: derivations.length, items: (derivations as any[]).map((d: any) => ({ ...d, source_ids: JSON.parse(d.source_ids || '[]') })).slice(0, 10) },
      contributions: { total_owed: Math.round(contributions.reduce((s: number, c: any) => s + (c.amount || 0), 0) * 10000) / 10000, items: contributions },
      purpose_breakdown: purposes,
      source_frequency: sourceFrequency,
      longitudinal_patterns: patterns,
    },
    negative_evidence: {
      sources_accessed_but_not_declared: accessed_not_declared,
      declaration_coverage: `${declared_source_ids.size} declared / ${accessed_source_ids.size} accessed`,
    },
    coverage: {
      scope: 'gateway_tracked_only',
      registered_sources: total_sources,
      note: 'This dossier covers gateway-tracked interactions only. Absence of a receipt does not prove absence of access.',
    },
    evidence_limits: 'This is a structured evidentiary record that may support audit, compliance, contractual enforcement, or legal review depending on jurisdiction and context. It does not constitute a legal determination of derivation or infringement.',
  })
})


// ═══════════════════════════════════════
// POST /api/v1/issuance-dossier
// Receives IssuanceContext from MCP server after every passport issuance.
// Fire-and-forget from MCP side — this endpoint stores the full evidence dossier.
// ═══════════════════════════════════════
gatewayRouter.post('/issuance-dossier', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const {
    passport_id, public_key_hash, passport_grade, flags,
    attestation_bundle_hash, observed_context,
    runtime_attestations, provider_attestations,
    self_declared_signals, derived_signals, prior_passport_ref,
  } = req.body

  if (!passport_id || !public_key_hash) {
    return res.status(400).json({ error: 'Required: passport_id, public_key_hash' })
  }

  const id = randomUUID()
  const obs = observed_context || {}

  try {
    db.prepare(`INSERT INTO issuance_dossiers
      (id, tenant_id, passport_id, public_key_hash, passport_grade,
       flags, attestation_bundle_hash, observed_context,
       runtime_attestations, provider_attestations,
       self_declared_signals, derived_signals, prior_passport_ref,
       transport_type, issuance_velocity, connection_timing_ms,
       request_payload_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        id, tenant.id, passport_id, public_key_hash,
        passport_grade || 0,
        JSON.stringify(flags || []),
        attestation_bundle_hash || null,
        JSON.stringify(obs),
        JSON.stringify(runtime_attestations || []),
        JSON.stringify(provider_attestations || []),
        JSON.stringify(self_declared_signals || []),
        JSON.stringify(derived_signals || []),
        prior_passport_ref || null,
        obs.transportType || null,
        obs.issuanceVelocity || null,
        obs.connectionTimingMs || null,
        obs.requestPayloadFingerprint || null,
      )

    // Velocity anomaly: if same public_key_hash issued 5+ passports in 1 hour
    const recentFromKey = db.prepare(
      `SELECT COUNT(*) as c FROM issuance_dossiers
       WHERE public_key_hash = ? AND created_at > datetime('now', '-1 hour')`
    ).get(public_key_hash) as any
    if (recentFromKey.c >= 5) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'sybil_issuance_velocity', 'critical',
          `Key ${public_key_hash.slice(0, 16)}... issued ${recentFromKey.c} passports in 1hr`)
    }

    // Fingerprint clustering: if same request_payload_fingerprint from 10+ different keys
    if (obs.requestPayloadFingerprint) {
      const fpCluster = db.prepare(
        `SELECT COUNT(DISTINCT public_key_hash) as c FROM issuance_dossiers
         WHERE request_payload_fingerprint = ? AND created_at > datetime('now', '-24 hours')`
      ).get(obs.requestPayloadFingerprint) as any
      if (fpCluster.c >= 10) {
        db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
          VALUES (?, ?, ?, ?, ?)`)
          .run(randomUUID(), tenant.id, 'sybil_fingerprint_cluster', 'critical',
            `Payload fingerprint ${obs.requestPayloadFingerprint.slice(0, 16)}... seen from ${fpCluster.c} distinct keys in 24h — farming script?`)
      }
    }

    res.status(201).json({
      dossier_id: id,
      passport_id,
      passport_grade: passport_grade || 0,
      stored: true,
    })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE constraint')) {
      // Update existing dossier (passport reissued)
      db.prepare(`UPDATE issuance_dossiers SET
        passport_grade = ?, flags = ?, attestation_bundle_hash = ?,
        observed_context = ?, runtime_attestations = ?,
        provider_attestations = ?, self_declared_signals = ?,
        derived_signals = ?
        WHERE tenant_id = ? AND passport_id = ?`)
        .run(
          passport_grade || 0, JSON.stringify(flags || []),
          attestation_bundle_hash || null, JSON.stringify(obs),
          JSON.stringify(runtime_attestations || []),
          JSON.stringify(provider_attestations || []),
          JSON.stringify(self_declared_signals || []),
          JSON.stringify(derived_signals || []),
          tenant.id, passport_id,
        )
      return res.json({ passport_id, updated: true })
    }
    res.status(500).json(safeError(e, 'behavioral-sequence'))
  }
})

// ═══════════════════════════════════════
// Evaluation Receipts — authenticated endpoints
// ═══════════════════════════════════════

// GET /api/v1/receipts/:agentId — all receipts for an agent (paginated)
gatewayRouter.get('/receipts/:agentId', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const limit = Math.min(parseInt(req.query.limit || '50'), 100)
  const offset = parseInt(req.query.offset || '0')
  const db = getDB()

  const rows = db.prepare(
    `SELECT * FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(tenant.id, agentId, limit, offset)
  const total = (db.prepare(
    `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c

  res.json({ receipts: rows, total, limit, offset })
})

// GET /api/v1/receipts/:agentId/denials — denial receipts only (proof of restraint)
gatewayRouter.get('/receipts/:agentId/denials', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const limit = Math.min(parseInt(req.query.limit || '50'), 100)
  const offset = parseInt(req.query.offset || '0')
  const db = getDB()

  const rows = db.prepare(
    `SELECT * FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny' ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(tenant.id, agentId, limit, offset)
  const total = (db.prepare(
    `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny'`
  ).get(tenant.id, agentId) as any).c

  res.json({ denials: rows, total, limit, offset })
})

// ═══════════════════════════════════════
// Receipt Window Seals — sealed intervals with gateway signatures
// Sorted-hash commitment (Option A). Upgrade to full Merkle when
// inclusion proofs are needed.
// ═══════════════════════════════════════

let _receiptsSinceLastSeal = 0

function sealReceiptWindow() {
  try {
    const db = getDB()
    const unsealed = db.prepare(
      'SELECT id, receipt_hash FROM evaluation_receipts WHERE seal_id IS NULL ORDER BY id'
    ).all() as Array<{ id: number; receipt_hash: string }>

    if (unsealed.length < 10) return // minimum batch size

    const seqStart = unsealed[0].id
    const seqEnd = unsealed[unsealed.length - 1].id
    const sealId = randomUUID()

    // Option A: sorted-hash commitment (receipts already in ID order)
    const sortedHashes = unsealed.map(r => r.receipt_hash || '').join('')
    const commitmentHash = createHash('sha256').update(sortedHashes).digest('hex')

    // Count permits/denials
    const counts = db.prepare(
      `SELECT verdict, COUNT(*) as c FROM evaluation_receipts WHERE id >= ? AND id <= ? GROUP BY verdict`
    ).all(seqStart, seqEnd) as Array<{ verdict: string; c: number }>
    const permitCount = counts.find(c => c.verdict === 'permit')?.c || 0
    const denyCount = counts.find(c => c.verdict === 'deny')?.c || 0

    const identity = getGatewayIdentity()
    const sig = identity.sign({
      seal_id: sealId, seq_start: seqStart, seq_end: seqEnd,
      receipt_count: unsealed.length, commitment_hash: commitmentHash,
    })

    // Atomic: insert seal + update receipts
    const txn = db.transaction(() => {
      db.prepare(`
        INSERT INTO receipt_window_seals (
          seal_id, seq_start, seq_end, receipt_count, permit_count, deny_count,
          commitment_hash, gateway_signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(sealId, seqStart, seqEnd, unsealed.length, permitCount, denyCount, commitmentHash, sig)

      db.prepare('UPDATE evaluation_receipts SET seal_id = ? WHERE id >= ? AND id <= ?')
        .run(sealId, seqStart, seqEnd)
    })
    txn()

    _receiptsSinceLastSeal = 0
    console.log(`[seal] Sealed window ${seqStart}-${seqEnd}: ${unsealed.length} receipts, hash=${commitmentHash.slice(0, 16)}`)
  } catch (e: any) {
    console.error('[seal] FAILED:', e.message)
  }
}

// Seal every hour
setInterval(sealReceiptWindow, 3600_000)
// Seal on startup (catch unsealed receipts from before crash)
setTimeout(sealReceiptWindow, 5000)

function maybeAutoSeal() {
  _receiptsSinceLastSeal++
  if (_receiptsSinceLastSeal >= 100) {
    sealReceiptWindow()
  }
}

// GET /api/v1/receipt-seals — list all seals (authenticated)
gatewayRouter.get('/receipt-seals', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const limit = Math.min(parseInt(req.query.limit || '50'), 100)
  const offset = parseInt(req.query.offset || '0')
  const db = getDB()

  const seals = db.prepare(
    `SELECT seal_id, seq_start, seq_end, receipt_count, permit_count, deny_count,
            commitment_hash, scope_note, created_at
     FROM receipt_window_seals ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(limit, offset)
  const total = (db.prepare('SELECT COUNT(*) as c FROM receipt_window_seals').get() as any).c

  res.json({ seals, total, limit, offset })
})

// GET /api/v1/receipt-seals/:sealId — seal details + receipt hashes (authenticated)
gatewayRouter.get('/receipt-seals/:sealId', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { sealId } = req.params
  const db = getDB()

  const seal = db.prepare('SELECT * FROM receipt_window_seals WHERE seal_id = ?').get(sealId) as any
  if (!seal) return res.status(404).json({ error: 'Seal not found' })

  const receipts = db.prepare(
    'SELECT id, receipt_hash, verdict, agent_id, action_type FROM evaluation_receipts WHERE seal_id = ? ORDER BY id'
  ).all(sealId)

  // Verification: recompute commitment
  const recomputedHash = createHash('sha256')
    .update(receipts.map((r: any) => r.receipt_hash || '').join(''))
    .digest('hex')

  res.json({
    seal,
    receipts,
    verification: {
      commitment_matches: recomputedHash === seal.commitment_hash,
      recomputed_hash: recomputedHash,
      kid: 'gateway-v1',
      alg: 'EdDSA',
      jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
    },
  })
})

// ═══════════════════════════════════════
// Agent Posture Overlay — suspend/restrict with audit trail
// ═══════════════════════════════════════

// POST /api/v1/agents/:agentId/posture — change agent operational posture
gatewayRouter.post('/agents/:agentId/posture', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const { status, reason, restricted_scopes } = req.body

  if (!status || !reason) {
    return res.status(400).json({ error: 'Required: status, reason' })
  }
  if (!['active', 'restricted', 'suspended'].includes(status)) {
    return res.status(400).json({ error: 'status must be active, restricted, or suspended' })
  }
  if (status === 'restricted' && !restricted_scopes) {
    return res.status(400).json({ error: 'restricted status requires restricted_scopes array' })
  }

  const db = getDB()
  const agent = db.prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
    .get(tenant.id, agentId) as any
  if (!agent) return res.status(404).json({ error: 'Agent not found' })

  const oldStatus = agent.status || 'active'
  const now = new Date().toISOString()
  const scopesJson = restricted_scopes ? JSON.stringify(restricted_scopes) : null

  // Update agent status
  db.prepare(`UPDATE agents SET status = ?, restricted_scopes = ?, posture_reason = ?, posture_updated_at = ? WHERE tenant_id = ? AND agent_id = ?`)
    .run(status, status === 'restricted' ? scopesJson : null, reason, now, tenant.id, agentId)

  // Log posture event
  db.prepare(`INSERT INTO posture_events (tenant_id, agent_id, old_status, new_status, restricted_scopes, reason, changed_by) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(tenant.id, agentId, oldStatus, status, scopesJson, reason, tenant.id)
  try { getEventBus().emit(tenant.id, { type: 'posture_update', agentId, data: { old_status: oldStatus, new_status: status, reason, restricted_scopes: restricted_scopes || null } }) } catch {}

  res.json({ agent_id: agentId, old_status: oldStatus, new_status: status, reason, restricted_scopes: restricted_scopes || null, changed_at: now })
})

// GET /api/v1/agents/:agentId/posture-history — audit trail
gatewayRouter.get('/agents/:agentId/posture-history', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const db = getDB()

  const events = db.prepare(
    `SELECT * FROM posture_events WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC`
  ).all(tenant.id, agentId)

  res.json({ agent_id: agentId, events, count: events.length })
})

// ═══════════════════════════════════════
// Authorization Audit Packets
// One receipt → one exportable proof chain. The atom of compliance evidence.
// decision_record is signed (immutable). current_context is NOT signed (volatile).
// ═══════════════════════════════════════

gatewayRouter.get('/audit-packet/:receiptId', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const receiptId = parseInt(req.params.receiptId)
  if (!Number.isFinite(receiptId)) {
    return res.status(400).json({ error: 'Invalid receipt ID' })
  }

  const db = getDB()
  const receipt = db.prepare(
    `SELECT * FROM evaluation_receipts WHERE id = ? AND tenant_id = ?`
  ).get(receiptId, tenant.id) as any

  if (!receipt) {
    return res.status(404).json({ error: 'Receipt not found', receipt_id: receiptId })
  }

  const missing: string[] = []
  const notes: string[] = []

  // ── decision_record (frozen at decision time, signed) ──
  let scopeRequested: string[] = []
  try { scopeRequested = JSON.parse(receipt.scope_requested_json || '[]') } catch { scopeRequested = [] }

  // Look up agent grade at decision time (from dossier nearest to decision timestamp)
  let agentGradeAtDecision = 0
  try {
    const dossier = db.prepare(
      `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, receipt.agent_id) as any
    if (dossier) agentGradeAtDecision = dossier.passport_grade
  } catch { notes.push('dossier_lookup_failed') }

  // Delegation chain hash (recompute from delegation_id)
  let delegationChainHash: string | null = null
  if (receipt.delegation_id) {
    try {
      const chain: Array<{ parent: string; child: string; scope: string; spend_limit: number | null }> = []
      // Find the delegation to get the child agent
      const del = db.prepare(
        `SELECT parent_agent_id, child_agent_id, scope, spend_limit FROM delegations WHERE id = ? AND tenant_id = ?`
      ).get(receipt.delegation_id, tenant.id) as any
      if (del) {
        let currentChild: string | null = del.child_agent_id
        const seen = new Set<string>()
        while (currentChild && !seen.has(currentChild)) {
          seen.add(currentChild)
          const row = db.prepare(
            `SELECT parent_agent_id, child_agent_id, scope, spend_limit FROM delegations
             WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
             ORDER BY created_at DESC LIMIT 1`
          ).get(tenant.id, currentChild) as any
          if (!row) break
          chain.push({ parent: row.parent_agent_id, child: row.child_agent_id, scope: row.scope, spend_limit: row.spend_limit })
          currentChild = row.parent_agent_id
        }
        chain.reverse()
        delegationChainHash = createHash('sha256')
          .update(canonicalJsonStringify(chain))
          .digest('hex')
      }
    } catch { notes.push('delegation_chain_hash_failed') }
  }

  const decisionRecord: Record<string, unknown> = {
    receipt_id: receipt.id,
    event_type: receipt.event_type,
    action_type: receipt.action_type,
    scope_requested: scopeRequested,
    verdict: receipt.verdict,
    reason_code: receipt.reason_code || null,
    delegation_id: receipt.delegation_id || null,
    delegation_chain_hash: delegationChainHash,
    policy_hash: receipt.policy_hash,
    decision_timestamp: receipt.created_at,
    agent_id: receipt.agent_id,
    agent_grade_at_decision: agentGradeAtDecision,
  }

  // Sign the decision record (stable: same receipt always produces same signature)
  let gatewaySignature: string | null = null
  let kid = 'gateway-v1'
  try {
    const identity = getGatewayIdentity()
    kid = identity.kid
    gatewaySignature = identity.sign(decisionRecord)
  } catch { notes.push('signing_failed') }

  // ── current_context (queried now, NOT signed) ──
  let agentContext: Record<string, unknown> | null = null
  try {
    const agent = db.prepare(
      `SELECT status, created_at FROM agents WHERE tenant_id = ? AND agent_id = ? LIMIT 1`
    ).get(tenant.id, receipt.agent_id) as any
    if (agent) {
      let currentGrade = 0
      const dossier = db.prepare(
        `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
      ).get(tenant.id, receipt.agent_id) as any
      if (dossier) currentGrade = dossier.passport_grade

      agentContext = {
        status: agent.status,
        grade: currentGrade,
        created_at: agent.created_at,
      }
    } else {
      missing.push('agent')
    }
  } catch { missing.push('agent') }

  // Delegation chain (current state)
  let delegationChain: Array<Record<string, unknown>> = []
  let revocationState: Record<string, unknown> = {
    agent_revoked: false, delegation_revoked: false, any_ancestor_revoked: false,
  }
  try {
    const agent = db.prepare(
      `SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ? LIMIT 1`
    ).get(tenant.id, receipt.agent_id) as any
    if (agent?.status !== 'active') {
      revocationState = { ...revocationState, agent_revoked: true }
    }

    if (receipt.delegation_id) {
      const del = db.prepare(
        `SELECT * FROM delegations WHERE id = ? AND tenant_id = ?`
      ).get(receipt.delegation_id, tenant.id) as any
      if (del) {
        if (del.status !== 'active') {
          revocationState = { ...revocationState, delegation_revoked: true }
        }
        // Build chain
        let currentChild: string | null = del.child_agent_id
        const seen = new Set<string>()
        while (currentChild && !seen.has(currentChild)) {
          seen.add(currentChild)
          const row = db.prepare(
            `SELECT parent_agent_id, child_agent_id, scope, status FROM delegations
             WHERE tenant_id = ? AND child_agent_id = ?
             ORDER BY created_at DESC LIMIT 1`
          ).get(tenant.id, currentChild) as any
          if (!row) break
          const scopes = row.scope ? row.scope.split(',').map((s: string) => s.trim()) : []
          delegationChain.push({ parent: row.parent_agent_id, child: row.child_agent_id, scope: scopes, status: row.status })
          if (row.status !== 'active') {
            revocationState = { ...revocationState, any_ancestor_revoked: true }
          }
          currentChild = row.parent_agent_id
        }
        delegationChain.reverse()
      } else {
        missing.push('delegation')
      }
    }
  } catch { missing.push('delegation_chain') }

  const completenessLevel = missing.length === 0 ? 'full' : 'partial'

  const packet: Record<string, unknown> = {
    type: 'authorization_audit_packet',
    version: '1.0.0',
    decision_record: { ...decisionRecord, gateway_signature: gatewaySignature },
    current_context: {
      _note: 'Queried NOW. Not part of the signed proof. May change.',
      generated_at: new Date().toISOString(),
      agent: agentContext,
      delegation_chain: delegationChain,
      revocation_state: revocationState,
    },
    completeness: {
      level: completenessLevel,
      missing_sections: missing,
      notes,
    },
    verification: {
      kid,
      alg: 'EdDSA',
      jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
    },
  }

  // Markdown format option
  if (req.query.format === 'markdown') {
    const dr = decisionRecord
    const md = `# Authorization Audit Packet

## Decision Record (frozen at decision time, signed)

| Field | Value |
|---|---|
| Receipt ID | ${dr.receipt_id} |
| Event Type | ${dr.event_type} |
| Action Type | ${dr.action_type} |
| Scope Requested | ${(dr.scope_requested as string[]).join(', ')} |
| Verdict | **${dr.verdict}** |
| Reason Code | ${dr.reason_code || 'n/a'} |
| Delegation ID | ${dr.delegation_id || 'none'} |
| Delegation Chain Hash | \`${dr.delegation_chain_hash || 'none'}\` |
| Policy Hash | \`${dr.policy_hash}\` |
| Decision Timestamp | ${dr.decision_timestamp} |
| Agent ID | ${dr.agent_id} |
| Agent Grade at Decision | ${dr.agent_grade_at_decision} |

## Current Context (queried now, not signed)

**Agent:** ${agentContext ? `status=${(agentContext as any).status}, grade=${(agentContext as any).grade}` : 'not found'}

**Delegation Chain:** ${delegationChain.length > 0 ? delegationChain.map((d: any) => `${d.parent} → ${d.child} [${d.scope.join(',')}] (${d.status})`).join(' → ') : 'none'}

**Revocation State:** agent_revoked=${(revocationState as any).agent_revoked}, delegation_revoked=${(revocationState as any).delegation_revoked}, any_ancestor_revoked=${(revocationState as any).any_ancestor_revoked}

## Completeness

Level: **${completenessLevel}**${missing.length > 0 ? `\nMissing: ${missing.join(', ')}` : ''}

## Verification

- **kid:** ${kid}
- **alg:** EdDSA
- **JWKS:** https://gateway.aeoess.com/.well-known/jwks.json
- **Decision Record Hash:** \`${createHash('sha256').update(canonicalJsonStringify(decisionRecord)).digest('hex')}\`
- **Gateway Signature:** \`${gatewaySignature ? gatewaySignature.slice(0, 40) + '...' : 'none'}\`
`
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8')
    return res.send(md)
  }

  res.json(packet)
})

// ═══════════════════════════════════════
// Full Governance Evidence Export — 9 sections, single signed artifact
// NOT a compliance report (no GDPR/EU AI Act article mapping).
// Proves what was AUTHORIZED and what constraints applied.
// ═══════════════════════════════════════

gatewayRouter.get('/governance/export', (req: any, res) => {
  try {
    const tenant = req.tenant as Tenant
    const db = getDB()
    const now = new Date().toISOString()
    const since = (req.query.since as string) || '2020-01-01T00:00:00Z'
    const until = (req.query.until as string) || now
    const agentFilter = req.query.agent_id as string | undefined

    // ── 1: Agent Registry (snapshot) ──
    const agentRows = db.prepare(
      agentFilter
        ? `SELECT agent_id, status, created_at FROM agents WHERE tenant_id = ? AND agent_id = ?`
        : `SELECT agent_id, status, created_at FROM agents WHERE tenant_id = ?`
    ).all(...(agentFilter ? [tenant.id, agentFilter] : [tenant.id])) as any[]

    const byStatus: Record<string, number> = {}
    for (const a of agentRows) byStatus[a.status || 'active'] = (byStatus[a.status || 'active'] || 0) + 1

    // Grade lookup
    const agentsWithGrade = agentRows.map((a: any) => {
      const dossier = db.prepare(
        `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
      ).get(tenant.id, a.agent_id) as any
      const grade = dossier?.passport_grade ?? 0
      const hasDel = !!(db.prepare(
        `SELECT 1 FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' LIMIT 1`
      ).get(tenant.id, a.agent_id))
      return { agent_id: a.agent_id, grade, grade_label: ['unknown','registered','endorsed','established'][grade] || 'unknown', status: a.status || 'active', has_delegation: hasDel, created_at: a.created_at }
    })

    const byGrade: Record<string, number> = {}
    for (const a of agentsWithGrade) byGrade[String(a.grade)] = (byGrade[String(a.grade)] || 0) + 1

    // ── 2: Delegation Inventory (snapshot) ──
    const delQuery = agentFilter
      ? `SELECT * FROM delegations WHERE tenant_id = ? AND (parent_agent_id = ? OR child_agent_id = ?)`
      : `SELECT * FROM delegations WHERE tenant_id = ?`
    const delRows = db.prepare(delQuery).all(...(agentFilter ? [tenant.id, agentFilter, agentFilter] : [tenant.id])) as any[]

    const activeDels = delRows.filter((d: any) => d.status === 'active').length
    const revokedDels = delRows.filter((d: any) => d.status !== 'active').length

    // ── 3: Evaluation Events (time-range) ──
    const evalWhere = agentFilter ? 'AND agent_id = ?' : ''
    const evalParams = agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until]
    const evalRows = db.prepare(
      `SELECT id, agent_id, action_type, verdict, reason, duration_ms, created_at FROM policy_evaluations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ${evalWhere} ORDER BY created_at`
    ).all(...evalParams) as any[]

    const permits3 = evalRows.filter((e: any) => (e.verdict || '').toLowerCase() === 'permit').length
    const denials3 = evalRows.length - permits3
    const avgLatency = evalRows.length > 0 ? Math.round(evalRows.reduce((s: number, e: any) => s + (e.duration_ms || 0), 0) / evalRows.length * 10) / 10 : 0

    // ── 4: Authorization Receipts (time-range) ──
    const rcptWhere = agentFilter ? 'AND agent_id = ?' : ''
    const rcptParams = agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until]
    const rcptRows = db.prepare(
      `SELECT id, agent_id, event_type, action_type, scope_requested_json, reason_code, policy_hash, receipt_hash, gateway_signature, created_at FROM evaluation_receipts WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ${rcptWhere} ORDER BY created_at`
    ).all(...rcptParams) as any[]

    const byType4: Record<string, number> = {}
    for (const r of rcptRows) byType4[r.event_type] = (byType4[r.event_type] || 0) + 1

    // ── 5: Revocation Events (time-range) ──
    const revRows = db.prepare(
      `SELECT * FROM revocations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(tenant.id, since, until) as any[]

    // ── 6: Posture Events (time-range) ──
    const postureRows = db.prepare(
      agentFilter
        ? `SELECT * FROM posture_events WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? AND agent_id = ? ORDER BY created_at`
        : `SELECT * FROM posture_events WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(...(agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until])) as any[]

    // ── 7: Key Rotations (time-range) ──
    const rotRows = db.prepare(
      agentFilter
        ? `SELECT * FROM key_rotations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? AND agent_id = ? ORDER BY created_at`
        : `SELECT * FROM key_rotations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(...(agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until])) as any[]

    // ── 8: Receipt Window Seals (time-range) ──
    const sealRows = db.prepare(
      `SELECT seal_id, seq_start, seq_end, receipt_count, permit_count, deny_count, commitment_hash, gateway_signature, created_at FROM receipt_window_seals WHERE created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(since, until) as any[]

    // ── 9: Governance Attestations (synthetic — count of attestation queries) ──
    // The gateway doesn't log individual attestation serves yet.
    // Section present with total: 0 — honest, not broken.

    // ── Assemble ──
    const exportData: Record<string, unknown> = {
      export_version: '1.0.0',
      generated_at: now,
      period: { from: since, to: until },
      completeness: 'full',
      scope: 'All gateway-mediated agent governance activity',
      known_exclusions: [
        'Downstream execution results (gateway authorizes, does not execute)',
        'External processing not mediated by this gateway',
      ],
      gateway: {
        id: 'gateway.aeoess.com',
        version: '0.4.0',
        kid: 'gateway-v1',
        jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
      },

      '1_agent_registry': {
        as_of: now,
        total: agentRows.length,
        by_status: byStatus,
        by_grade: byGrade,
        agents: agentsWithGrade,
      },

      '2_delegation_inventory': {
        as_of: now,
        total: delRows.length,
        active: activeDels,
        revoked: revokedDels,
        delegations: delRows.map((d: any) => ({
          id: d.id, parent: d.parent_agent_id, child: d.child_agent_id,
          scope: d.scope ? d.scope.split(',').map((s: string) => s.trim()) : [],
          spend_limit: d.spend_limit, spend_used: d.spend_used, max_depth: d.max_depth,
          status: d.status, created_at: d.created_at,
        })),
      },

      '3_evaluation_events': {
        from: since, to: until,
        total: evalRows.length, permits: permits3, denials: denials3,
        avg_latency_ms: avgLatency,
        events: evalRows.map((e: any) => ({
          agent_id: e.agent_id, action_type: e.action_type,
          verdict: e.verdict, reason_code: e.reason || null,
          policy_hash: null, timestamp: e.created_at,
        })),
      },

      '4_authorization_receipts': {
        from: since, to: until,
        total: rcptRows.length,
        by_type: byType4,
        receipts: rcptRows.map((r: any) => {
          let scope: string[] = []
          try { scope = JSON.parse(r.scope_requested_json || '[]') } catch {}
          return {
            id: r.id, agent_id: r.agent_id, event_type: r.event_type,
            action_type: r.action_type, scope_requested: scope,
            reason_code: r.reason_code, policy_hash: r.policy_hash,
            receipt_hash: r.receipt_hash, gateway_signature: r.gateway_signature,
            timestamp: r.created_at,
          }
        }),
      },

      '5_revocation_events': {
        from: since, to: until,
        total: revRows.length,
        revocations: revRows.map((r: any) => ({
          target_id: r.target_id, target_type: r.target_type,
          revoked_by: r.revoked_by, reason: r.reason || null,
          cascade_count: r.cascade_count, timestamp: r.created_at,
        })),
      },

      '6_posture_events': {
        from: since, to: until,
        total: postureRows.length,
        events: postureRows.map((p: any) => ({
          agent_id: p.agent_id, old_status: p.old_status, new_status: p.new_status,
          reason: p.reason, changed_by: p.changed_by, timestamp: p.created_at,
        })),
      },

      '7_key_rotations': {
        from: since, to: until,
        total: rotRows.length,
        rotations: rotRows.map((r: any) => ({
          agent_id: r.agent_id, mode: r.mode, state: r.state,
          announced_at: r.announced_at, activation_time: r.activation_time,
          completed_at: r.completed_at,
        })),
      },

      '8_receipt_window_seals': {
        from: since, to: until,
        total: sealRows.length,
        seals: sealRows.map((s: any) => ({
          seal_id: s.seal_id, seq_start: s.seq_start, seq_end: s.seq_end,
          receipt_count: s.receipt_count, commitment_hash: s.commitment_hash,
          gateway_signature: s.gateway_signature, created_at: s.created_at,
        })),
      },

      '9_governance_attestations': {
        from: since, to: until,
        total: 0,
        attestations_served: [],
      },
    }

    // Sign entire canonicalized export
    const identity = getGatewayIdentity()
    const signature = identity.sign(exportData as Record<string, unknown>)
    ;(exportData as any).signature = signature

    res.json(exportData)
  } catch (e: any) {
    console.error('[governance-export] FAILED:', e.message)
    res.status(500).json({ error: 'Export generation failed' })
  }
})


// ═══════════════════════════════════════
// GET /api/v1/agents/:agentId/health — Agent Health Status
// Enterprise monitoring integration (Datadog, Grafana).
// Matches AgentHealthStatus shape from agent-passport-system SDK.
// ═══════════════════════════════════════

gatewayRouter.get('/agents/:agentId/health', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params

    // 1. Look up agent
    const agent = db.prepare(
      `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!agent) {
      return res.status(404).json({ error: `Agent "${agentId}" not found` })
    }

    // 2. Passport validity
    const passportValid = agent.status === 'active' || agent.status === 'restricted'

    // 3. Delegation
    const delegation = db.prepare(
      `SELECT * FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agentId) as any
    const delegationActive = !!delegation
    const spendUtilization = delegation && delegation.spend_limit
      ? (delegation.spend_used || 0) / delegation.spend_limit
      : 0

    // 4. Passport grade (from dossier or heuristic)
    const dossier = db.prepare(
      `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agentId) as any
    let grade = 0
    if (dossier) {
      grade = dossier.passport_grade
    } else {
      if (agent.status === 'active') grade = 1
      if (delegation) grade = 2
    }

    // 5. Behavioral signals
    const lastAction = db.prepare(
      `SELECT MAX(created_at) as last_ts FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    const actionsLast24h = db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND created_at > datetime('now', '-1 day')`
    ).get(tenant.id, agentId) as any
    const recentDenials = db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny' AND created_at > datetime('now', '-1 hour')`
    ).get(tenant.id, agentId) as any

    // 6. Recovery events (from evaluation_receipts with event_type pattern)
    const recentRecoveries = db.prepare(
      `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny' AND created_at > datetime('now', '-1 hour')`
    ).get(tenant.id, agentId) as any

    // 7. Recovery policy (if table exists)
    let activeRecoveryPolicy: string | null = null
    let currentStrategy: string | null = null
    try {
      const policy = db.prepare(
        `SELECT id FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
      ).get(tenant.id, agentId) as any
      if (policy) activeRecoveryPolicy = policy.id
    } catch { /* table may not exist yet */ }

    // 8. Derive status
    let status: 'healthy' | 'degraded' | 'suspended' | 'expired'
    if (!passportValid) status = 'expired'
    else if (agent.status === 'suspended') status = 'suspended'
    else if ((recentRecoveries?.c || 0) > 2 || spendUtilization > 0.9) status = 'degraded'
    else status = 'healthy'

    // Compute expiry (agents table doesn't have expires_at, use delegation or default)
    const expiresAt = delegation?.created_at
      ? new Date(new Date(delegation.created_at).getTime() + 90 * 24 * 60 * 60 * 1000).toISOString()
      : new Date(new Date(agent.created_at).getTime() + 365 * 24 * 60 * 60 * 1000).toISOString()

    const healthStatus = {
      agentId,
      timestamp: new Date().toISOString(),
      passport: {
        valid: passportValid,
        expiresAt,
        grade,
      },
      delegation: {
        active: delegationActive,
        scopeCount: delegation ? delegation.scope.split(',').map((s: string) => s.trim()).filter(Boolean).length : 0,
        spendUtilization: Math.round(spendUtilization * 10000) / 10000,
        expiresAt: delegation?.revoked_at || null,
      },
      behavioral: {
        continuityScore: 0, // TODO: wire to context_continuity when implemented
        lastActionTimestamp: lastAction?.last_ts || null,
        actionsInWindow: actionsLast24h?.c || 0,
        driftDetected: false,
      },
      recovery: {
        activeRecoveryPolicy,
        recentRecoveryEvents: recentRecoveries?.c || 0,
        currentStrategy,
      },
      status,
    }

    res.json(healthStatus)
  } catch (e) {
    const err = safeError(e, 'agent-health')
    res.status(500).json(err)
  }
})


// ═══════════════════════════════════════
// Recovery Policy CRUD
// ═══════════════════════════════════════

// POST /api/v1/agents/:agentId/recovery-policy — Configure recovery policy
gatewayRouter.post('/agents/:agentId/recovery-policy', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params
    const policy = req.body

    if (!policy || !policy.policyId || !policy.rules || !policy.defaultStrategy) {
      return res.status(400).json({ error: 'Required: policyId, rules, defaultStrategy, maxTotalAttempts' })
    }

    const agent = db.prepare(
      `SELECT agent_id FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!agent) {
      return res.status(404).json({ error: `Agent "${agentId}" not found` })
    }

    const id = randomUUID()
    db.prepare(
      `INSERT INTO recovery_policies (id, tenant_id, agent_id, policy_json)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
         policy_json = excluded.policy_json,
         updated_at = datetime('now')`
    ).run(id, tenant.id, agentId, JSON.stringify(policy))

    res.status(201).json({ policyId: policy.policyId, agentId, status: 'active' })
  } catch (e) {
    const err = safeError(e, 'recovery-policy-create')
    res.status(500).json(err)
  }
})

// GET /api/v1/agents/:agentId/recovery-policy — Get recovery policy
gatewayRouter.get('/agents/:agentId/recovery-policy', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params

    const row = db.prepare(
      `SELECT policy_json FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!row) {
      return res.status(404).json({ error: 'No recovery policy configured for this agent' })
    }

    res.json(JSON.parse(row.policy_json))
  } catch (e) {
    const err = safeError(e, 'recovery-policy-get')
    res.status(500).json(err)
  }
})

// DELETE /api/v1/agents/:agentId/recovery-policy — Remove recovery policy
gatewayRouter.delete('/agents/:agentId/recovery-policy', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params

    const result = db.prepare(
      `DELETE FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
    ).run(tenant.id, agentId)

    if (result.changes === 0) {
      return res.status(404).json({ error: 'No recovery policy found' })
    }

    res.json({ agentId, status: 'removed' })
  } catch (e) {
    const err = safeError(e, 'recovery-policy-delete')
    res.status(500).json(err)
  }
})
