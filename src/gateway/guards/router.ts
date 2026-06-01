// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C2 guards router (layer a, read-only surface).
 *
 * The guards themselves run INSIDE the enforce pipeline (pre-flight, before the
 * billable evaluate). This router only EXPOSES the compiled guard set and lets a
 * caller dry-run a context against the guards. It performs no enforcement and
 * holds no authority. Mounted at /api/v1.
 *
 * GET  /guards            list the compiled guard names + high-risk vocabulary
 * POST /guards/dry-run    evaluate a hypothetical context (no side effects)
 */

import { Router } from 'express'
import type { Tenant } from '../../auth/api-keys.js'
import {
  evaluateGuards,
  isScopeHighRisk,
  GUARD_NAMES,
  DEFAULT_HIGH_RISK_SCOPES,
  type GuardContext,
} from './index.js'
import { scopeCoveredByLivePlaybook } from '../playbooks/index.js'

export const guardsRouter = Router()

guardsRouter.get('/guards', (_req: any, res) => {
  res.json({
    guards: GUARD_NAMES,
    high_risk_scopes: DEFAULT_HIGH_RISK_SCOPES,
    note: 'Guards are compiled, stateless, non-Turing-complete and run pre-flight inside /evaluate. No agent or LLM is in this path.',
  })
})

guardsRouter.post('/guards/dry-run', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_status, scope_required, action_type, estimated_cost, cost_ceiling } = req.body || {}
  if (!scope_required || typeof scope_required !== 'string') {
    return res.status(400).json({ error: 'Required: scope_required (string)' })
  }
  const isHighRisk = isScopeHighRisk(scope_required, DEFAULT_HIGH_RISK_SCOPES)
  let covered = false
  if (isHighRisk) {
    try { covered = scopeCoveredByLivePlaybook(tenant.id, scope_required) } catch { covered = false }
  }
  const ctx: GuardContext = {
    agentStatus: typeof agent_status === 'string' ? agent_status : 'active',
    scopeRequired: scope_required,
    actionType: typeof action_type === 'string' ? action_type : '',
    estimatedCost: typeof estimated_cost === 'number' ? estimated_cost : 0,
    isHighRisk,
    coveredBySignedPlaybook: covered,
    costCeiling: typeof cost_ceiling === 'number' ? cost_ceiling : 0,
  }
  const decision = evaluateGuards(ctx)
  res.json({
    decision: decision.verdict,
    code: decision.code,
    reason: decision.reason,
    guard: decision.guard,
    is_high_risk: isHighRisk,
    covered_by_signed_playbook: covered,
  })
})
