// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Modes + simulation HTTP surface
// ══════════════════════════════════════════════════════════════════
// Customer-facing routes, mounted under /api/v1 behind authMiddleware so
// req.tenant is populated. Kept minimal: read/set mode, read the migration
// metric, and run a policy simulation. Input is validated at the boundary.
//
// Claims discipline (C4): the simulation response carries the honest
// disclaimer verbatim; nothing here asserts compliance or future safety.
// ══════════════════════════════════════════════════════════════════

import { Router } from 'express'
import type { Tenant } from '../../auth/api-keys.js'
import { isEnforcementMode, type EnforcementMode } from './modes.js'
import { resolveMode, setMode, listModes } from './mode-config.js'
import { computeMigrationMetric } from './migration-metric.js'
import { simulatePolicy, type CandidatePolicy } from './engine.js'
import { emitToEventSpine } from './event-spine.js'
import { SIMULATION_DISCLAIMER } from './disclaimer.js'

export const simulationRouter = Router()

// GET /api/v1/modes - list configured modes for the tenant (default + overrides)
simulationRouter.get('/modes', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const active = resolveMode(tenant.id, (req.query.workflow_id as string) || null)
  res.json({
    active_mode: active,
    configured: listModes(tenant.id),
    workflow_id: (req.query.workflow_id as string) || null,
  })
})

// PUT /api/v1/modes - set the tenant default mode or a per-workflow override
simulationRouter.put('/modes', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { mode, workflow_id } = req.body || {}
  if (!isEnforcementMode(mode)) {
    return res.status(400).json({
      error: 'Required: mode (one of observe, warn, approval, enforce, emergency)',
    })
  }
  const result = setMode({
    tenantId: tenant.id,
    mode: mode as EnforcementMode,
    workflowId: workflow_id || null,
    updatedBy: tenant.email || 'api',
  })
  res.json({ ok: true, ...result })
})

// GET /api/v1/modes/migration-metric - the "0 blocked, N would-have-been-denied,
// M policies need tuning before enforce" readiness line
simulationRouter.get('/modes/migration-metric', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const workflowId = (req.query.workflow_id as string) || null
  const windowDays = req.query.window_days ? parseInt(req.query.window_days as string, 10) : null
  const currentMode = resolveMode(tenant.id, workflowId)
  const metric = computeMigrationMetric({
    tenantId: tenant.id,
    workflowId,
    currentMode,
    windowDays: Number.isFinite(windowDays as number) ? windowDays : null,
  })
  res.json(metric)
})

// POST /api/v1/simulate - replay a candidate policy over historical receipts
simulationRouter.post('/simulate', async (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const body = req.body || {}
    const candidate = body.candidate_policy || body.candidate
    if (!candidate || typeof candidate !== 'object' || typeof candidate.name !== 'string') {
      return res.status(400).json({
        error: 'Required: candidate_policy { name, allowScopes?, denyScopes?, spendCap?, blockHighRisk? }',
        disclaimer: SIMULATION_DISCLAIMER,
      })
    }
    const limit = body.limit ? parseInt(String(body.limit), 10) : undefined
    const result = await simulatePolicy({
      tenantId: tenant.id,
      candidate: candidate as CandidatePolicy,
      limit: Number.isFinite(limit as number) ? limit : undefined,
      agentId: body.agent_id || null,
    })

    // Record the simulation run on the event spine (G-A1 seam / local bus).
    emitToEventSpine(tenant.id, 'policy_simulation', {
      candidate_policy: result.candidate_policy,
      receipts_evaluated: result.receipts_evaluated,
      newly_denied: result.newly_denied,
      newly_permitted: result.newly_permitted,
    })

    res.json(result)
  } catch (e) {
    console.error('[simulate] error:', (e as Error).message)
    res.status(500).json({ error: 'Simulation failed', disclaimer: SIMULATION_DISCLAIMER })
  }
})
