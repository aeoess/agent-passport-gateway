// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Destinations router (G-D3)
// ══════════════════════════════════════════════════════════════════
//   POST /api/v1/destinations               register a destination policy
//   GET  /api/v1/destinations               list destinations
//   POST /api/v1/destinations/:id/check     before-the-fact destination
//                                            control: given a source's
//                                            class + destination, return
//                                            permit/deny.
//
// Non-conflicting path: there is no existing /destinations route, and we
// avoid the taken /data-sources POST. The check joins the source's
// recorded class (from the classification module) with the destination
// policy and returns a thin verdict. The gateway records the sink's
// confirmation SUPPORT and risk tier; the sink performs the actual
// confirmation. The gateway is not the trusted brain.
// ══════════════════════════════════════════════════════════════════

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import type { Tenant } from '../../auth/api-keys.js'
import { getEventBus } from '../events.js'
import { getGatewayIdentity } from '../identity.js'
import { checkDestination } from './destination-policy.js'
import type {
  DestinationPolicy,
  DestinationPlacement,
  DestinationRiskTier,
  SinkConfirmationSupport,
  DestinationCheckRequest,
} from './destination-policy.js'

export const destinationsRouter = Router()

const PLACEMENTS: DestinationPlacement[] = ['internal', 'external']
const RISK_TIERS: DestinationRiskTier[] = ['low', 'medium', 'high', 'unknown']
const SINK_SUPPORT: SinkConfirmationSupport[] = ['none', 'supported', 'attested']

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return []
  return v.filter((x): x is string => typeof x === 'string')
}

function rowToPolicy(row: any): DestinationPolicy {
  return {
    destinationId: row.destination_id,
    destinationName: row.destination_name,
    placement: row.placement,
    allowedDataClasses: JSON.parse(row.allowed_data_classes || '[]'),
    allowedAgentRoles: JSON.parse(row.allowed_agent_roles || '[]'),
    allowedPurposes: JSON.parse(row.allowed_purposes || '[]'),
    storagePolicy: JSON.parse(row.storage_policy || '{}'),
    trainingPolicy: JSON.parse(row.training_policy || '{}'),
    sinkConfirmationSupport: row.sink_confirmation_support,
    riskTier: row.risk_tier,
  }
}

// POST /api/v1/destinations - register a destination policy.
destinationsRouter.post('/destinations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const b = req.body || {}
  const { destination_id, destination_name } = b
  if (!destination_id || !destination_name) {
    return res.status(400).json({ error: 'Required: destination_id, destination_name' })
  }

  const placement: DestinationPlacement = PLACEMENTS.includes(b.placement) ? b.placement : 'external'
  const riskTier: DestinationRiskTier = RISK_TIERS.includes(b.risk_tier) ? b.risk_tier : 'unknown'
  const sinkSupport: SinkConfirmationSupport = SINK_SUPPORT.includes(b.sink_confirmation_support)
    ? b.sink_confirmation_support
    : 'none'

  const allowedDataClasses = asStringArray(b.allowed_data_classes)
  const allowedAgentRoles = asStringArray(b.allowed_agent_roles)
  const allowedPurposes = asStringArray(b.allowed_purposes)
  const storagePolicy = b.storage_policy && typeof b.storage_policy === 'object' ? b.storage_policy : { persists: false }
  const trainingPolicy = b.training_policy && typeof b.training_policy === 'object' ? b.training_policy : { allowsTraining: false }

  // Sign the destination registration so external verifiers can confirm
  // the recorded policy. Gateway-local state until W2-destinations.
  // TODO(W2-destinations): replace gateway-local signed state with the
  //   SDK destination / sink-confirmation primitive (sink-confirmation
  //   support + risk-tier attestation).
  // TODO(W2-set): emit a SET for destination registration via the SDK SET
  //   emitter once Wave 2 lands.
  const attestation = getGatewayIdentity().sign({
    kind: 'destination_registration',
    tenant_id: tenant.id,
    destination_id,
    placement,
    risk_tier: riskTier,
    sink_confirmation_support: sinkSupport,
    allowed_data_classes: allowedDataClasses,
  })

  const db = getDB()
  const id = randomUUID()
  try {
    db.prepare(
      `INSERT INTO destinations
         (id, tenant_id, destination_id, destination_name, placement,
          allowed_data_classes, allowed_agent_roles, allowed_purposes,
          storage_policy, training_policy, sink_confirmation_support,
          risk_tier, attestation)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      id,
      tenant.id,
      destination_id,
      destination_name,
      placement,
      JSON.stringify(allowedDataClasses),
      JSON.stringify(allowedAgentRoles),
      JSON.stringify(allowedPurposes),
      JSON.stringify(storagePolicy),
      JSON.stringify(trainingPolicy),
      sinkSupport,
      riskTier,
      attestation,
    )
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Destination already registered' })
    return res.status(500).json({ error: 'destination-register failed' })
  }

  try {
    getEventBus().emit(tenant.id, {
      type: 'destination_registered',
      data: { destination_id, placement, risk_tier: riskTier },
    })
  } catch {}

  return res.status(201).json({ id, destination_id, status: 'active', risk_tier: riskTier })
})

// GET /api/v1/destinations - list destinations.
destinationsRouter.get('/destinations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const items = db
    .prepare(`SELECT * FROM destinations WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(tenant.id, limit, offset)
  const total = (db.prepare(`SELECT COUNT(*) as c FROM destinations WHERE tenant_id = ?`).get(tenant.id) as any).c
  res.json({ destinations: items, total, limit, offset, has_more: offset + items.length < total })
})

// POST /api/v1/destinations/:id/check - before-the-fact destination control.
// Body: { source_id?, source_class?, agent_role?, purpose?, for_training? }
// Either source_id (we read its recorded class) or source_class is required.
destinationsRouter.post('/destinations/:id/check', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const destinationId = req.params.id
  const b = req.body || {}
  const db = getDB()

  const destRow = db
    .prepare(`SELECT * FROM destinations WHERE tenant_id = ? AND destination_id = ?`)
    .get(tenant.id, destinationId) as any
  if (!destRow) {
    return res.status(404).json({ error: `Destination "${destinationId}" not found` })
  }

  // Resolve the source class. Prefer the recorded class on the source
  // (set from a connector label), never a payload scan. source_class may
  // be supplied directly for a source not registered through this gateway.
  let sourceClass: string | undefined = typeof b.source_class === 'string' ? b.source_class : undefined
  if (b.source_id) {
    const srcRow = db
      .prepare(`SELECT data_class FROM data_sources WHERE tenant_id = ? AND source_id = ?`)
      .get(tenant.id, b.source_id) as any
    if (!srcRow) {
      return res.status(404).json({ error: `Data source "${b.source_id}" not found` })
    }
    if (!srcRow.data_class) {
      return res.status(409).json({ error: `Data source "${b.source_id}" is not classified` })
    }
    sourceClass = srcRow.data_class
  }
  if (!sourceClass) {
    return res.status(400).json({ error: 'Required: source_id (classified) or source_class' })
  }

  const checkReq: DestinationCheckRequest = {
    sourceClass,
    agentRole: typeof b.agent_role === 'string' ? b.agent_role : undefined,
    purpose: b.purpose,
    forTraining: b.for_training === true,
  }

  const isActive = destRow.status === 'active' && !destRow.revoked_at
  const result = checkDestination(checkReq, rowToPolicy(destRow), isActive)

  try {
    getEventBus().emit(tenant.id, {
      type: 'destination_check',
      data: {
        destination_id: destinationId,
        source_class: sourceClass,
        decision: result.decision,
        reason: result.reason,
      },
    })
  } catch {}

  return res.status(200).json({
    destination_id: destinationId,
    source_class: sourceClass,
    decision: result.decision,
    reason: result.reason,
    sink_confirmation_support: result.sinkConfirmationSupport,
    risk_tier: result.riskTier,
  })
})
