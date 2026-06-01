// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - Tenant isolation + onboarding router
// ══════════════════════════════════════════════════════════════════
// Mounted under /api/v1 behind authMiddleware (same pattern as every other
// gateway router). A tenant operates ONLY on its own row; the isolation
// switch and the D2 toggle are tenant-self-service plus operator override.
//
// Routes:
//   GET  /tenant-isolation/state            - read own isolation state
//   POST /tenant-isolation/mode             - set hard|standard
//   POST /tenant-isolation/cohort-opt-in    - opt in/out of cross-tenant signal
//   POST /tenant-isolation/trust-root       - bind customer BYO trust root (W2-B1 seam)
//   GET  /tenant-isolation/airgap-bundle    - offline-verifiable audit bundle
//
// Every state change records an onboarding_events row (hash-and-pointer:
// event type + pointer, never PHI) and emits on the existing per-tenant bus.
// ══════════════════════════════════════════════════════════════════

import { Router } from 'express'
import type { Tenant } from '../../auth/api-keys.js'
import { getDB } from '../../db/schema.js'
import { getEventBus } from '../events.js'
import {
  getTenantIsolationState,
  setIsolationMode,
  setCohortOptIn,
  type IsolationMode,
} from './isolation-switch.js'
import { bindTrustRoot, type CustomerTrustAnchor, type TrustRootSource } from './trust-root-seam.js'
import { buildAirGapBundle } from './airgap-bundle.js'
import { assertNoRawPayload } from './hash-pointer-seam.js'

export const tenantIsolationRouter = Router()

/** Append a hash-and-pointer onboarding lifecycle event. */
function recordOnboardingEvent(tenantId: string, eventType: string, detailPointer?: string): void {
  const db = getDB()
  db.prepare(
    `INSERT INTO onboarding_events (tenant_id, event_type, detail_pointer) VALUES (?, ?, ?)`,
  ).run(tenantId, eventType, detailPointer ?? null)
}

// ─── GET state ───────────────────────────────────────────────────────
tenantIsolationRouter.get('/tenant-isolation/state', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const state = getTenantIsolationState(tenant.id)
  if (!state) return res.status(404).json({ error: 'tenant not found' })
  return res.json(state)
})

// ─── POST mode (hard | standard) ─────────────────────────────────────
tenantIsolationRouter.post('/tenant-isolation/mode', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const mode = req.body?.mode as IsolationMode | undefined
  if (mode !== 'hard' && mode !== 'standard') {
    return res.status(400).json({ error: "mode must be 'hard' or 'standard'" })
  }
  let result
  try {
    result = setIsolationMode(tenant.id, mode)
  } catch (e: any) {
    return res.status(404).json({ error: e?.message || 'tenant not found' })
  }
  if (result.changed) {
    recordOnboardingEvent(tenant.id, 'tenant_isolation_set', `${result.from}->${result.to}`)
    getEventBus().emit(tenant.id, {
      type: 'tenant_isolation_set',
      data: { from: result.from, to: result.to },
    })
  }
  return res.json({ ok: true, ...result })
})

// ─── POST cohort opt-in ──────────────────────────────────────────────
tenantIsolationRouter.post('/tenant-isolation/cohort-opt-in', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const optIn = req.body?.opt_in
  if (typeof optIn !== 'boolean') {
    return res.status(400).json({ error: 'opt_in must be a boolean' })
  }
  let result
  try {
    result = setCohortOptIn(tenant.id, optIn)
  } catch (e: any) {
    return res.status(404).json({ error: e?.message || 'tenant not found' })
  }
  if (!result.applied) {
    return res.status(409).json({ ok: false, ...result })
  }
  recordOnboardingEvent(tenant.id, 'tenant_cohort_opt_in', String(optIn))
  getEventBus().emit(tenant.id, {
    type: 'tenant_cohort_opt_in',
    data: { opt_in: optIn },
  })
  return res.json({ ok: true, ...result })
})

// ─── POST trust-root (customer BYO; W2-B1 seam) ──────────────────────
tenantIsolationRouter.post('/tenant-isolation/trust-root', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const body = req.body || {}
  const source = body.source as TrustRootSource | undefined
  if (source !== 'gateway' && source !== 'hsm' && source !== 'kms') {
    return res.status(400).json({ error: "source must be 'gateway', 'hsm', or 'kms'" })
  }
  // Defence in depth: refuse a body that smells like raw key material / PHI.
  try {
    assertNoRawPayload(body)
  } catch (e: any) {
    return res.status(400).json({ error: e?.message })
  }
  const anchor: CustomerTrustAnchor = {
    source,
    keyRef: typeof body.key_ref === 'string' ? body.key_ref : '',
    anchorMaterial: typeof body.anchor_material === 'string' ? body.anchor_material : undefined,
    label: typeof body.label === 'string' ? body.label : undefined,
  }
  let binding
  try {
    binding = bindTrustRoot(anchor)
  } catch (e: any) {
    return res.status(400).json({ error: e?.message || 'trust-root binding refused' })
  }
  // Store fingerprint + pointer only; never the key material.
  const db = getDB()
  db.prepare(
    `UPDATE tenants SET trust_root_source = ?, trust_root_key_ref = ? WHERE id = ?`,
  ).run(binding.source, binding.keyRef, tenant.id)
  recordOnboardingEvent(tenant.id, 'tenant_trust_root_bound', binding.anchorFingerprint || binding.source)
  getEventBus().emit(tenant.id, {
    type: 'tenant_trust_root_bound',
    data: { source: binding.source, anchor_fingerprint: binding.anchorFingerprint },
  })
  return res.json({
    ok: true,
    source: binding.source,
    anchor_fingerprint: binding.anchorFingerprint,
    bound_at: binding.boundAt,
    note: 'cryptographic validation deferred to SDK trust-root policy (W2-B1)',
  })
})

// ─── GET air-gapped offline-verifiable audit bundle ──────────────────
tenantIsolationRouter.get('/tenant-isolation/airgap-bundle', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const from = req.query.from as string
  const to = req.query.to as string
  if (!from || !to) {
    return res.status(400).json({ error: 'from and to (ISO 8601) are required' })
  }
  if (isNaN(Date.parse(from)) || isNaN(Date.parse(to))) {
    return res.status(400).json({ error: 'invalid date; use ISO 8601' })
  }
  const bundle = buildAirGapBundle({
    tenantId: tenant.id,
    from,
    to,
    scope: typeof req.query.scope === 'string' ? req.query.scope : undefined,
  })
  recordOnboardingEvent(tenant.id, 'airgap_bundle_built', bundle.records_digest)
  res.setHeader('Content-Type', 'application/json')
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="airgap-bundle-${tenant.id}-${from}-${to}.json"`,
  )
  return res.send(JSON.stringify(bundle, null, 2))
})
