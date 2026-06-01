// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway - Signed Audit Evidence Bundle endpoints (Build G-D2).
 *
 * These routes are mounted onto the existing auditExportRouter (already wired
 * at server.ts under /api/v1 behind authMiddleware), so no new server wiring
 * is needed beyond reusing that router.
 *
 *   POST /tenant/:tenantId/audit-bundles
 *     Body: { bundleType, from?, to?, receiptId?, agentId?, policyHash?,
 *             incidentId?, controlId?, framework?, scope?, redact? }
 *     Returns the SIGNED BUNDLE MANIFEST (or a redacted excerpt when redact).
 *
 *   GET  /tenant/:tenantId/audit-bundles/controls
 *     Returns the SUPPORTS-EVIDENCE-FOR control catalog (discovery).
 *
 * Rate limited separately from the audit-export limiter, with its own keyPrefix
 * so the two limits do not collide.
 */

import { Router } from 'express'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import type { Tenant } from '../../auth/api-keys.js'
import { getEventBus } from '../events.js'
import {
  assembleBundle,
  redactBundle,
  type BundleRequest,
} from './assembler.js'
import {
  buildControlMapping,
  listControlFrameworks,
} from './control-mapping.js'
import type { BundleType } from './types.js'

const BUNDLE_TYPES: BundleType[] = [
  'per-action',
  'per-agent',
  'per-policy',
  'per-incident',
  'per-compliance-control',
]

// Distinct keyPrefix from audit_export so the two limiters do not clash.
const bundleLimiter = new RateLimiterMemory({
  points: 10,
  duration: 3600,
  keyPrefix: 'audit_bundle',
})

export const auditBundlesRouter = Router()

auditBundlesRouter.get('/tenant/:tenantId/audit-bundles/controls', (req: any, res) => {
  const tenant: Tenant = req.tenant
  if (tenant.id !== req.params.tenantId) {
    return res.status(403).json({ error: 'Cannot read controls for another tenant' })
  }
  const framework = req.query.framework as string | undefined
  return res.json({
    frameworks: listControlFrameworks(),
    controls: buildControlMapping({ framework }),
    note:
      'Control mappings use supports-evidence-for language. A bundle supports ' +
      'evidence for these controls and does not by itself make any organization compliant.',
  })
})

auditBundlesRouter.post('/tenant/:tenantId/audit-bundles', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { tenantId } = req.params

  if (tenant.id !== tenantId) {
    return res.status(403).json({ error: 'Cannot build audit bundles for another tenant' })
  }

  try {
    await bundleLimiter.consume(tenant.id)
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 10 bundles per hour.' })
  }

  const body = req.body || {}
  const bundleType = body.bundleType as BundleType

  if (!bundleType || !BUNDLE_TYPES.includes(bundleType)) {
    return res
      .status(400)
      .json({ error: `Invalid bundleType. Use one of: ${BUNDLE_TYPES.join(', ')}` })
  }

  // Per-type required selector validation.
  if (bundleType === 'per-action' && body.receiptId === undefined) {
    return res.status(400).json({ error: 'per-action bundle requires receiptId' })
  }
  if (bundleType === 'per-agent' && !body.agentId) {
    return res.status(400).json({ error: 'per-agent bundle requires agentId' })
  }
  if (bundleType === 'per-policy' && !body.policyHash) {
    return res.status(400).json({ error: 'per-policy bundle requires policyHash' })
  }
  if (bundleType === 'per-compliance-control' && !body.controlId && !body.framework) {
    return res
      .status(400)
      .json({ error: 'per-compliance-control bundle requires controlId or framework' })
  }

  // Validate optional dates.
  for (const k of ['from', 'to'] as const) {
    if (body[k] && isNaN(Date.parse(body[k]))) {
      return res.status(400).json({ error: `Invalid ${k} date. Use ISO 8601.` })
    }
  }

  const request: BundleRequest = {
    tenantId: tenant.id,
    bundleType,
    from: body.from,
    to: body.to,
    receiptId: body.receiptId,
    agentId: body.agentId,
    policyHash: body.policyHash,
    incidentId: body.incidentId,
    controlId: body.controlId,
    framework: body.framework,
    scope: body.scope,
    jwksUrl: '/.well-known/jwks.json',
  }

  let signed
  try {
    signed = assembleBundle(request)
  } catch (e: any) {
    return res.status(500).json({ error: 'Bundle assembly failed', detail: e?.message })
  }

  // Emit on creation. The gateway coordinates and emits; it does not retain
  // enforcement authority over the customer-owned artifact.
  try {
    getEventBus().emit(tenant.id, {
      type: 'audit_bundle_created',
      data: {
        bundle_id: signed.manifest.bundleId,
        bundle_type: signed.manifest.bundleType,
        manifest_hash: signed.manifestHash,
        record_count: signed.manifest.records.length,
        merkle_root: signed.manifest.hashManifest.merkleRoot,
      },
    })
  } catch {
    // Emission failure must not block returning the signed artifact.
  }

  const redact = body.redact === true || req.query.redact === 'true'
  const filename = `audit-bundle-${tenant.id}-${signed.manifest.bundleType}-${signed.manifest.bundleId}.json`
  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
  return res.send(JSON.stringify(redact ? redactBundle(signed) : signed, null, 2))
})
