// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C2 automations router (layer b).
 *
 * Triggers post-flight governance automations on demand. Every automation runs
 * under its own narrowed delegation and returns a signed self-receipt. None of
 * these endpoints performs a high-risk side effect: alert routing summarizes,
 * evidence-bundle composes read-only, drift/revocation recommend, integration-
 * health escalates a summary. Mounted at /api/v1.
 *
 * POST /automations/route-alert
 * POST /automations/evidence-bundle
 * POST /automations/policy-drift
 * POST /automations/recommend-revocation
 * POST /automations/integration-health
 */

import { Router } from 'express'
import type { Tenant } from '../../auth/api-keys.js'
import {
  routeAlert,
  generateEvidenceBundle,
  detectPolicyDrift,
  recommendRevocation,
  checkIntegrationHealth,
} from './index.js'

export const automationsRouter = Router()

automationsRouter.post('/automations/route-alert', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { recipient_email, recipient_name, signal, severity, summary, recommendation, target } = req.body || {}
  if (!recipient_email || !signal || !summary) {
    return res.status(400).json({ error: 'Required: recipient_email, signal, summary' })
  }
  const sev = severity === 'critical' || severity === 'warning' ? severity : 'info'
  const result = await routeAlert({
    tenantId: tenant.id,
    recipientEmail: recipient_email,
    recipientName: recipient_name || 'operator',
    signal,
    severity: sev,
    summary,
    recommendation: recommendation || 'Review in the dashboard.',
    target,
  })
  res.status(result.acted ? 200 : 409).json(result)
})

automationsRouter.post('/automations/evidence-bundle', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { from, to, scope } = req.body || {}
  if (!from || !to) return res.status(400).json({ error: 'Required: from, to (ISO 8601)' })
  if (isNaN(Date.parse(from)) || isNaN(Date.parse(to))) {
    return res.status(400).json({ error: 'Invalid date format. Use ISO 8601.' })
  }
  const result = await generateEvidenceBundle({ tenantId: tenant.id, from, to, scope })
  res.status(result.acted ? 200 : 409).json(result)
})

automationsRouter.post('/automations/policy-drift', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { window_hours, min_evaluations } = req.body || {}
  const result = await detectPolicyDrift({
    tenantId: tenant.id,
    windowHours: typeof window_hours === 'number' ? window_hours : undefined,
    minEvaluations: typeof min_evaluations === 'number' ? min_evaluations : undefined,
  })
  res.status(result.acted ? 200 : 409).json(result)
})

automationsRouter.post('/automations/recommend-revocation', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { target_type, target_id } = req.body || {}
  if (!target_id) return res.status(400).json({ error: 'Required: target_id' })
  const tt = target_type === 'delegation' || target_type === 'data_source' ? target_type : 'agent'
  const result = await recommendRevocation({ tenantId: tenant.id, targetType: tt, targetId: target_id })
  res.status(result.acted ? 200 : 409).json(result)
})

automationsRouter.post('/automations/integration-health', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { integration_names, window_hours } = req.body || {}
  const names = Array.isArray(integration_names) && integration_names.length > 0
    ? integration_names
    : ['default']
  const result = await checkIntegrationHealth({
    tenantId: tenant.id,
    integrationNames: names,
    windowHours: typeof window_hours === 'number' ? window_hours : undefined,
  })
  res.status(result.acted ? 200 : 409).json(result)
})
