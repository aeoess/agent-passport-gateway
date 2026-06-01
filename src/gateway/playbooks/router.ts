// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C2 playbooks router (layer c).
 *
 * Surfaces the customer pre-signed incident-playbook registry and the offline-
 * enforced kill. The gateway holds NO kill switch of its own: the kill endpoint
 * bumps the customer-subject epoch (B2 seam) with the AUTHENTICATED customer as
 * the actor, and enforcement is the sink's offline epoch check. Mounted at /api/v1.
 *
 * POST /playbooks                 register a customer pre-signed playbook
 * GET  /playbooks/:id             get a playbook
 * POST /playbooks/fire            fire a pre-authorized response (post-review pending)
 * POST /playbooks/kill            customer unilateral kill (epoch bump; sink-enforced)
 * POST /playbooks/fires/:id/review  record the MANDATORY post-review
 * GET  /playbooks/pending-reviews  fires awaiting post-review
 */

import { Router } from 'express'
import type { Tenant } from '../../auth/api-keys.js'
import {
  registerPlaybook,
  getPlaybook,
  fireResponse,
  customerKillPlaybooks,
  reviewFire,
  pendingReviews,
  type PlaybookResponse,
  type PlaybookSubjectKind,
} from './index.js'

export const playbooksRouter = Router()

playbooksRouter.post('/playbooks', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { name, trigger, authorized_responses, delegation_id, subject_kind, subject_id, ttl_hours } = req.body || {}
  if (!name || !trigger || !Array.isArray(authorized_responses) || !delegation_id || !subject_id) {
    return res.status(400).json({ error: 'Required: name, trigger, authorized_responses[], delegation_id, subject_id' })
  }
  const subjectKind: PlaybookSubjectKind = subject_kind === 'agent' ? 'agent' : 'delegation'
  const responses: PlaybookResponse[] = authorized_responses
  const pb = registerPlaybook({
    tenantId: tenant.id,
    name,
    trigger,
    authorizedResponses: responses,
    delegationId: delegation_id,
    subjectKind,
    subjectId: subject_id,
    ttlHours: typeof ttl_hours === 'number' ? ttl_hours : 24,
  })
  res.status(201).json(pb)
})

playbooksRouter.get('/playbooks/:id', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const pb = getPlaybook(tenant.id, req.params.id)
  if (!pb) return res.status(404).json({ error: 'Playbook not found' })
  res.json(pb)
})

playbooksRouter.post('/playbooks/fire', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { trigger, response_scope, trigger_payload } = req.body || {}
  if (!trigger || !response_scope) {
    return res.status(400).json({ error: 'Required: trigger, response_scope' })
  }
  const result = fireResponse({
    tenantId: tenant.id,
    trigger,
    responseScope: response_scope,
    triggerPayload: trigger_payload ?? null,
  })
  // A refusal (no live signed playbook) is a 409, not a server error: the
  // request is well-formed, the authority simply is not there.
  if (!result.fired) return res.status(409).json({ fired: false, reason: result.reason })
  res.status(201).json(result)
})

playbooksRouter.post('/playbooks/kill', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { subject_kind, subject_id, killed_by, reason } = req.body || {}
  if (!subject_id || !killed_by) {
    return res.status(400).json({ error: 'Required: subject_id, killed_by (the authenticated customer)' })
  }
  const subjectKind: PlaybookSubjectKind = subject_kind === 'agent' ? 'agent' : 'delegation'
  const result = customerKillPlaybooks({
    tenantId: tenant.id,
    subjectKind,
    subjectId: subject_id,
    killedBy: killed_by,
    reason,
  })
  res.json({
    killed: true,
    new_epoch: result.newEpoch,
    killed_playbook_ids: result.killedPlaybookIds,
    note: 'Enforcement is offline at the sink via the epoch check. The gateway took no enforcement action.',
  })
})

playbooksRouter.post('/playbooks/fires/:id/review', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { reviewed_by, action_taken, notes } = req.body || {}
  if (!reviewed_by) return res.status(400).json({ error: 'Required: reviewed_by' })
  const result = reviewFire({
    tenantId: tenant.id,
    fireId: req.params.id,
    reviewedBy: reviewed_by,
    actionTaken: !!action_taken,
    notes,
  })
  if (!result.reviewed) return res.status(409).json({ reviewed: false, reason: result.reason })
  res.json({ reviewed: true, review_state: result.reason })
})

playbooksRouter.get('/playbooks/pending-reviews', (req: any, res) => {
  const tenant: Tenant = req.tenant
  res.json({ pending: pendingReviews(tenant.id) })
})
