// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Coordination API — Task lifecycle with state machine, events, audit trail.
 *
 * POST   /tasks              — Create task
 * GET    /tasks              — List tasks
 * GET    /tasks/:taskId      — Get task detail + events
 * PUT    /tasks/:taskId/assign   — Assign to agent
 * PUT    /tasks/:taskId/accept   — Agent accepts
 * PUT    /tasks/:taskId/evidence — Submit evidence
 * PUT    /tasks/:taskId/review   — Review evidence
 * PUT    /tasks/:taskId/deliver  — Submit deliverable
 * PUT    /tasks/:taskId/cancel   — Cancel task
 *
 * Nate B Jones Primitive #4: Workflow State.
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getDB } from '../db/schema.js'
import { getEventBus } from './events.js'
import type { Tenant } from '../auth/api-keys.js'

export const coordinationRouter = Router()

// Valid status transitions
const TRANSITIONS: Record<string, string[]> = {
  draft:              ['assigned', 'cancelled'],
  assigned:           ['in_progress', 'cancelled'],
  in_progress:        ['evidence_submitted', 'cancelled'],
  evidence_submitted: ['approved', 'revision_requested', 'cancelled'],
  revision_requested: ['evidence_submitted', 'cancelled'],
  approved:           ['completed', 'cancelled'],
  under_review:       ['approved', 'revision_requested', 'cancelled'],
}

function canTransition(from: string, to: string): boolean {
  return TRANSITIONS[from]?.includes(to) ?? false
}

function recordEvent(tenantId: string, taskId: string, eventType: string, agentId?: string, data?: unknown) {
  const db = getDB()
  db.prepare(`INSERT INTO task_events (id, tenant_id, task_id, event_type, agent_id, data) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenantId, taskId, eventType, agentId || null, data ? JSON.stringify(data) : null)
}

function getTask(tenantId: string, taskId: string) {
  return getDB().prepare(`SELECT * FROM tasks WHERE tenant_id = ? AND id = ?`).get(tenantId, taskId) as any
}

// H5: column whitelist prevents SQL injection via field names
const TASK_COLUMNS = new Set(['status', 'assigned_to', 'scope', 'evidence', 'review_verdict', 'review_notes', 'deliverable', 'completed_at', 'acceptance_criteria', 'description'])

function updateTask(tenantId: string, taskId: string, fields: Record<string, unknown>) {
  const keys = Object.keys(fields).filter(k => TASK_COLUMNS.has(k))
  if (keys.length === 0) return
  const sets = keys.map(k => `${k} = ?`).join(', ')
  const vals = keys.map(k => fields[k])
  getDB().prepare(`UPDATE tasks SET ${sets}, updated_at = datetime('now') WHERE tenant_id = ? AND id = ?`)
    .run(...vals, tenantId, taskId)
}

// P2-12: Atomic state transition (prevents TOCTOU on concurrent requests)
function atomicTransition(
  tenantId: string, taskId: string, targetStatus: string,
  validate: (task: any) => string | null,
  fields: Record<string, unknown>,
): { task: any; error?: string } {
  const db = getDB()
  return db.transaction(() => {
    const task = db.prepare(`SELECT * FROM tasks WHERE tenant_id = ? AND id = ?`).get(tenantId, taskId) as any
    if (!task) return { task: null, error: 'Task not found' }
    if (!canTransition(task.status, targetStatus)) return { task, error: `Cannot transition: task is "${task.status}"` }
    const validationError = validate(task)
    if (validationError) return { task, error: validationError }
    const allFields = { ...fields, status: targetStatus }
    const safeKeys = Object.keys(allFields).filter(k => TASK_COLUMNS.has(k))
    if (safeKeys.length > 0) {
      const sets = safeKeys.map(k => `${k} = ?`).join(', ')
      const vals = safeKeys.map(k => allFields[k])
      db.prepare(`UPDATE tasks SET ${sets}, updated_at = datetime('now') WHERE tenant_id = ? AND id = ?`).run(...vals, tenantId, taskId)
    }
    return { task: db.prepare(`SELECT * FROM tasks WHERE tenant_id = ? AND id = ?`).get(tenantId, taskId) }
  }).immediate()
}

// ═══════════════════════════════════════
// POST /tasks — Create task
// ═══════════════════════════════════════

coordinationRouter.post('/tasks', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { title, description, created_by, scope, acceptance_criteria } = req.body
  if (!title || !created_by) {
    return res.status(400).json({ error: 'Required: title, created_by' })
  }

  const db = getDB()
  const id = randomUUID()
  db.prepare(
    `INSERT INTO tasks (id, tenant_id, title, description, status, created_by, scope, acceptance_criteria)
     VALUES (?, ?, ?, ?, 'draft', ?, ?, ?)`
  ).run(id, tenant.id, title, description || null, created_by, scope || null, acceptance_criteria || null)

  recordEvent(tenant.id, id, 'created', created_by)
  try { getEventBus().emit(tenant.id, { type: 'task_created', data: { task_id: id, title, created_by } }) } catch {}

  res.status(201).json({ id, status: 'draft', created_at: new Date().toISOString() })
})

// ═══════════════════════════════════════
// GET /tasks — List tasks
// ═══════════════════════════════════════

coordinationRouter.get('/tasks', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const status = req.query.status as string
  const assignedTo = req.query.assigned_to as string
  const sort = (req.query.sort as string) || 'created_at:desc'
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0

  let query = `SELECT id, title, status, created_by, assigned_to, scope, created_at, updated_at, completed_at FROM tasks WHERE tenant_id = ?`
  const params: unknown[] = [tenant.id]

  if (status) { query += ` AND status = ?`; params.push(status) }
  if (assignedTo) { query += ` AND assigned_to = ?`; params.push(assignedTo) }

  const [sortCol, sortDir] = sort.split(':')
  const col = ['created_at', 'updated_at', 'title', 'status'].includes(sortCol) ? sortCol : 'created_at'
  const dir = sortDir === 'asc' ? 'ASC' : 'DESC'
  query += ` ORDER BY ${col} ${dir} LIMIT ? OFFSET ?`
  params.push(limit, offset)

  const tasks = db.prepare(query).all(...params)
  const total = db.prepare(
    `SELECT COUNT(*) as c FROM tasks WHERE tenant_id = ?${status ? ' AND status = ?' : ''}${assignedTo ? ' AND assigned_to = ?' : ''}`
  ).get(...[tenant.id, ...(status ? [status] : []), ...(assignedTo ? [assignedTo] : [])] as unknown[]) as any

  res.json({ tasks, total: total.c, limit, offset })
})

// ═══════════════════════════════════════
// GET /tasks/:taskId — Task detail + events
// ═══════════════════════════════════════

coordinationRouter.get('/tasks/:taskId', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })

  const events = getDB().prepare(
    `SELECT * FROM task_events WHERE tenant_id = ? AND task_id = ? ORDER BY created_at ASC`
  ).all(tenant.id, req.params.taskId)

  res.json({ ...task, events })
})

// ═══════════════════════════════════════
// PUT /tasks/:taskId/assign
// ═══════════════════════════════════════

coordinationRouter.put('/tasks/:taskId/assign', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, scope } = req.body
  if (!agent_id) return res.status(400).json({ error: 'Required: agent_id' })
  const db = getDB()
  const agent = db.prepare(`SELECT agent_id, status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agent_id) as any
  if (!agent) return res.status(404).json({ error: `Agent "${agent_id}" not found` })
  if (agent.status !== 'active') return res.status(409).json({ error: `Agent "${agent_id}" is ${agent.status}` })
  const { task, error } = atomicTransition(tenant.id, req.params.taskId, 'assigned', () => null, { assigned_to: agent_id, ...(scope ? { scope } : {}) })
  if (error) return res.status(task ? 409 : 404).json({ error })
  recordEvent(tenant.id, req.params.taskId, 'assigned', agent_id, { scope })
  try { getEventBus().emit(tenant.id, { type: 'task_assigned', agentId: agent_id, data: { task_id: req.params.taskId } }) } catch {}
  res.json(task)
})

coordinationRouter.put('/tasks/:taskId/accept', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id } = req.body
  if (!agent_id) return res.status(400).json({ error: 'Required: agent_id' })
  const { task, error } = atomicTransition(tenant.id, req.params.taskId, 'in_progress',
    (t) => t.assigned_to !== agent_id ? 'Only the assigned agent can accept' : null, {})
  if (error) return res.status(task ? 409 : 404).json({ error })
  recordEvent(tenant.id, req.params.taskId, 'accepted', agent_id)
  try { getEventBus().emit(tenant.id, { type: 'task_accepted', agentId: agent_id, data: { task_id: req.params.taskId } }) } catch {}
  res.json(task)
})

coordinationRouter.put('/tasks/:taskId/evidence', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, evidence } = req.body
  if (!agent_id || !evidence) return res.status(400).json({ error: 'Required: agent_id, evidence' })
  const evidenceStr = typeof evidence === 'string' ? evidence : JSON.stringify(evidence)
  const { task, error } = atomicTransition(tenant.id, req.params.taskId, 'evidence_submitted',
    (t) => t.assigned_to !== agent_id ? 'Only the assigned agent can submit evidence' : null, { evidence: evidenceStr })
  if (error) return res.status(task ? 409 : 404).json({ error })
  recordEvent(tenant.id, req.params.taskId, 'evidence_submitted', agent_id, { evidence_length: evidenceStr.length })
  try { getEventBus().emit(tenant.id, { type: 'task_evidence', agentId: agent_id, data: { task_id: req.params.taskId } }) } catch {}
  res.json(task)
})

coordinationRouter.put('/tasks/:taskId/review', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { reviewer_id, verdict, notes } = req.body
  if (!reviewer_id || !verdict) return res.status(400).json({ error: 'Required: reviewer_id, verdict (approved|revision_requested)' })
  if (verdict !== 'approved' && verdict !== 'revision_requested') return res.status(400).json({ error: 'verdict must be "approved" or "revision_requested"' })
  const { task, error } = atomicTransition(tenant.id, req.params.taskId, verdict,
    (t) => t.assigned_to === reviewer_id ? 'Reviewer cannot be the assigned agent' : null, { review_verdict: verdict, review_notes: notes || null })
  if (error) return res.status(task ? 409 : 404).json({ error })
  recordEvent(tenant.id, req.params.taskId, 'reviewed', reviewer_id, { verdict, notes })
  try { getEventBus().emit(tenant.id, { type: 'task_reviewed', data: { task_id: req.params.taskId, verdict, reviewer_id } }) } catch {}
  res.json(task)
})

coordinationRouter.put('/tasks/:taskId/deliver', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, deliverable } = req.body
  if (!agent_id || !deliverable) return res.status(400).json({ error: 'Required: agent_id, deliverable' })
  const deliverableStr = typeof deliverable === 'string' ? deliverable : JSON.stringify(deliverable)
  const { task, error } = atomicTransition(tenant.id, req.params.taskId, 'completed',
    (t) => t.status !== 'approved' ? `Cannot deliver: task is "${t.status}", must be "approved"` : null,
    { deliverable: deliverableStr, completed_at: new Date().toISOString() })
  if (error) return res.status(task ? 409 : 404).json({ error })
  recordEvent(tenant.id, req.params.taskId, 'completed', agent_id, { deliverable_length: deliverableStr.length })
  try { getEventBus().emit(tenant.id, { type: 'task_completed', agentId: agent_id, data: { task_id: req.params.taskId } }) } catch {}
  res.json(task)
})

coordinationRouter.put('/tasks/:taskId/cancel', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { cancelled_by, reason } = req.body
  if (!cancelled_by) return res.status(400).json({ error: 'Required: cancelled_by' })
  const { task, error } = atomicTransition(tenant.id, req.params.taskId, 'cancelled',
    (t) => (t.status === 'completed' || t.status === 'cancelled') ? `Cannot cancel: already "${t.status}"` : null, {})
  if (error) return res.status(task ? 409 : 404).json({ error })
  recordEvent(tenant.id, req.params.taskId, 'cancelled', cancelled_by, { reason })
  try { getEventBus().emit(tenant.id, { type: 'task_cancelled', data: { task_id: req.params.taskId, cancelled_by, reason } }) } catch {}
  res.json(task)
})
