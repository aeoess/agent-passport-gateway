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

function updateTask(tenantId: string, taskId: string, fields: Record<string, unknown>) {
  const keys = Object.keys(fields)
  const sets = keys.map(k => `${k} = ?`).join(', ')
  const vals = keys.map(k => fields[k])
  getDB().prepare(`UPDATE tasks SET ${sets}, updated_at = datetime('now') WHERE tenant_id = ? AND id = ?`)
    .run(...vals, tenantId, taskId)
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

  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })
  if (!canTransition(task.status, 'assigned')) {
    return res.status(409).json({ error: `Cannot assign: task is "${task.status}"`, current_status: task.status })
  }

  const db = getDB()
  const agent = db.prepare(`SELECT agent_id, status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agent_id) as any
  if (!agent) return res.status(404).json({ error: `Agent "${agent_id}" not found` })
  if (agent.status !== 'active') return res.status(409).json({ error: `Agent "${agent_id}" is ${agent.status}` })

  updateTask(tenant.id, req.params.taskId, { status: 'assigned', assigned_to: agent_id, ...(scope ? { scope } : {}) })
  recordEvent(tenant.id, req.params.taskId, 'assigned', agent_id, { scope })
  try { getEventBus().emit(tenant.id, { type: 'task_assigned', agentId: agent_id, data: { task_id: req.params.taskId, title: task.title } }) } catch {}

  res.json({ ...getTask(tenant.id, req.params.taskId) })
})

// ═══════════════════════════════════════
// PUT /tasks/:taskId/accept
// ═══════════════════════════════════════

coordinationRouter.put('/tasks/:taskId/accept', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id } = req.body
  if (!agent_id) return res.status(400).json({ error: 'Required: agent_id' })

  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })
  if (task.assigned_to !== agent_id) return res.status(403).json({ error: 'Only the assigned agent can accept' })
  if (!canTransition(task.status, 'in_progress')) {
    return res.status(409).json({ error: `Cannot accept: task is "${task.status}"`, current_status: task.status })
  }

  updateTask(tenant.id, req.params.taskId, { status: 'in_progress' })
  recordEvent(tenant.id, req.params.taskId, 'accepted', agent_id)
  try { getEventBus().emit(tenant.id, { type: 'task_accepted', agentId: agent_id, data: { task_id: req.params.taskId } }) } catch {}

  res.json({ ...getTask(tenant.id, req.params.taskId) })
})

// ═══════════════════════════════════════
// PUT /tasks/:taskId/evidence
// ═══════════════════════════════════════

coordinationRouter.put('/tasks/:taskId/evidence', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, evidence } = req.body
  if (!agent_id || !evidence) return res.status(400).json({ error: 'Required: agent_id, evidence' })

  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })
  if (task.assigned_to !== agent_id) return res.status(403).json({ error: 'Only the assigned agent can submit evidence' })
  if (!canTransition(task.status, 'evidence_submitted')) {
    return res.status(409).json({ error: `Cannot submit evidence: task is "${task.status}"`, current_status: task.status })
  }

  const evidenceStr = typeof evidence === 'string' ? evidence : JSON.stringify(evidence)
  updateTask(tenant.id, req.params.taskId, { status: 'evidence_submitted', evidence: evidenceStr })
  recordEvent(tenant.id, req.params.taskId, 'evidence_submitted', agent_id, { evidence_length: evidenceStr.length })
  try { getEventBus().emit(tenant.id, { type: 'task_evidence', agentId: agent_id, data: { task_id: req.params.taskId } }) } catch {}

  res.json({ ...getTask(tenant.id, req.params.taskId) })
})

// ═══════════════════════════════════════
// PUT /tasks/:taskId/review
// ═══════════════════════════════════════

coordinationRouter.put('/tasks/:taskId/review', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { reviewer_id, verdict, notes } = req.body
  if (!reviewer_id || !verdict) return res.status(400).json({ error: 'Required: reviewer_id, verdict (approved|revision_requested)' })
  if (verdict !== 'approved' && verdict !== 'revision_requested') {
    return res.status(400).json({ error: 'verdict must be "approved" or "revision_requested"' })
  }

  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })
  if (task.assigned_to === reviewer_id) return res.status(403).json({ error: 'Reviewer cannot be the assigned agent' })
  if (!canTransition(task.status, verdict)) {
    return res.status(409).json({ error: `Cannot review: task is "${task.status}"`, current_status: task.status })
  }

  const fields: Record<string, unknown> = { status: verdict, review_verdict: verdict, review_notes: notes || null }
  updateTask(tenant.id, req.params.taskId, fields)
  recordEvent(tenant.id, req.params.taskId, 'reviewed', reviewer_id, { verdict, notes })
  try { getEventBus().emit(tenant.id, { type: 'task_reviewed', data: { task_id: req.params.taskId, verdict, reviewer_id } }) } catch {}

  res.json({ ...getTask(tenant.id, req.params.taskId) })
})

// ═══════════════════════════════════════
// PUT /tasks/:taskId/deliver
// ═══════════════════════════════════════

coordinationRouter.put('/tasks/:taskId/deliver', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, deliverable } = req.body
  if (!agent_id || !deliverable) return res.status(400).json({ error: 'Required: agent_id, deliverable' })

  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })
  if (task.status !== 'approved') {
    return res.status(409).json({ error: `Cannot deliver: task is "${task.status}", must be "approved"`, current_status: task.status })
  }

  const deliverableStr = typeof deliverable === 'string' ? deliverable : JSON.stringify(deliverable)
  updateTask(tenant.id, req.params.taskId, { status: 'completed', deliverable: deliverableStr, completed_at: new Date().toISOString() })
  recordEvent(tenant.id, req.params.taskId, 'completed', agent_id, { deliverable_length: deliverableStr.length })
  try { getEventBus().emit(tenant.id, { type: 'task_completed', agentId: agent_id, data: { task_id: req.params.taskId, title: task.title } }) } catch {}

  res.json({ ...getTask(tenant.id, req.params.taskId) })
})

// ═══════════════════════════════════════
// PUT /tasks/:taskId/cancel
// ═══════════════════════════════════════

coordinationRouter.put('/tasks/:taskId/cancel', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { cancelled_by, reason } = req.body
  if (!cancelled_by) return res.status(400).json({ error: 'Required: cancelled_by' })

  const task = getTask(tenant.id, req.params.taskId)
  if (!task) return res.status(404).json({ error: 'Task not found' })
  if (task.status === 'completed' || task.status === 'cancelled') {
    return res.status(409).json({ error: `Cannot cancel: task is already "${task.status}"`, current_status: task.status })
  }

  updateTask(tenant.id, req.params.taskId, { status: 'cancelled' })
  recordEvent(tenant.id, req.params.taskId, 'cancelled', cancelled_by, { reason })
  try { getEventBus().emit(tenant.id, { type: 'task_cancelled', data: { task_id: req.params.taskId, cancelled_by, reason } }) } catch {}

  res.json({ ...getTask(tenant.id, req.params.taskId) })
})
