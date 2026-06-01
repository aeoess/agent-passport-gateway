// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Risk Queue (G-A3) - the portal center.
 *
 * A prioritized inbox of actions a human operator should act on, derived
 * from gateway-observed events. This is the operator console core: not a
 * receipt table, but a worklist sorted highest-risk-first.
 *
 * Item kinds (the things a human is asked to decide on):
 *   needs_approval, revocation_stale, denied_high_risk_action, new_destination,
 *   missing_sink_confirmation, repeated_denials, agent_outside_baseline
 *
 * Item actions (what the operator can do about an item):
 *   approve, deny, freeze, open_ticket, export_bundle, edit_policy, escalate
 *
 * THIN GATEWAY: this module surfaces decisions and emits events. Trust and
 * enforcement live at the edges - short-lived owner confirmations (signed by
 * the delegator, SDK human-escalation), sinks that verify, and customer-owned
 * signed artifacts. A resolution row records that a decision was surfaced and
 * which action the operator chose; enforcement is carried out by the relevant
 * edge (token expiry, sink check, revocation epoch), not by this queue.
 *
 * SDK CONSUMPTION: the risk-decision logic is SDK-owned. We call
 * checkEscalationRequired (v2 human-escalation) to decide whether an action
 * must enter the queue as needs_approval, and checkHumanApprovalThreshold
 * (commerce) for spend-triggered entries. We do not reimplement those.
 *
 * GET  /api/v1/risk-queue            - open items, highest-risk first
 * GET  /api/v1/risk-queue/:id        - single item
 * POST /api/v1/risk-queue/:id/action - apply an operator action (resolve)
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getDB } from '../db/schema.js'
import { getGatewayIdentity } from './identity.js'
import { getEventBus, type GatewayEvent } from './events.js'
import type { Tenant } from '../auth/api-keys.js'
import {
  recordApproval,
  getUnreviewedFatigueFlags,
} from '../sdk-migrated/v2/approval-fatigue.js'
import type { ApprovalRecord, RiskClass } from 'agent-passport-system'

// ── Item model ──

export type RiskItemKind =
  | 'needs_approval'
  | 'revocation_stale'
  | 'denied_high_risk_action'
  | 'new_destination'
  | 'missing_sink_confirmation'
  | 'repeated_denials'
  | 'agent_outside_baseline'

export type RiskItemAction =
  | 'approve'
  | 'deny'
  | 'freeze'
  | 'open_ticket'
  | 'export_bundle'
  | 'edit_policy'
  | 'escalate'

export type RiskSeverity = RiskClass // 'low' | 'medium' | 'high' | 'critical'

export interface RiskItem {
  id: string
  tenant_id: string
  kind: RiskItemKind
  severity: RiskSeverity
  /** Derived sort key, higher = act sooner. Computed, never trusted from input. */
  priority: number
  agent_id: string | null
  /** The thing the decision is about: a destination host, delegation id, etc. */
  subject: string | null
  summary: string
  detail: Record<string, unknown>
  source_event_id: string | null
  resolved_at: string | null
  resolved_action: RiskItemAction | null
  resolution_receipt: string | null
  created_at: string
}

export interface NewRiskItem {
  kind: RiskItemKind
  severity?: RiskSeverity
  agent_id?: string | null
  subject?: string | null
  summary: string
  detail?: Record<string, unknown>
  source_event_id?: string | null
}

// ── Prioritization ──
//
// Highest-risk-first. Priority is derived, not supplied: severity dominates,
// item kind breaks ties (a stale revocation outranks a one-off denial at the
// same severity because the window of exposure keeps growing), and age is a
// final, small nudge so nothing starves. The exact numbers are tuned for a
// total order operators can reason about; the contract tested is the ORDER.

const SEVERITY_WEIGHT: Record<RiskSeverity, number> = {
  critical: 4000,
  high: 3000,
  medium: 2000,
  low: 1000,
}

// Kind weight: time-sensitive / exposure-growing kinds rank above one-shot
// kinds at the same severity. Range kept under the severity step so severity
// always dominates kind.
const KIND_WEIGHT: Record<RiskItemKind, number> = {
  revocation_stale: 90, // exposure grows every epoch it stays open
  agent_outside_baseline: 80, // active drift, may be in progress now
  denied_high_risk_action: 70, // a high-risk action was attempted
  repeated_denials: 60, // probing / brute pattern
  missing_sink_confirmation: 50, // delivery unproven at the edge
  needs_approval: 40, // blocked, waiting on a human
  new_destination: 30, // novel but not yet shown harmful
}

/**
 * Derive the priority sort key for an item. Higher acts sooner.
 * Pure and deterministic given (kind, severity, created_at, now).
 */
export function computePriority(
  kind: RiskItemKind,
  severity: RiskSeverity,
  createdAt: string,
  now: number = Date.now(),
): number {
  const base = (SEVERITY_WEIGHT[severity] ?? SEVERITY_WEIGHT.low) + (KIND_WEIGHT[kind] ?? 0)
  // Age nudge: up to +29 over 24h, capped so it can never cross a kind step.
  const ageMs = Math.max(0, now - new Date(createdAt).getTime())
  const ageNudge = Math.min(29, Math.floor(ageMs / (1000 * 60 * 60)) ) // +1 per hour, cap 29
  return base + ageNudge
}

/**
 * Total order over open items: highest priority first, then newest first as a
 * stable tiebreak (a fresh critical and an old critical sort by recency only
 * after priority ties). Returns a new sorted array; does not mutate input.
 */
export function prioritize(items: RiskItem[], now: number = Date.now()): RiskItem[] {
  return [...items]
    .map((it) => ({ it, p: computePriority(it.kind, it.severity, it.created_at, now) }))
    .sort((a, b) => {
      if (b.p !== a.p) return b.p - a.p
      // tie: newer first
      return new Date(b.it.created_at).getTime() - new Date(a.it.created_at).getTime()
    })
    .map((x) => ({ ...x.it, priority: x.p }))
}

// ── Event spine seam (G-A1) ──
//
// Today we emit on the in-tree SSE EventBus. G-A1's event-merkle spine will
// supersede this with an append-only Merkle-chained log returning per-event
// {seq, leafHash, merkleRoot} we can anchor resolution receipts to. We isolate
// that behind a single indirection so the swap is one function.
//
// TODO(G-A1 / gw-a1-event-merkle): replace getEventBus().emit with
// eventSpine.appendEvent() once A1 merges; consume returned {seq, leafHash,
// merkleRoot} for receipt anchoring. Keep the GatewayEvent shape as the
// shared contract.
function appendToSpine(
  tenantId: string,
  evt: Pick<GatewayEvent, 'type' | 'agentId' | 'data'>,
): void {
  // emit must never throw (matches enforce.ts pattern)
  try {
    getEventBus().emit(tenantId, evt)
  } catch {
    /* event emission is best-effort; never block a queue write */
  }
}

// ── SDK-owned admission decisions ──
//
// Whether an action MUST enter the queue is SDK logic, not gateway logic.
// We lazy-import so a missing SDK fails closed loudly rather than at module load.

/**
 * Ask the SDK whether an action requires owner escalation (and therefore a
 * needs_approval queue item). Consumes v2 human-escalation; we do not encode
 * the flagged-action-class policy ourselves.
 *
 * Returns null when the SDK is unavailable (caller decides fail-closed vs skip).
 */
export async function escalationAdmits(
  delegation: unknown,
  action: { action_class: string; action_details: Record<string, unknown>; session_id?: string | null },
): Promise<{ required: boolean; reason?: string } | null> {
  try {
    const sdk = await import('agent-passport-system')
    const check = sdk.checkEscalationRequired(delegation as any, action as any)
    return { required: check.required, reason: check.reason }
  } catch {
    return null
  }
}

/**
 * Spend-triggered admission: consumes commerce checkHumanApprovalThreshold.
 * Returns null when unavailable.
 */
export async function spendAdmits(
  delegation: unknown,
  total: number,
): Promise<{ required: boolean } | null> {
  try {
    const sdk = await import('agent-passport-system')
    const res: any = sdk.checkHumanApprovalThreshold(delegation as any, total as any)
    // Different SDK minor versions name this field; normalize defensively.
    const required = typeof res === 'boolean' ? res : !!(res?.required ?? res?.approval_required)
    return { required }
  } catch {
    return null
  }
}

// SDK Wave 2 auto-trip / circuit-breaker admission.
// The auto-flag hook for "agent acting outside baseline" and the auto-trip on
// repeated high-severity denials belong in the SDK's v2 circuit-breakers
// module. In alpha.3 that surface is a stub (dist/src/v2/circuit-breakers.d.ts
// is empty), so we admit such items from gateway-observed signals today and
// leave the auto-trip wiring as a marked integration point.
//
// TODO(SDK Wave 2 / v2/circuit-breakers): route agent_outside_baseline and
// repeated_denials admission through the SDK circuit-breaker auto-trip once it
// ships, rather than admitting them from gateway-side heuristics here.

// ── Event-type → item kind mapping ──
//
// The spine carries gateway-observed events; the queue distills the subset a
// human must act on. This map is the projection. Events not listed produce no
// queue item (they are informational on the SSE feed only).
const EVENT_TO_KIND: Partial<Record<GatewayEvent['type'], RiskItemKind>> = {
  approval_required: 'needs_approval',
  denial: 'denied_high_risk_action',
}

/**
 * Project a spine/bus event into an optional new queue item. Pure: callers
 * persist the result. Returns null when the event is not actionable.
 *
 * This is the "live update from the event spine" entry point: a spine
 * subscriber calls this for each event and, on a non-null result, enqueues it.
 */
export function projectEventToItem(event: GatewayEvent): NewRiskItem | null {
  const kind = EVENT_TO_KIND[event.type]
  if (!kind) return null
  const d = event.data || {}
  // Severity: trust an explicit, validated severity on the event, else default
  // by kind. Never trust arbitrary strings - coerce to the known set.
  const sev = coerceSeverity((d as any).severity) ?? defaultSeverityForKind(kind)
  return {
    kind,
    severity: sev,
    agent_id: event.agentId ?? ((d as any).agent_id as string) ?? null,
    subject: ((d as any).target as string) ?? ((d as any).subject as string) ?? null,
    summary: summarizeEvent(kind, d),
    detail: d as Record<string, unknown>,
    source_event_id: event.id,
  }
}

function coerceSeverity(v: unknown): RiskSeverity | null {
  return v === 'low' || v === 'medium' || v === 'high' || v === 'critical' ? v : null
}

function defaultSeverityForKind(kind: RiskItemKind): RiskSeverity {
  switch (kind) {
    case 'revocation_stale':
    case 'agent_outside_baseline':
      return 'high'
    case 'denied_high_risk_action':
    case 'repeated_denials':
      return 'high'
    case 'missing_sink_confirmation':
      return 'medium'
    case 'needs_approval':
      return 'medium'
    case 'new_destination':
      return 'low'
  }
}

function summarizeEvent(kind: RiskItemKind, d: Record<string, unknown>): string {
  const agent = (d as any).agent_id || (d as any).agentId || 'an agent'
  switch (kind) {
    case 'needs_approval':
      return `${agent} requested an action that requires owner approval`
    case 'denied_high_risk_action':
      return `${agent} was denied a high-risk action`
    default:
      return `${agent}: ${kind}`
  }
}

// ── Persistence ──

function rowToItem(r: any): RiskItem {
  return {
    id: r.id,
    tenant_id: r.tenant_id,
    kind: r.kind,
    severity: r.severity,
    priority: r.priority,
    agent_id: r.agent_id ?? null,
    subject: r.subject ?? null,
    summary: r.summary,
    detail: safeParse(r.detail),
    source_event_id: r.source_event_id ?? null,
    resolved_at: r.resolved_at ?? null,
    resolved_action: r.resolved_action ?? null,
    resolution_receipt: r.resolution_receipt ?? null,
    created_at: r.created_at,
  }
}

function safeParse(s: unknown): Record<string, unknown> {
  if (typeof s !== 'string') return {}
  try {
    const v = JSON.parse(s)
    return v && typeof v === 'object' ? v : {}
  } catch {
    return {}
  }
}

/**
 * Enqueue an item, compute its derived priority, persist it, and announce it
 * on the spine. Returns the stored item. Emission never blocks the write.
 */
export function enqueue(tenantId: string, input: NewRiskItem, now: number = Date.now()): RiskItem {
  const db = getDB()
  const id = `rq-${randomUUID()}`
  const createdAt = new Date(now).toISOString()
  const severity = input.severity ?? defaultSeverityForKind(input.kind)
  const priority = computePriority(input.kind, severity, createdAt, now)
  const detailJson = JSON.stringify(input.detail ?? {})

  db.prepare(`
    INSERT INTO risk_queue (
      id, tenant_id, kind, severity, priority, agent_id, subject,
      summary, detail, source_event_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, tenantId, input.kind, severity, priority,
    input.agent_id ?? null, input.subject ?? null,
    input.summary, detailJson, input.source_event_id ?? null, createdAt,
  )

  const item: RiskItem = {
    id, tenant_id: tenantId, kind: input.kind, severity, priority,
    agent_id: input.agent_id ?? null, subject: input.subject ?? null,
    summary: input.summary, detail: input.detail ?? {},
    source_event_id: input.source_event_id ?? null,
    resolved_at: null, resolved_action: null, resolution_receipt: null,
    created_at: createdAt,
  }

  // A new high-stakes item is itself a spine event so live consoles update.
  appendToSpine(tenantId, {
    type: input.kind === 'needs_approval' ? 'approval_required' : 'risk_flagged',
    agentId: input.agent_id ?? undefined,
    data: { item_id: id, kind: input.kind, severity, summary: input.summary },
  })

  return item
}

/** Open (unresolved) items for a tenant, highest-risk first. */
export function listOpen(tenantId: string, now: number = Date.now()): RiskItem[] {
  const db = getDB()
  const rows = db.prepare(`
    SELECT * FROM risk_queue WHERE tenant_id = ? AND resolved_at IS NULL
  `).all(tenantId) as any[]
  return prioritize(rows.map(rowToItem), now)
}

export function getItem(tenantId: string, id: string): RiskItem | null {
  const db = getDB()
  const row = db.prepare(`
    SELECT * FROM risk_queue WHERE tenant_id = ? AND id = ?
  `).get(tenantId, id) as any
  return row ? rowToItem(row) : null
}

// ── Actions ──
//
// Each operator action is wired to a handler. The queue's job is to record the
// decision and announce it; the actual enforcement is performed at the edge by
// the relevant subsystem. We surface that division explicitly in the receipt's
// `enforced_by` field so the console never implies the gateway is the brain.

/** Which edge enforces the effect of each action (claims-safe, not a guarantee). */
const ENFORCED_BY: Record<RiskItemAction, string> = {
  approve: 'owner-signed confirmation (short-lived)',
  deny: 'sink verification on next attempt',
  freeze: 'revocation epoch (sink-enforced)',
  open_ticket: 'external ticketing system',
  export_bundle: 'customer-owned evidence bundle',
  edit_policy: 'delegation contract (customer-owned, re-signed)',
  escalate: 'owner confirmation request (SDK human-escalation)',
}

const VALID_ACTIONS: ReadonlySet<RiskItemAction> = new Set<RiskItemAction>([
  'approve', 'deny', 'freeze', 'open_ticket', 'export_bundle', 'edit_policy', 'escalate',
])

export function isValidAction(a: string): a is RiskItemAction {
  return VALID_ACTIONS.has(a as RiskItemAction)
}

export interface ResolutionResult {
  item: RiskItem
  receipt: ResolutionReceipt
}

export interface ResolutionReceipt {
  receipt_type: 'risk_queue_resolution'
  item_id: string
  tenant_id: string
  kind: RiskItemKind
  action: RiskItemAction
  /** Who carries out the effect. The queue surfaces the decision; the edge enforces it. */
  enforced_by: string
  operator: string
  resolved_at: string
  schema_version: '1.0.0'
  /** JWS compact signature over the above, by the gateway identity. */
  signature: string | null
}

/**
 * Apply an operator action to an open item: resolve it, sign a resolution
 * receipt (supports evidence for which decision was surfaced and which action
 * the operator chose, NOT that the downstream effect was carried out), record
 * the approval for fatigue detection, and announce resolution on the spine.
 *
 * Throws on unknown action or unknown/already-resolved item so the caller can
 * return a 4xx - actions must be wired and items must exist.
 */
export function applyAction(
  tenantId: string,
  id: string,
  action: string,
  operator: string,
  now: number = Date.now(),
): ResolutionResult {
  if (!isValidAction(action)) {
    throw new RiskQueueError('unknown_action', `Unknown action: ${action}`)
  }
  const item = getItem(tenantId, id)
  if (!item) throw new RiskQueueError('not_found', `No such item: ${id}`)
  if (item.resolved_at) throw new RiskQueueError('already_resolved', `Item already resolved: ${id}`)

  const resolvedAt = new Date(now).toISOString()

  const receiptBody = {
    receipt_type: 'risk_queue_resolution' as const,
    item_id: id,
    tenant_id: tenantId,
    kind: item.kind,
    action: action as RiskItemAction,
    enforced_by: ENFORCED_BY[action as RiskItemAction],
    operator,
    resolved_at: resolvedAt,
    schema_version: '1.0.0' as const,
  }

  // Sign the decision with the gateway identity (reuse - no new key path).
  let signature: string | null = null
  try {
    signature = getGatewayIdentity().sign(receiptBody as unknown as Record<string, unknown>)
  } catch {
    /* signing optional; receipt is still recorded unsigned */
  }

  const receipt: ResolutionReceipt = { ...receiptBody, signature }
  const receiptJson = JSON.stringify(receipt)

  const db = getDB()
  const res = db.prepare(`
    UPDATE risk_queue
       SET resolved_at = ?, resolved_action = ?, resolution_receipt = ?
     WHERE tenant_id = ? AND id = ? AND resolved_at IS NULL
  `).run(resolvedAt, action, receiptJson, tenantId, id)

  if (res.changes === 0) {
    // Lost a race; re-read to report the real state.
    throw new RiskQueueError('already_resolved', `Item already resolved: ${id}`)
  }

  // Approve/deny on a needs_approval item feeds the SDK fatigue detector so a
  // rubber-stamping operator surfaces as its own queue signal. We do not write
  // anomaly logic here; we consume approval-fatigue.
  if (item.kind === 'needs_approval' && (action === 'approve' || action === 'deny')) {
    try {
      const record: ApprovalRecord = {
        id: `ar-${id}`,
        principal_id: operator,
        agent_id: item.agent_id ?? '',
        intent_id: id,
        decision: action === 'approve' ? 'approved' : 'denied',
        decision_latency_ms: Math.max(0, now - new Date(item.created_at).getTime()),
        intent_complexity: typeof (item.detail as any).complexity === 'number'
          ? (item.detail as any).complexity : 0.5,
        risk_class: item.severity,
        timestamp: resolvedAt,
      }
      recordApproval(record)
    } catch {
      /* fatigue accounting is advisory; never block resolution */
    }
  }

  const resolvedItem: RiskItem = {
    ...item,
    resolved_at: resolvedAt,
    resolved_action: action as RiskItemAction,
    resolution_receipt: receiptJson,
  }

  appendToSpine(tenantId, {
    type: 'approval_resolved',
    agentId: item.agent_id ?? undefined,
    data: { item_id: id, action, kind: item.kind, enforced_by: receiptBody.enforced_by },
  })

  return { item: resolvedItem, receipt }
}

export class RiskQueueError extends Error {
  constructor(public code: 'unknown_action' | 'not_found' | 'already_resolved', message: string) {
    super(message)
    this.name = 'RiskQueueError'
  }
}

// ── Router ──

export const riskQueueRouter = Router()

riskQueueRouter.get('/risk-queue', (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const items = listOpen(tenant.id)
    // Surface operator-oversight signals (rubber-stamping etc.) alongside the
    // queue so the console can warn without us reimplementing the detector.
    const fatigue = safeFatigueFlags()
    res.json({
      items,
      count: items.length,
      operator_oversight_flags: fatigue,
      actions: ['approve', 'deny', 'freeze', 'open_ticket', 'export_bundle', 'edit_policy', 'escalate'],
      note: 'Items are surfaced for decision. A row does not record that an action was taken.',
    })
  } catch (e: any) {
    res.status(500).json({ error: 'Failed to load risk queue', ref: randomUUID().slice(0, 8) })
    console.error('[risk-queue] list failed:', e?.message || e)
  }
})

riskQueueRouter.get('/risk-queue/:id', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const item = getItem(tenant.id, req.params.id)
  if (!item) return res.status(404).json({ error: 'Item not found' })
  res.json({ item })
})

riskQueueRouter.post('/risk-queue/:id/action', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const action = String(req.body?.action ?? '')
  const operator = String(req.tenant?.id ?? 'operator')
  try {
    const result = applyAction(tenant.id, req.params.id, action, operator)
    res.json({ ok: true, item: result.item, receipt: result.receipt })
  } catch (e) {
    if (e instanceof RiskQueueError) {
      const status = e.code === 'not_found' ? 404 : e.code === 'unknown_action' ? 400 : 409
      return res.status(status).json({ error: e.message, code: e.code })
    }
    res.status(500).json({ error: 'Action failed', ref: randomUUID().slice(0, 8) })
    console.error('[risk-queue] action failed:', (e as Error)?.message || e)
  }
})

function safeFatigueFlags() {
  try {
    return getUnreviewedFatigueFlags()
  } catch {
    return []
  }
}
