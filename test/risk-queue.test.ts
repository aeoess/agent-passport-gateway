// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// G-A3 Risk Queue - unit tests.
//
// Covers, with negatives:
//   1. Prioritization order is correct (highest-risk first, kind tiebreak,
//      age nudge bounded so it never crosses a kind/severity step).
//   2. Each operator action is wired to a handler (resolve + signed receipt),
//      including the negatives: unknown action, missing item, double-resolve.
//   3. Live update from the event spine (mocked bus): enqueue and resolve emit
//      on the bus, and an inbound event projects into a queue item.
//   4. SDK projection of event -> item kind.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { getEventBus, type GatewayEvent } from '../src/gateway/events.js'
import {
  computePriority,
  prioritize,
  projectEventToItem,
  enqueue,
  listOpen,
  getItem,
  applyAction,
  isValidAction,
  RiskQueueError,
  type RiskItem,
  type RiskItemKind,
  type RiskSeverity,
} from '../src/gateway/risk-queue.js'

const TENANT = 'tenant-rq'

function fakeItem(over: Partial<RiskItem> = {}): RiskItem {
  return {
    id: over.id ?? 'rq-x',
    tenant_id: TENANT,
    kind: over.kind ?? 'needs_approval',
    severity: over.severity ?? 'medium',
    priority: 0,
    agent_id: over.agent_id ?? null,
    subject: over.subject ?? null,
    summary: over.summary ?? 'x',
    detail: over.detail ?? {},
    source_event_id: over.source_event_id ?? null,
    resolved_at: over.resolved_at ?? null,
    resolved_action: over.resolved_action ?? null,
    resolution_receipt: over.resolution_receipt ?? null,
    created_at: over.created_at ?? '2026-05-31T00:00:00.000Z',
  }
}

// ─── 1. Prioritization ───────────────────────────────────────────────

describe('risk-queue prioritization', () => {
  const NOW = Date.parse('2026-05-31T00:00:00.000Z')

  it('orders by severity first: critical > high > medium > low', () => {
    const items = [
      fakeItem({ id: 'low', kind: 'needs_approval', severity: 'low' }),
      fakeItem({ id: 'crit', kind: 'needs_approval', severity: 'critical' }),
      fakeItem({ id: 'med', kind: 'needs_approval', severity: 'medium' }),
      fakeItem({ id: 'high', kind: 'needs_approval', severity: 'high' }),
    ]
    const order = prioritize(items, NOW).map((i) => i.id)
    assert.deepEqual(order, ['crit', 'high', 'med', 'low'])
  })

  it('breaks ties by kind: a stale revocation outranks a one-off denial at equal severity', () => {
    const items = [
      fakeItem({ id: 'denial', kind: 'denied_high_risk_action', severity: 'high' }),
      fakeItem({ id: 'stale', kind: 'revocation_stale', severity: 'high' }),
      fakeItem({ id: 'newdest', kind: 'new_destination', severity: 'high' }),
    ]
    const order = prioritize(items, NOW).map((i) => i.id)
    assert.deepEqual(order, ['stale', 'denial', 'newdest'])
  })

  it('severity always dominates kind (a critical low-priority kind beats a high high-priority kind)', () => {
    const critNewDest = computePriority('new_destination', 'critical', '2026-05-31T00:00:00Z', NOW)
    const highStale = computePriority('revocation_stale', 'high', '2026-05-31T00:00:00Z', NOW)
    assert.ok(critNewDest > highStale, 'critical/new_destination must outrank high/revocation_stale')
  })

  it('age nudges priority up but is bounded so it never crosses a kind step', () => {
    const fresh = computePriority('needs_approval', 'high', '2026-05-31T00:00:00.000Z', NOW)
    const old = computePriority(
      'needs_approval', 'high', '2026-05-30T00:00:00.000Z', NOW, // 24h older
    )
    assert.ok(old > fresh, 'older item should sort sooner at equal kind+severity')
    // The smallest kind step is 10 (KIND_WEIGHT spacing); age nudge caps at 29
    // BUT must never let a lower kind at the same severity overtake a higher
    // kind. Verify the cap directly: a very old low-kind item still loses to a
    // fresh higher-kind item at the same severity.
    const oldLowKind = computePriority('new_destination', 'high', '2020-01-01T00:00:00.000Z', NOW)
    const freshHighKind = computePriority('revocation_stale', 'high', '2026-05-31T00:00:00.000Z', NOW)
    assert.ok(freshHighKind > oldLowKind, 'fresh higher-kind must still beat very old lower-kind')
  })

  it('prioritize does not mutate its input array', () => {
    const items = [fakeItem({ id: 'a', severity: 'low' }), fakeItem({ id: 'b', severity: 'high' })]
    const before = items.map((i) => i.id)
    prioritize(items, NOW)
    assert.deepEqual(items.map((i) => i.id), before)
  })
})

// ─── 4. SDK / event projection ───────────────────────────────────────

describe('risk-queue event projection', () => {
  function evt(over: Partial<GatewayEvent>): GatewayEvent {
    return {
      id: over.id ?? 'evt-1',
      type: over.type ?? 'denial',
      timestamp: over.timestamp ?? '2026-05-31T00:00:00Z',
      agentId: over.agentId,
      data: over.data ?? {},
    }
  }

  it('projects an approval_required event into a needs_approval item', () => {
    const item = projectEventToItem(evt({ type: 'approval_required', agentId: 'agent-7', data: {} }))
    assert.ok(item)
    assert.equal(item!.kind, 'needs_approval')
    assert.equal(item!.agent_id, 'agent-7')
    assert.equal(item!.source_event_id, 'evt-1')
  })

  it('projects a denial event into a denied_high_risk_action item', () => {
    const item = projectEventToItem(evt({ type: 'denial', data: { agent_id: 'a9', target: 'api.x.test' } }))
    assert.ok(item)
    assert.equal(item!.kind, 'denied_high_risk_action')
    assert.equal(item!.subject, 'api.x.test')
  })

  it('returns null for non-actionable events (no queue item)', () => {
    assert.equal(projectEventToItem(evt({ type: 'receipt_stored' })), null)
    assert.equal(projectEventToItem(evt({ type: 'spend_update' })), null)
  })

  it('coerces an untrusted severity string to the default for the kind', () => {
    const item = projectEventToItem(evt({ type: 'denial', data: { severity: 'EXTREME' } }))
    assert.ok(item)
    // 'EXTREME' is not in the known set -> default severity for the kind ('high')
    assert.equal(item!.severity, 'high')
  })

  it('honors an explicit valid severity on the event', () => {
    const item = projectEventToItem(evt({ type: 'denial', data: { severity: 'critical' } }))
    assert.equal(item!.severity, 'critical')
  })
})

// ─── 2 & 3. Persistence, actions, and live emission ──────────────────

describe('risk-queue persistence, actions, and live spine emission', () => {
  before(() => {
    initDB(':memory:')
    // risk-queue rows FK to tenants(id); satisfy it.
    getDB().exec(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES ('${TENANT}', 'RQ', 'rq@test.invalid')`)
    initGatewayIdentity()
  })

  beforeEach(() => {
    getDB().exec('DELETE FROM risk_queue')
  })

  it('isValidAction accepts the seven wired actions and rejects others', () => {
    for (const a of ['approve', 'deny', 'freeze', 'open_ticket', 'export_bundle', 'edit_policy', 'escalate']) {
      assert.equal(isValidAction(a), true, a + ' should be valid')
    }
    assert.equal(isValidAction('nuke'), false)
    assert.equal(isValidAction(''), false)
  })

  it('enqueue persists an item with a derived priority and lists it open', () => {
    const item = enqueue(TENANT, { kind: 'needs_approval', severity: 'high', summary: 's', agent_id: 'a1' })
    assert.ok(item.id.startsWith('rq-'))
    assert.ok(item.priority > 0)
    const open = listOpen(TENANT)
    assert.equal(open.length, 1)
    assert.equal(open[0].id, item.id)
  })

  it('listOpen returns items in priority order (highest risk first)', () => {
    enqueue(TENANT, { kind: 'new_destination', severity: 'low', summary: 'low' })
    enqueue(TENANT, { kind: 'revocation_stale', severity: 'critical', summary: 'crit' })
    enqueue(TENANT, { kind: 'needs_approval', severity: 'medium', summary: 'med' })
    const open = listOpen(TENANT)
    assert.deepEqual(open.map((i) => i.summary), ['crit', 'med', 'low'])
  })

  it('each action is wired: applyAction resolves the item and signs a receipt', () => {
    for (const action of ['approve', 'deny', 'freeze', 'open_ticket', 'export_bundle', 'edit_policy', 'escalate']) {
      const item = enqueue(TENANT, { kind: 'needs_approval', severity: 'medium', summary: 'for ' + action })
      const { item: resolved, receipt } = applyAction(TENANT, item.id, action, 'op-1')
      assert.equal(resolved.resolved_action, action)
      assert.ok(resolved.resolved_at)
      assert.equal(receipt.action, action)
      assert.equal(receipt.receipt_type, 'risk_queue_resolution')
      assert.ok(receipt.enforced_by, 'receipt names the enforcing edge for ' + action)
      assert.ok(receipt.signature, 'receipt is signed by the gateway identity')
      // A resolved item leaves the open queue.
      assert.equal(getItem(TENANT, item.id)!.resolved_at !== null, true)
    }
    assert.equal(listOpen(TENANT).length, 0)
  })

  it('NEGATIVE: unknown action throws unknown_action and does not resolve', () => {
    const item = enqueue(TENANT, { kind: 'needs_approval', severity: 'low', summary: 'x' })
    assert.throws(() => applyAction(TENANT, item.id, 'launch_missiles', 'op'),
      (e: unknown) => e instanceof RiskQueueError && e.code === 'unknown_action')
    assert.equal(getItem(TENANT, item.id)!.resolved_at, null)
  })

  it('NEGATIVE: action on a missing item throws not_found', () => {
    assert.throws(() => applyAction(TENANT, 'rq-does-not-exist', 'approve', 'op'),
      (e: unknown) => e instanceof RiskQueueError && e.code === 'not_found')
  })

  it('NEGATIVE: resolving an already-resolved item throws already_resolved', () => {
    const item = enqueue(TENANT, { kind: 'needs_approval', severity: 'low', summary: 'x' })
    applyAction(TENANT, item.id, 'approve', 'op')
    assert.throws(() => applyAction(TENANT, item.id, 'deny', 'op'),
      (e: unknown) => e instanceof RiskQueueError && e.code === 'already_resolved')
  })

  it('tenant isolation: one tenant cannot resolve another tenant item', () => {
    const item = enqueue(TENANT, { kind: 'needs_approval', severity: 'low', summary: 'x' })
    assert.throws(() => applyAction('other-tenant', item.id, 'approve', 'op'),
      (e: unknown) => e instanceof RiskQueueError && e.code === 'not_found')
  })

  // ── Live update from the event spine (mocked bus) ──

  it('enqueue emits a live event on the bus (spine seam)', () => {
    const seen: GatewayEvent[] = []
    const cb = (e: GatewayEvent) => seen.push(e)
    getEventBus().subscribe(TENANT, cb)
    try {
      enqueue(TENANT, { kind: 'needs_approval', severity: 'high', summary: 'live', agent_id: 'a1' })
    } finally {
      getEventBus().unsubscribe(TENANT, cb)
    }
    const types = seen.map((e) => e.type)
    assert.ok(types.includes('approval_required'), 'needs_approval enqueue emits approval_required')
  })

  it('a risk_flagged item enqueue emits risk_flagged on the bus', () => {
    const seen: GatewayEvent[] = []
    const cb = (e: GatewayEvent) => seen.push(e)
    getEventBus().subscribe(TENANT, cb)
    try {
      enqueue(TENANT, { kind: 'revocation_stale', severity: 'high', summary: 'flag' })
    } finally {
      getEventBus().unsubscribe(TENANT, cb)
    }
    assert.ok(seen.some((e) => e.type === 'risk_flagged'))
  })

  it('applyAction emits approval_resolved on the bus', () => {
    const item = enqueue(TENANT, { kind: 'needs_approval', severity: 'medium', summary: 'r' })
    const seen: GatewayEvent[] = []
    const cb = (e: GatewayEvent) => seen.push(e)
    getEventBus().subscribe(TENANT, cb)
    try {
      applyAction(TENANT, item.id, 'approve', 'op')
    } finally {
      getEventBus().unsubscribe(TENANT, cb)
    }
    const resolved = seen.find((e) => e.type === 'approval_resolved')
    assert.ok(resolved, 'resolution emits approval_resolved')
    assert.equal((resolved!.data as any).item_id, item.id)
    assert.equal((resolved!.data as any).action, 'approve')
  })

  it('full live loop: an inbound spine event projects, enqueues, and surfaces in the queue', () => {
    // Simulate the spine handing the queue a denial event; project then enqueue.
    const inbound: GatewayEvent = {
      id: 'evt-spine-1',
      type: 'denial',
      timestamp: new Date().toISOString(),
      agentId: 'agent-spine',
      data: { target: 'sink.test', severity: 'critical' },
    }
    const proj = projectEventToItem(inbound)
    assert.ok(proj)
    const stored = enqueue(TENANT, proj!)
    const open = listOpen(TENANT)
    assert.equal(open[0].id, stored.id)
    assert.equal(open[0].kind, 'denied_high_risk_action')
    assert.equal(open[0].severity, 'critical')
    assert.equal(open[0].source_event_id, 'evt-spine-1')
  })
})
