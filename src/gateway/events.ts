// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Real-time SSE Event Stream - live evaluations, denials, receipts, revocations.
 *
 * GET /api/v1/events/stream - Server-Sent Events endpoint
 * Optional: ?types=evaluation,denial to filter event types
 *
 * Nate B Jones Primitive #6: Structured Streaming Events.
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import type { Tenant } from '../auth/api-keys.js'

// ── Event types ──

export interface GatewayEvent {
  id: string
  type: 'evaluation' | 'denial' | 'receipt_stored' | 'revocation' | 'alert'
    | 'agent_registered' | 'delegation_created' | 'spend_update' | 'tenant_created'
    | 'data_source_registered' | 'access_receipt' | 'posture_update'
    | 'recovery_event' | 'settlement_created' | 'derivation_created'
    | 'key_rotated' | 'wallet_provisioned' | 'wallet_transaction'
    | 'wallet_frozen' | 'payment_created' | 'cost_recorded'
    | 'task_created' | 'task_assigned' | 'task_accepted'
    | 'task_evidence' | 'task_reviewed' | 'task_completed' | 'task_cancelled'
    // GEM (G-A1): Merkle aggregation egress event spine. The root and a
    // structural summary travel downstream; granular leaves stay in the
    // local outbox and are fetched out of band on anomaly.
    | 'batch_committed' | 'anchor_submitted' | 'egress_dispatched'
    | 'egress_retry' | 'egress_dead_lettered' | 'leaf_fetch'
  timestamp: string
  agentId?: string
  data: Record<string, unknown>
}

// ── Event Bus ──

type EventCallback = (event: GatewayEvent) => void

/** Bounded per-tenant replay backlog size. The backlog is a short reconnect
 *  window so an SSE client that drops can catch up the events it missed; it
 *  is deliberately small and is NOT a store of record. The durable store of
 *  record for granular receipt leaves is the GEM outbox ledger
 *  (src/gateway/egress/leaf-outbox.ts), fetched out of band on anomaly. */
const DEFAULT_BACKLOG_PER_TENANT = 256

class EventBus {
  private subscribers = new Map<string, Set<EventCallback>>()
  // Durable replay ring: tenantId -> most-recent events, oldest first.
  private backlog = new Map<string, GatewayEvent[]>()
  private backlogLimit: number

  constructor(backlogLimit: number = DEFAULT_BACKLOG_PER_TENANT) {
    this.backlogLimit = Math.max(0, backlogLimit)
  }

  emit(tenantId: string, event: Omit<GatewayEvent, 'id' | 'timestamp'>): GatewayEvent {
    const full: GatewayEvent = {
      ...event,
      id: randomUUID(),
      timestamp: new Date().toISOString(),
    }
    this.record(tenantId, full)
    const subs = this.subscribers.get(tenantId)
    if (subs) {
      for (const cb of subs) {
        try { cb(full) } catch { /* subscriber error must not crash bus */ }
      }
    }
    return full
  }

  private record(tenantId: string, event: GatewayEvent): void {
    if (this.backlogLimit === 0) return
    let ring = this.backlog.get(tenantId)
    if (!ring) { ring = []; this.backlog.set(tenantId, ring) }
    ring.push(event)
    if (ring.length > this.backlogLimit) ring.splice(0, ring.length - this.backlogLimit)
  }

  /** Replay buffered events for a reconnecting subscriber. When afterId is
   *  given, only events emitted after that id are returned (Last-Event-ID
   *  semantics); if afterId is not in the backlog the whole window replays. */
  replay(tenantId: string, afterId?: string, typeFilter?: readonly string[] | null): GatewayEvent[] {
    const ring = this.backlog.get(tenantId)
    if (!ring || ring.length === 0) return []
    let slice = ring
    if (afterId) {
      const idx = ring.findIndex((e) => e.id === afterId)
      if (idx >= 0) slice = ring.slice(idx + 1)
    }
    if (typeFilter && typeFilter.length > 0) {
      slice = slice.filter((e) => typeFilter.includes(e.type))
    }
    return slice
  }

  subscribe(tenantId: string, callback: EventCallback): void {
    let subs = this.subscribers.get(tenantId)
    if (!subs) {
      subs = new Set()
      this.subscribers.set(tenantId, subs)
    }
    subs.add(callback)
  }

  unsubscribe(tenantId: string, callback: EventCallback): void {
    const subs = this.subscribers.get(tenantId)
    if (subs) {
      subs.delete(callback)
      if (subs.size === 0) this.subscribers.delete(tenantId)
    }
  }

  subscriberCount(tenantId: string): number {
    return this.subscribers.get(tenantId)?.size || 0
  }

  backlogSize(tenantId: string): number {
    return this.backlog.get(tenantId)?.length || 0
  }
}

// ── Singleton ──

let _bus: EventBus | null = null

export function getEventBus(): EventBus {
  if (!_bus) _bus = new EventBus()
  return _bus
}

// ── SSE Router ──

export const eventsRouter = Router()

eventsRouter.get('/events/stream', (req: any, res) => {
  const tenant: Tenant = req.tenant

  // M10: per-tenant connection limit
  const bus = getEventBus()
  if (bus.subscriberCount(tenant.id) >= 5) {
    return res.status(429).json({ error: 'Too many SSE connections (max 5 per tenant)' })
  }

  const typeFilter = req.query.types
    ? (req.query.types as string).split(',').map((t: string) => t.trim()).filter(Boolean)
    : null

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  })

  res.write(`data: ${JSON.stringify({ type: 'connected', tenantId: tenant.id, timestamp: new Date().toISOString() })}\n\n`)

  const writeEvent = (event: GatewayEvent) => {
    if (typeFilter && !typeFilter.includes(event.type)) return
    res.write(`id: ${event.id}\n`)
    res.write(`event: ${event.type}\n`)
    res.write(`data: ${JSON.stringify(event)}\n\n`)
  }

  // Durable replay: a reconnecting client that sends Last-Event-ID (header or
  // ?last_event_id=) catches up the bounded backlog it missed before live
  // delivery resumes. No state of record is held here, only a short window.
  const lastEventId = (req.headers['last-event-id'] as string | undefined)
    || (req.query.last_event_id as string | undefined)
  for (const event of bus.replay(tenant.id, lastEventId, typeFilter)) {
    writeEvent(event)
  }

  const callback: EventCallback = writeEvent

  bus.subscribe(tenant.id, callback)

  // P2-14: heartbeat with dead socket detection
  const heartbeat = setInterval(() => {
    const ok = res.write(`: heartbeat ${new Date().toISOString()}\n\n`)
    if (!ok) cleanup()
  }, 30000)

  // P2-14: max 30 min connection duration
  const maxDuration = setTimeout(() => cleanup(), 30 * 60 * 1000)

  function cleanup() {
    clearInterval(heartbeat)
    clearTimeout(maxDuration)
    bus.unsubscribe(tenant.id, callback)
    try { res.end() } catch {}
  }

  req.on('close', cleanup)
})
