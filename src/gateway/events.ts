// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Real-time SSE Event Stream — live evaluations, denials, receipts, revocations.
 *
 * GET /api/v1/events/stream — Server-Sent Events endpoint
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
  timestamp: string
  agentId?: string
  data: Record<string, unknown>
}

// ── Event Bus ──

type EventCallback = (event: GatewayEvent) => void

class EventBus {
  private subscribers = new Map<string, Set<EventCallback>>()

  emit(tenantId: string, event: Omit<GatewayEvent, 'id' | 'timestamp'>): void {
    const full: GatewayEvent = {
      ...event,
      id: randomUUID(),
      timestamp: new Date().toISOString(),
    }
    const subs = this.subscribers.get(tenantId)
    if (subs) {
      for (const cb of subs) {
        try { cb(full) } catch { /* subscriber error must not crash bus */ }
      }
    }
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
  const typeFilter = req.query.types
    ? (req.query.types as string).split(',').map((t: string) => t.trim()).filter(Boolean)
    : null

  // SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  })

  // Initial connection event
  res.write(`data: ${JSON.stringify({ type: 'connected', tenantId: tenant.id, timestamp: new Date().toISOString() })}\n\n`)

  // Subscribe to events
  const bus = getEventBus()
  const callback: EventCallback = (event) => {
    if (typeFilter && !typeFilter.includes(event.type)) return
    res.write(`id: ${event.id}\n`)
    res.write(`event: ${event.type}\n`)
    res.write(`data: ${JSON.stringify(event)}\n\n`)
  }

  bus.subscribe(tenant.id, callback)

  // Heartbeat every 30s
  const heartbeat = setInterval(() => {
    res.write(`: heartbeat ${new Date().toISOString()}\n\n`)
  }, 30000)

  // Cleanup on close
  req.on('close', () => {
    clearInterval(heartbeat)
    bus.unsubscribe(tenant.id, callback)
  })
})
