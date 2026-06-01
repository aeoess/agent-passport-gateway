// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Delivery dispatcher (retry + dead-letter)
// ══════════════════════════════════════════════════════════════════
// The spec's "retry with backoff" + "dead-letter queue" requirement is owned
// by G-A1's EgressDispatcher. We do NOT write a second retry/DLQ engine. This
// module is a thin seam over the SAME policy shape (maxAttempts / baseDelayMs /
// maxDelayMs, exponential backoff) operating on a ConnectorEvent + ConnectorSink
// instead of a raw EgressEnvelope, plus a durable dead-letter persistence step
// the in-memory G-A1 queue does not do. When egress/ merges, the retry loop here
// is replaced by delegating to EgressDispatcher.dispatch and this file keeps only
// the ConnectorEvent->EgressEnvelope adaptation and the DB persistence.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { getEventBus } from '../../gateway/events.js'
import type { ConnectorEvent } from './event-schema.js'
import type { ConnectorKind, ConnectorSink } from './connector.js'

// TODO(G-A1 / gw-a1-event-merkle): replace this RetryPolicy + the retry loop in
//   deliver() with { EgressDispatcher, DEFAULT_RETRY_POLICY, backoffDelay,
//   type RetryPolicy } from '../../gateway/egress/index.js'. The shape below is
//   field-identical to G-A1's so the swap is mechanical.
export interface RetryPolicy {
  maxAttempts: number
  baseDelayMs: number
  maxDelayMs: number
}

/** Identical to G-A1 DEFAULT_RETRY_POLICY (maxAttempts 4, base 200, cap 5000). */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 200,
  maxDelayMs: 5000,
}

/** Exponential backoff, capped. Mirrors G-A1 backoffDelay. Exposed for tests. */
export function backoffDelay(attempt: number, policy: RetryPolicy): number {
  const raw = policy.baseDelayMs * Math.pow(2, Math.max(0, attempt - 1))
  return Math.min(raw, policy.maxDelayMs)
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

export interface DeliveryResult {
  delivered: boolean
  attempts: number
  deadLetterId: string | null
}

export interface ConnectorDispatcherOptions {
  policy?: RetryPolicy
  /** Override the backoff wait, primarily for deterministic tests. */
  waitFn?: (ms: number) => Promise<void>
}

/**
 * Deliver one connector event through one sink with bounded retry. On
 * exhaustion the envelope is persisted to connector_dead_letters so an operator
 * can drain or redeliver it. Every outcome is emitted on the base EventBus.
 */
export class ConnectorDispatcher {
  private readonly policy: RetryPolicy
  private readonly waitFn: (ms: number) => Promise<void>

  constructor(opts?: ConnectorDispatcherOptions) {
    this.policy = opts?.policy ?? DEFAULT_RETRY_POLICY
    this.waitFn = opts?.waitFn ?? sleep
  }

  async deliver(
    tenantId: string,
    kind: ConnectorKind,
    sink: ConnectorSink,
    event: ConnectorEvent,
    endpointId: string | null = null,
  ): Promise<DeliveryResult> {
    let lastError = ''
    for (let attempt = 1; attempt <= this.policy.maxAttempts; attempt++) {
      try {
        await sink(event)
        // NOTE: emit against the BASE void EventBus contract - do not consume a
        // return value. G-A1's EventBus.emit returns GatewayEvent; this stays
        // forward-compatible by ignoring any return.
        safeEmit(tenantId, 'connector_delivered', {
          connector_kind: kind,
          event_id: event.event_id,
          event_type: event.event_type,
          attempts: attempt,
          endpoint_id: endpointId,
        })
        return { delivered: true, attempts: attempt, deadLetterId: null }
      } catch (e: unknown) {
        lastError = e instanceof Error ? e.message : String(e)
        const willRetry = attempt < this.policy.maxAttempts
        safeEmit(tenantId, 'connector_retry', {
          connector_kind: kind,
          event_id: event.event_id,
          attempt,
          will_retry: willRetry,
          error: lastError,
        })
        if (willRetry) await this.waitFn(backoffDelay(attempt, this.policy))
      }
    }

    const deadLetterId = persistDeadLetter({
      tenantId,
      endpointId,
      kind,
      event,
      attempts: this.policy.maxAttempts,
      lastError,
    })
    safeEmit(tenantId, 'connector_dead_lettered', {
      connector_kind: kind,
      event_id: event.event_id,
      event_type: event.event_type,
      attempts: this.policy.maxAttempts,
      dead_letter_id: deadLetterId,
      error: lastError,
    })
    return { delivered: false, attempts: this.policy.maxAttempts, deadLetterId }
  }

  /** Re-attempt a dead-lettered delivery. Marks the row redelivered on success.
   *  Returns null if the dead-letter id is unknown for this tenant. */
  async redeliver(
    tenantId: string,
    deadLetterId: string,
    sink: ConnectorSink,
  ): Promise<DeliveryResult | null> {
    const db = getDB()
    const row = db
      .prepare(
        `SELECT * FROM connector_dead_letters
           WHERE id = ? AND tenant_id = ? AND redelivered_at IS NULL`,
      )
      .get(deadLetterId, tenantId) as any
    if (!row) return null
    const event = JSON.parse(row.payload) as ConnectorEvent
    const result = await this.deliver(tenantId, row.connector_kind, sink, event, row.endpoint_id)
    if (result.delivered) {
      db.prepare(
        `UPDATE connector_dead_letters SET redelivered_at = datetime('now') WHERE id = ?`,
      ).run(deadLetterId)
    }
    return result
  }
}

/** Count undrained dead letters for a tenant. */
export function deadLetterCount(tenantId: string): number {
  const db = getDB()
  const row = db
    .prepare(
      `SELECT COUNT(*) AS c FROM connector_dead_letters
         WHERE tenant_id = ? AND redelivered_at IS NULL`,
    )
    .get(tenantId) as { c: number }
  return row.c
}

/** Snapshot undrained dead letters for an operator drain endpoint. */
export function listDeadLetters(tenantId: string): Array<{
  id: string
  connector_kind: string
  event_id: string
  event_type: string
  attempts: number
  last_error: string | null
  dead_lettered_at: string
}> {
  const db = getDB()
  return db
    .prepare(
      `SELECT id, connector_kind, event_id, event_type, attempts, last_error, dead_lettered_at
         FROM connector_dead_letters
         WHERE tenant_id = ? AND redelivered_at IS NULL
         ORDER BY dead_lettered_at ASC`,
    )
    .all(tenantId) as any
}

function persistDeadLetter(opts: {
  tenantId: string
  endpointId: string | null
  kind: ConnectorKind
  event: ConnectorEvent
  attempts: number
  lastError: string
}): string {
  const db = getDB()
  const id = randomUUID()
  db.prepare(
    `INSERT INTO connector_dead_letters
       (id, tenant_id, endpoint_id, connector_kind, event_id, event_type, payload, attempts, last_error)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    opts.tenantId,
    opts.endpointId,
    opts.kind,
    opts.event.event_id,
    opts.event.event_type,
    JSON.stringify(opts.event),
    opts.attempts,
    opts.lastError,
  )
  return id
}

function safeEmit(tenantId: string, type: string, data: Record<string, unknown>): void {
  // Cast: connector lifecycle literals are net-new and are added to the
  // GatewayEvent union (see event-types augmentation comment in router.ts) so
  // they merge cleanly with G-A1's union. The base union does not yet list
  // them, so we widen here without consuming any return value.
  try {
    getEventBus().emit(tenantId, { type: type as any, data })
  } catch {
    /* bus failure must not break delivery accounting */
  }
}
