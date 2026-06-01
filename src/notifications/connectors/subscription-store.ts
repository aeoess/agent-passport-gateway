// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Webhook endpoint registration + replay window
// ══════════════════════════════════════════════════════════════════
// "Signed webhook subscriptions" with "auth, replay protection via
// nonce+timestamp, ... subscription filtering". Named "endpoint" not
// "subscription" to avoid colliding with Stripe subscriptions and the SSE
// EventBus subscribe/unsubscribe vocabulary.
//
// Each registered endpoint carries a target URL (run through validateExternalUrl
// for SSRF), a per-endpoint secret used to derive the outbound HMAC, and an
// event-type filter. Replay protection is a (scope, nonce) seen-set bounded by a
// freshness window: an envelope older than the window, or a nonce already seen
// inside it, is rejected. This is the same primitive used both for OUTBOUND
// signing metadata and for INBOUND identity-bridge verification.
// ══════════════════════════════════════════════════════════════════

import { randomBytes, randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { validateExternalUrl } from '../../gateway/url-safety.js'
import type { ConnectorEventType } from './event-schema.js'

/** Default replay freshness window. A signed envelope whose timestamp is
 *  further than this from now is rejected; a nonce is remembered for this long.
 *  Five minutes matches common webhook tolerance (Stripe uses 5 min). */
export const DEFAULT_REPLAY_WINDOW_MS = 5 * 60 * 1000

export interface WebhookEndpoint {
  id: string
  tenantId: string
  targetUrl: string
  secret: string
  /** '*' for all, or a comma-free array of ConnectorEventType. */
  eventTypes: ConnectorEventType[] | '*'
  status: 'active' | 'paused'
  createdAt: string
}

export interface RegisterEndpointInput {
  tenantId: string
  targetUrl: string
  eventTypes?: ConnectorEventType[] | '*'
  /** Caller-supplied secret; one is generated if omitted. */
  secret?: string
}

export interface RegisterEndpointResult {
  ok: boolean
  endpoint?: WebhookEndpoint
  error?: string
}

/** Register a signed-webhook endpoint. The target URL is SSRF-validated before
 *  it is ever stored, so the gateway will not later be coerced into delivering
 *  to localhost / metadata services. */
export function registerEndpoint(input: RegisterEndpointInput): RegisterEndpointResult {
  const safety = validateExternalUrl(input.targetUrl)
  if (!safety.safe) {
    return { ok: false, error: `target_url rejected: ${safety.reason}` }
  }
  const db = getDB()
  const id = randomUUID()
  const secret = input.secret && input.secret.length >= 16 ? input.secret : randomBytes(32).toString('hex')
  const eventTypes = input.eventTypes ?? '*'
  const eventTypesStr = eventTypes === '*' ? '*' : eventTypes.join(',')
  db.prepare(
    `INSERT INTO connector_webhook_endpoints (id, tenant_id, target_url, secret, event_types, status)
     VALUES (?, ?, ?, ?, ?, 'active')`,
  ).run(id, input.tenantId, input.targetUrl, secret, eventTypesStr)
  return {
    ok: true,
    endpoint: {
      id,
      tenantId: input.tenantId,
      targetUrl: input.targetUrl,
      secret,
      eventTypes,
      status: 'active',
      createdAt: new Date().toISOString(),
    },
  }
}

function rowToEndpoint(row: any): WebhookEndpoint {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    targetUrl: row.target_url,
    secret: row.secret,
    eventTypes: row.event_types === '*' ? '*' : (row.event_types.split(',').filter(Boolean) as ConnectorEventType[]),
    status: row.status,
    createdAt: row.created_at,
  }
}

/** List a tenant's active endpoints, optionally filtered to those subscribed to
 *  a given event type. Subscription filtering happens here so a connector only
 *  fans out to endpoints that asked for the event. */
export function listEndpoints(tenantId: string, eventType?: ConnectorEventType): WebhookEndpoint[] {
  const db = getDB()
  const rows = db
    .prepare(
      `SELECT * FROM connector_webhook_endpoints
         WHERE tenant_id = ? AND status = 'active'
         ORDER BY created_at ASC`,
    )
    .all(tenantId) as any[]
  const endpoints = rows.map(rowToEndpoint)
  if (!eventType) return endpoints
  return endpoints.filter((e) => e.eventTypes === '*' || e.eventTypes.includes(eventType))
}

export function getEndpoint(tenantId: string, id: string): WebhookEndpoint | null {
  const db = getDB()
  const row = db
    .prepare(`SELECT * FROM connector_webhook_endpoints WHERE id = ? AND tenant_id = ?`)
    .get(id, tenantId) as any
  return row ? rowToEndpoint(row) : null
}

export function deleteEndpoint(tenantId: string, id: string): boolean {
  const db = getDB()
  const res = db
    .prepare(`DELETE FROM connector_webhook_endpoints WHERE id = ? AND tenant_id = ?`)
    .run(id, tenantId)
  return res.changes > 0
}

export function recordDeliveryOutcome(id: string, status: string): void {
  const db = getDB()
  db.prepare(
    `UPDATE connector_webhook_endpoints SET last_delivery_at = datetime('now'), last_status = ? WHERE id = ?`,
  ).run(status, id)
}

// ── Replay protection ─────────────────────────────────────────────

export interface ReplayCheckResult {
  ok: boolean
  reason?: string
}

/**
 * Verify a (timestamp, nonce) pair against the replay window and remember the
 * nonce on success. `scope` separates outbound from inbound and one provider
 * from another so a nonce reused across scopes is not a false positive.
 *
 *   - Reject if the timestamp is outside +/- windowMs of now (stale or skewed).
 *   - Reject if the (scope, nonce) was already seen inside the window (replay).
 *   - Otherwise remember it and accept.
 */
export function checkAndRecordNonce(opts: {
  scope: string
  nonce: string
  timestampMs: number
  tenantId?: string
  windowMs?: number
  nowMs?: number
}): ReplayCheckResult {
  const windowMs = opts.windowMs ?? DEFAULT_REPLAY_WINDOW_MS
  const now = opts.nowMs ?? Date.now()
  if (!Number.isFinite(opts.timestampMs)) {
    return { ok: false, reason: 'timestamp is not a finite number' }
  }
  if (Math.abs(now - opts.timestampMs) > windowMs) {
    return { ok: false, reason: 'timestamp outside replay window (stale or future-dated)' }
  }
  if (!opts.nonce || opts.nonce.length < 8) {
    return { ok: false, reason: 'nonce missing or too short' }
  }

  const db = getDB()
  pruneExpiredNonces(now, windowMs)
  const existing = db
    .prepare(`SELECT 1 FROM connector_seen_nonces WHERE scope = ? AND nonce = ?`)
    .get(opts.scope, opts.nonce)
  if (existing) {
    return { ok: false, reason: 'nonce already seen (replay rejected)' }
  }
  db.prepare(
    `INSERT INTO connector_seen_nonces (nonce, scope, tenant_id, seen_at_ms) VALUES (?, ?, ?, ?)`,
  ).run(opts.nonce, opts.scope, opts.tenantId ?? null, now)
  return { ok: true }
}

/** Drop seen nonces older than the window so the table does not grow without
 *  bound. Anything older than the window can never be a live replay. */
function pruneExpiredNonces(nowMs: number, windowMs: number): void {
  const db = getDB()
  db.prepare(`DELETE FROM connector_seen_nonces WHERE seen_at_ms < ?`).run(nowMs - windowMs)
}
