// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Inbound Identity Bridge (Okta / Entra -> revoke)
// ══════════════════════════════════════════════════════════════════
// The ONE piece of inbound automation the spec permits: an identity provider
// (Okta or Microsoft Entra) signals that a user / service principal was
// offboarded (SCIM DELETE or a deprovision lifecycle event), and the gateway
// maps that to a revoke of the agent / delegation that the offboarded identity
// owned. This is NOT a connector zoo of inbound automation; it is a single,
// bounded bridge whose only effect is to invoke the gateway's existing cascade
// revoke (enforce.ts POST /api/v1/revoke).
//
// Thin gateway: the bridge VERIFIES the inbound signed event at the edge (HMAC
// over the raw body + replay window) before it does anything, then calls the
// same revoke primitive a customer could call by hand. It concentrates no new
// authority: offboard maps to revoke, nothing more.
//
// GATE: framework + the verify/replay/mapping seam is Claude's. The actual
// Okta / Entra request shapes, signature schemes, and SCIM attribute->agent
// resolution are Tima's (Okta/Entra identity bridge). The mapping function
// resolveTargetFromOffboard is a typed seam Tima fills with the real attribute
// lookup. See FOUNDER-GATE notes in the structured report.
// ══════════════════════════════════════════════════════════════════

import { createHmac, timingSafeEqual } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { getEventBus } from '../../gateway/events.js'
import { checkAndRecordNonce } from './subscription-store.js'
import { buildConnectorEvent } from './event-schema.js'
import type { ConnectorEvent } from './event-schema.js'

export type IdentityProvider = 'okta' | 'entra'

/** A normalized offboard event, provider-agnostic. The provider-specific
 *  parsing that produces this is Tima's part of the gate. */
export interface NormalizedOffboard {
  provider: IdentityProvider
  /** The external identity that was offboarded (Okta user id / Entra objectId). */
  externalUserId: string
  /** Optional SCIM userName / UPN for human-readable correlation. */
  userName?: string
  /** Lifecycle action; only deprovision/delete map to a revoke. */
  action: 'deprovision' | 'delete' | 'suspend' | 'other'
}

export interface OffboardVerifyInput {
  provider: IdentityProvider
  /** Raw request body bytes exactly as received (for HMAC). */
  rawBody: string
  /** Per-provider shared secret the customer configured. */
  secret: string
  /** Provider signature header value (hex HMAC-SHA256 over rawBody). */
  signature: string
  /** Replay nonce supplied by the provider or derived from the event id. */
  nonce: string
  /** Provider event timestamp in epoch ms. */
  timestampMs: number
  tenantId: string
  nowMs?: number
}

export interface OffboardVerifyResult {
  ok: boolean
  reason?: string
}

/**
 * Verify an inbound offboard event at the edge: constant-time HMAC over the raw
 * body, then the replay window (nonce + timestamp). Both must pass before the
 * bridge maps anything to a revoke. This is the inbound counterpart of the
 * outbound webhook signing.
 */
export function verifyInboundOffboard(input: OffboardVerifyInput): OffboardVerifyResult {
  const expected = createHmac('sha256', input.secret).update(input.rawBody).digest('hex')
  const provided = input.signature.replace(/^sha256=/, '')
  if (!constantTimeEqualHex(expected, provided)) {
    return { ok: false, reason: 'inbound HMAC signature mismatch' }
  }
  const replay = checkAndRecordNonce({
    scope: `inbound:${input.provider}:${input.tenantId}`,
    nonce: input.nonce,
    timestampMs: input.timestampMs,
    tenantId: input.tenantId,
    nowMs: input.nowMs,
  })
  if (!replay.ok) return { ok: false, reason: replay.reason }
  return { ok: true }
}

/**
 * Resolve which gateway target an offboarded external identity maps to. Reads
 * the agents table for an agent whose stored metadata records the external
 * identity. Returns null when no mapping exists (offboard of an identity that
 * never owned an agent is a no-op).
 *
 * GATE (Tima / Okta-Entra bridge): the exact metadata key the customer's IdP
 * binding writes (e.g. metadata.okta_user_id, metadata.entra_object_id) and the
 * SCIM attribute mapping is Tima's to finalize. The query below uses a
 * conventional metadata key and is structured so only the key strings change.
 */
export function resolveTargetFromOffboard(
  tenantId: string,
  offboard: NormalizedOffboard,
): { targetType: 'agent'; targetId: string } | null {
  const db = getDB()
  const metaKey = offboard.provider === 'okta' ? 'okta_user_id' : 'entra_object_id'
  // agents.metadata is JSON text; match the external id inside it. Scoped to
  // the tenant so one tenant's offboard cannot revoke another's agent.
  const row = db
    .prepare(
      `SELECT agent_id FROM agents
         WHERE tenant_id = ?
           AND status = 'active'
           AND metadata LIKE ?
         LIMIT 1`,
    )
    .get(tenantId, `%"${metaKey}":"${offboard.externalUserId}"%`) as any
  if (!row) return null
  return { targetType: 'agent', targetId: row.agent_id }
}

export interface OffboardOutcome {
  mapped: boolean
  targetType?: 'agent'
  targetId?: string
  event: ConnectorEvent
}

/**
 * Map a verified offboard to a gateway revoke. Calls the injected revoke
 * function, which production wires to the SAME cascade the enforce.ts POST
 * /api/v1/revoke route runs (the bridge does not duplicate that logic; the
 * router passes a thunk that performs the in-process cascade). Emits an
 * identity_offboard connector event either way so the offboard is observable
 * even when it maps to no agent.
 */
export async function applyOffboard(opts: {
  tenantId: string
  offboard: NormalizedOffboard
  /** Performs the cascade revoke. Wired by the router to the existing route. */
  revoke: (target: { targetType: 'agent'; targetId: string; revokedBy: string }) => Promise<{ cascadeCount: number }>
}): Promise<OffboardOutcome> {
  const target = deprovisions(opts.offboard.action)
    ? resolveTargetFromOffboard(opts.tenantId, opts.offboard)
    : null

  let cascadeCount = 0
  if (target) {
    const r = await opts.revoke({ ...target, revokedBy: `idp:${opts.offboard.provider}` })
    cascadeCount = r.cascadeCount
  }

  // TODO(W2-SET): emit a Security Event Token (RFC 8417 SET) for this offboard
  //   via the SDK SET-emission module once it ships. The installed alpha.3 has
  //   no SET export; today the gateway emits the connector event below instead.
  //   The real call will be roughly: sdk.emitSecurityEventToken({
  //     events: { 'https://schemas.openid.net/secevent/risc/event-type/account-disabled': {...} },
  //     sub_id: { format: 'opaque', id: opts.offboard.externalUserId } }).

  const event = buildConnectorEvent({
    eventType: 'identity_offboard',
    eventId: `offboard-${opts.offboard.provider}-${opts.offboard.externalUserId}-${Date.now()}`,
    tenantId: opts.tenantId,
    data: {
      provider: opts.offboard.provider,
      external_user_id: opts.offboard.externalUserId,
      user_name: opts.offboard.userName ?? null,
      action: opts.offboard.action,
      mapped: Boolean(target),
      target_type: target?.targetType ?? null,
      target_id: target?.targetId ?? null,
      cascade_count: cascadeCount,
    },
  })

  try {
    getEventBus().emit(opts.tenantId, { type: 'identity_offboard' as any, data: event.data })
  } catch {
    /* bus failure must not break the offboard path */
  }

  return {
    mapped: Boolean(target),
    ...(target ? { targetType: target.targetType, targetId: target.targetId } : {}),
    event,
  }
}

function deprovisions(action: NormalizedOffboard['action']): boolean {
  return action === 'deprovision' || action === 'delete'
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  try {
    return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
  } catch {
    return false
  }
}

// ── SDK delegation-revoke seam ────────────────────────────────────
// The bridge's primary path calls the gateway's own cascade revoke (the DB
// cascade in enforce.ts), which is the customer-controllable, sink-enforceable
// surface. For callers that also want to mark the SDK-side delegation record
// revoked, the installed alpha.3 SDK exposes revokeByAgent. Loaded via the same
// dynamic-import pattern enforce.ts uses so a missing export degrades safely.
let _revokeByAgent: ((...args: any[]) => any) | null = null
export async function getSdkRevokeByAgent(): Promise<((...args: any[]) => any) | null> {
  if (_revokeByAgent) return _revokeByAgent
  try {
    const sdk: any = await import('agent-passport-system')
    if (typeof sdk.revokeByAgent === 'function') _revokeByAgent = sdk.revokeByAgent
  } catch {
    /* SDK revocation surface may be absent in some builds; gateway cascade still runs */
  }
  return _revokeByAgent
}
