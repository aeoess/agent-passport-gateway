// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Revocation sinks: where revocation, epoch, freeze and thaw events go.
 *
 * Two sinks, deliberately separate:
 *
 *  1. The in-process EventBus (src/gateway/events.ts). Works today, drives the
 *     SSE stream that the dashboard and any same-process subscriber read.
 *
 *  2. A Security Event Token (SET) push to external sinks and SIEM. This is the
 *     edge-enforcement path: a signed event the sink itself verifies and acts
 *     on, rather than trusting the control plane to have already enforced. The
 *     SET builder and subscriber-stream push live in SDK Wave 2 (W2-B3); until
 *     that lands this is a local-log stub so the call sites are wired now.
 *
 * Thin-gateway note: the gateway emits events; it does not assume delivery.
 * Propagation freshness is recorded (emittedAt), never asserted as instant.
 */

import { getEventBus, type GatewayEvent } from '../events.js'

/** Event categories this module pushes. Subset of the GatewayEvent union. */
export type RevocationEventType =
  | 'revocation'
  | 'epoch_bump'
  | 'panic_freeze'
  | 'multisig_thaw'
  | 'alert'

export interface SecurityEventToken {
  /** Event family, e.g. 'epoch_bump'. */
  type: RevocationEventType
  /** Tenant the event belongs to. */
  tenantId: string
  /** Subject the sink should key off (agentId / delegationId). */
  subject?: string
  /** Free-form event payload, already free of secrets. */
  data: Record<string, unknown>
  /** When the gateway emitted it. Freshness is recorded, not asserted as zero. */
  emittedAt: string
}

/**
 * STUB: SDK Wave 2 W2-B3 SET emission.
 *
 * Today: structured local log only, so the integration point exists and is
 * exercised by tests. When W2-B3 lands, this delegates to the SDK signed-SET
 * builder plus the SSF subscriber-stream push.
 *
 * TODO(W2-B3): replace stub body with SDK SET builder + SSF subscriber push.
 */
export function pushSecurityEventToken(token: SecurityEventToken): void {
  // No throw, no external call: a stubbed sink must never break a revoke path.
  // Kept intentionally quiet in tests; a real emitter swaps in at W2-B3.
  if (process.env.APS_SET_DEBUG === '1') {
    // eslint-disable-next-line no-console
    console.log(`[SET-stub] ${token.type} tenant=${token.tenantId} subject=${token.subject ?? '-'} at=${token.emittedAt}`)
  }
}

/**
 * Emit a revocation-family event to BOTH sinks: the in-process EventBus (works
 * now, drives SSE) and the SET push (stubbed for W2-B3). Returns the emit
 * timestamp so callers can record propagation freshness.
 */
export function emitRevocationEvent(
  tenantId: string,
  type: RevocationEventType,
  data: Record<string, unknown>,
  subject?: string,
): string {
  const emittedAt = new Date().toISOString()

  // Sink 1: in-process bus (drives SSE). Never let a subscriber error break the
  // revoke path; the bus already swallows subscriber throws, this is belt+braces.
  try {
    getEventBus().emit(tenantId, { type: type as GatewayEvent['type'], data })
  } catch { /* emit must not crash the revoke path */ }

  // Sink 2: SET push to external sinks / SIEM (stubbed for W2-B3).
  try {
    pushSecurityEventToken({ type, tenantId, subject, data, emittedAt })
  } catch { /* stubbed sink must not crash the revoke path */ }

  return emittedAt
}
