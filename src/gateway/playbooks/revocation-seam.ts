// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Revocation-family event seam.
 *
 * G-B2 owns the dual-sink emitter (gw-b2-revocation/src/gateway/revocation/
 * sinks.ts): in-process EventBus + Security Event Token (SET) push. B2 is NOT
 * merged into this base, so we depend on its PUBLIC surface only and stub the
 * import. Crucially we REUSE B2's single SET seam (pushSecurityEventToken /
 * TODO(W2-B3)); we do NOT create a second SET stub.
 *
 * B2 public surface consumed (from .../revocation/sinks.ts):
 *   - emitRevocationEvent(tenantId, type, data, subject?): string
 *   - pushSecurityEventToken(token): void
 *   - type RevocationEventType = 'revocation' | 'epoch_bump' | 'panic_freeze'
 *       | 'multisig_thaw' | 'alert'
 *
 * TODO(G-B2 / gw-b2-revocation): replace this file's body with a direct import:
 *   import { emitRevocationEvent } from '../revocation/index.js'
 * The signature below is identical so the swap is mechanical. The single SET
 * stub remains B2's; this seam never adds its own.
 *
 * TODO(W2-B3): SDK SET builder + SSF subscriber push lives in B2's
 *   pushSecurityEventToken (one stub, shared). This seam forwards to it; it does
 *   not introduce a second W2-B3 stub.
 */

import { getEventBus, type GatewayEvent } from '../events.js'

/** Subset of GatewayEvent the revocation family pushes. Matches B2's union. */
export type RevocationEventTypeSeam =
  | 'revocation'
  | 'epoch_bump'
  | 'panic_freeze'
  | 'multisig_thaw'
  | 'alert'

/**
 * Mirror of B2 emitRevocationEvent. Emits to the in-process bus (drives SSE)
 * and would push a SET via B2's single stub. Error-swallowing on both sinks: a
 * stubbed/cosmetic sink must never break a revoke/kill path. Returns the emit
 * timestamp so callers can record propagation freshness (never asserted instant).
 *
 * Until B2 merges, the SET push is B2's responsibility; here we only drive the
 * bus and record freshness. We intentionally do NOT re-implement a SET stub.
 */
export function emitRevocationEventSeam(
  tenantId: string,
  type: RevocationEventTypeSeam,
  data: Record<string, unknown>,
  _subject?: string,
): string {
  const emittedAt = new Date().toISOString()
  try {
    // The bus type union does not enumerate every revocation-family literal in
    // this base; B2's sinks.ts performs the same cast. The literal is carried
    // verbatim for SSE subscribers and the SET push at W2-B3.
    getEventBus().emit(tenantId, { type: type as GatewayEvent['type'], data })
  } catch { /* emit must not crash the kill/revoke path */ }
  // SET push is B2's single stub (pushSecurityEventToken / TODO(W2-B3)). Not
  // duplicated here. When B2 merges, the real emitRevocationEvent does both.
  return emittedAt
}
