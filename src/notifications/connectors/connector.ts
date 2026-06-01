// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - The ONE Adapter Interface
// ══════════════════════════════════════════════════════════════════
// The spec mandates "real adapters behind ONE interface". That interface is
// G-A1's EgressSink: (envelope) => Promise<void>. Aligning every adapter to it
// means each connector composes with G-A1's EgressDispatcher for retry +
// dead-letter for free, so this module never writes a second retry/DLQ engine.
//
// A connector here adapts a versioned ConnectorEvent into whatever the
// downstream system expects (an OCSF record, a Slack message, a Jira issue).
// The gateway EMITS through these sinks; the customer runs their own reaction
// logic on the receiving side. Verification lives at the edge: the webhook
// sink signs, the receiver verifies; the gateway is not a trusted central brain.
// ══════════════════════════════════════════════════════════════════

import type { ConnectorEvent } from './event-schema.js'

// TODO(G-A1 / gw-a1-event-merkle): import { EgressDispatcher, type EgressSink,
//   type EgressEnvelope, DEFAULT_RETRY_POLICY, backoffDelay,
//   type RetryPolicy, type DeadLetter, type DispatchResult }
//   from '../../gateway/egress/index.js' once egress/ is merged into base.
//   Until then EgressSink is mirrored locally, field-compatible, so adapters
//   typecheck against the same shape they will get from G-A1.

/** A downstream sink, mirrored from G-A1's egress/dispatcher.ts. Resolves on
 *  accepted delivery, rejects to trigger the dispatcher's retry. The arg is a
 *  ConnectorEvent rather than a raw EgressEnvelope so adapters receive the
 *  versioned schema; the dispatcher seam below adapts an EgressEnvelope into a
 *  ConnectorEvent when G-A1 batch egress drives the delivery. */
export type ConnectorSink = (event: ConnectorEvent) => Promise<void>

/** A registered, named adapter. `kind` selects the integration; `deliver` is
 *  the EgressSink-shaped function. `verifiesAtEdge` documents whether the
 *  receiving side is expected to verify the signed envelope (true for webhook,
 *  internal-http, otel; the chat/ticket adapters post into an authenticated
 *  channel the customer already trusts). */
export interface Connector {
  kind: ConnectorKind
  deliver: ConnectorSink
  verifiesAtEdge: boolean
}

export type ConnectorKind =
  | 'webhook'
  | 'otel-ocsf'
  | 'slack'
  | 'teams'
  | 'jira'
  | 'servicenow'
  | 'internal-http'
  | 'email'

/** A delivery error that should be retried by the dispatcher. Throwing this
 *  (or any Error) from a ConnectorSink triggers G-A1's bounded retry. */
export class ConnectorDeliveryError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
    this.name = 'ConnectorDeliveryError'
  }
}

/**
 * Deterministic canonical JSON. Mirrors the local canonicalJsonStringify in
 * enforce.ts (sorted keys, stable separators) so HMAC/JWS signing inputs are
 * reproducible by a verifier. Reused here rather than adding a new
 * canonicalizer or touching the frozen src/core/canonical-jcs.ts primitive.
 */
export function canonicalJson(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (seen.has(value as object)) throw new ConnectorDeliveryError('cycle in payload')
  seen.add(value as object)
  if (Array.isArray(value)) {
    const out = '[' + value.map((i) => canonicalJson(i, seen)).join(',') + ']'
    seen.delete(value as object)
    return out
  }
  const keys = Object.keys(value as Record<string, unknown>).sort()
  const out =
    '{' +
    keys
      .map(
        (k) =>
          JSON.stringify(k) + ':' + canonicalJson((value as Record<string, unknown>)[k], seen),
      )
      .join(',') +
    '}'
  seen.delete(value as object)
  return out
}
