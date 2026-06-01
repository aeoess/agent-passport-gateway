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

// G-A1 egress is now merged. We import its real sink/envelope types so the
// adaptation below is anchored to the source of truth rather than a local
// mirror. EgressSink is (EgressEnvelope) => Promise<void>; ConnectorSink
// deliberately takes a ConnectorEvent (the versioned schema) instead, so the
// two are NOT the same type. batch-egress.ts is the seam that adapts an
// EgressEnvelope into a ConnectorEvent when G-A1 batch egress drives delivery.
import type { EgressSink, EgressEnvelope } from '../../gateway/egress/index.js'

/** G-A1's raw downstream sink: (EgressEnvelope) => Promise<void>. Re-exported
 *  under a local name so the adaptation below can point at the source of truth.
 *  ConnectorSink deliberately diverges from this - do not collapse the two. */
export type RawEgressSink = EgressSink
/** The raw envelope G-A1 hands its EgressSink; a ConnectorEvent wraps the
 *  versioned schema around this same structural batch reference. */
export type EgressBatchEnvelope = EgressEnvelope

/** A downstream sink. Resolves on accepted delivery, rejects to trigger the
 *  dispatcher's retry. The arg is a ConnectorEvent (the versioned schema)
 *  rather than a raw {@link EgressBatchEnvelope} so adapters receive the
 *  versioned shape; batch-egress.ts adapts an EgressEnvelope into a
 *  ConnectorEvent when G-A1 batch egress drives the delivery. Distinct from
 *  G-A1's {@link RawEgressSink} by design - do not collapse the two. */
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
