// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Signed Webhook Sink
// ══════════════════════════════════════════════════════════════════
// The signed-delivery primitive. An outbound webhook carries:
//   - a per-endpoint HMAC-SHA256 over a canonical signing string
//     (timestamp + nonce + body), so the receiver can verify integrity and
//     origin with the shared secret it registered;
//   - a detached JWS (EdDSA) from the gateway identity, so a receiver that
//     does not hold the shared secret can still verify via the gateway JWKS at
//     /.well-known/jwks.json;
//   - a nonce and timestamp for replay protection at the edge.
//
// Thin gateway: signing happens here, VERIFICATION happens at the receiving
// edge. The gateway does not hold a verification brain; it attaches material
// the customer's own reaction logic checks. The helper verifyWebhookSignature
// is provided so tests and a reference receiver can confirm a delivery verifies.
// ══════════════════════════════════════════════════════════════════

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { getGatewayIdentity } from '../../gateway/identity.js'
import { canonicalJson, ConnectorDeliveryError } from './connector.js'
import type { ConnectorSink } from './connector.js'
import type { ConnectorEvent } from './event-schema.js'

/** Header names the receiver inspects. Namespaced under x-aeoess-connector-* so
 *  they never collide with Stripe's x-... webhook headers. */
export const HDR_SIGNATURE = 'x-aeoess-connector-signature'
export const HDR_JWS = 'x-aeoess-connector-jws'
export const HDR_TIMESTAMP = 'x-aeoess-connector-timestamp'
export const HDR_NONCE = 'x-aeoess-connector-nonce'
export const HDR_KEY_ID = 'x-aeoess-connector-kid'
export const HDR_SCHEMA = 'x-aeoess-connector-schema'

export interface SignedWebhookRequest {
  url: string
  body: string
  headers: Record<string, string>
}

/** Build the canonical string the HMAC is computed over. A verifier must
 *  reconstruct exactly this: timestamp, nonce, and the raw body, joined by
 *  newlines. Including timestamp + nonce binds the signature to a single
 *  delivery so a captured signature cannot be replayed with a fresh body. */
export function webhookSigningString(timestampMs: number, nonce: string, body: string): string {
  return `${timestampMs}\n${nonce}\n${body}`
}

/** Compute the HMAC-SHA256 hex signature for a delivery. */
export function signWebhookHmac(secret: string, timestampMs: number, nonce: string, body: string): string {
  return createHmac('sha256', secret)
    .update(webhookSigningString(timestampMs, nonce, body))
    .digest('hex')
}

/**
 * Build a fully signed webhook request for a connector event. The body is the
 * canonical JSON of the versioned envelope, so a verifier recomputes the same
 * bytes. Attaches both the HMAC (shared secret) and the gateway JWS (JWKS).
 */
export function buildSignedWebhook(opts: {
  url: string
  secret: string
  event: ConnectorEvent
  nowMs?: number
  nonce?: string
}): SignedWebhookRequest {
  const timestampMs = opts.nowMs ?? Date.now()
  const nonce = opts.nonce ?? randomBytes(16).toString('hex')
  const body = canonicalJson(opts.event)
  const hmac = signWebhookHmac(opts.secret, timestampMs, nonce, body)

  // Detached gateway JWS over the same structural facts. The receiver verifies
  // it against /.well-known/jwks.json without holding the shared secret.
  const identity = getGatewayIdentity()
  const jws = identity.sign({
    event_id: opts.event.event_id,
    event_type: opts.event.event_type,
    tenant_id: opts.event.tenant_id,
    timestamp_ms: timestampMs,
    nonce,
    body_sha_hmac: hmac,
  })

  return {
    url: opts.url,
    body,
    headers: {
      'content-type': 'application/json',
      [HDR_SIGNATURE]: `sha256=${hmac}`,
      [HDR_JWS]: jws,
      [HDR_KEY_ID]: identity.kid,
      [HDR_TIMESTAMP]: String(timestampMs),
      [HDR_NONCE]: nonce,
      [HDR_SCHEMA]: opts.event.schema_version,
    },
  }
}

export interface VerifyResult {
  ok: boolean
  reason?: string
}

/**
 * Reference verifier a receiving edge (or a test) runs to confirm a signed
 * delivery. Checks the HMAC in constant time and the timestamp freshness.
 * Nonce-replay is the receiver's responsibility (it tracks seen nonces in its
 * own window); this helper just confirms the signature material is internally
 * consistent and fresh.
 */
export function verifyWebhookSignature(opts: {
  secret: string
  body: string
  headers: Record<string, string>
  nowMs?: number
  toleranceMs?: number
}): VerifyResult {
  const now = opts.nowMs ?? Date.now()
  const tolerance = opts.toleranceMs ?? 5 * 60 * 1000
  const sigHeader = lower(opts.headers, HDR_SIGNATURE)
  const tsHeader = lower(opts.headers, HDR_TIMESTAMP)
  const nonce = lower(opts.headers, HDR_NONCE)
  if (!sigHeader || !tsHeader || !nonce) {
    return { ok: false, reason: 'missing signature, timestamp, or nonce header' }
  }
  const timestampMs = Number(tsHeader)
  if (!Number.isFinite(timestampMs)) return { ok: false, reason: 'timestamp header is not numeric' }
  if (Math.abs(now - timestampMs) > tolerance) {
    return { ok: false, reason: 'timestamp outside tolerance (stale or future-dated)' }
  }
  const expected = signWebhookHmac(opts.secret, timestampMs, nonce, opts.body)
  const got = sigHeader.replace(/^sha256=/, '')
  if (!constantTimeEqualHex(expected, got)) {
    return { ok: false, reason: 'HMAC signature mismatch' }
  }
  return { ok: true }
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  try {
    return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
  } catch {
    return false
  }
}

function lower(headers: Record<string, string>, name: string): string | undefined {
  // Header lookup is case-insensitive; callers may pass either casing.
  if (headers[name] !== undefined) return headers[name]
  const lc = name.toLowerCase()
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lc) return headers[k]
  }
  return undefined
}

/**
 * Build a webhook ConnectorSink bound to one endpoint. The httpPost function is
 * injected so production wires the real fetch and tests inject a capturing or
 * failing stub (the dispatcher's retry then exercises the same path). The sink
 * throws ConnectorDeliveryError on a non-2xx so the dispatcher retries.
 */
export function makeWebhookSink(opts: {
  url: string
  secret: string
  httpPost: (req: SignedWebhookRequest) => Promise<{ status: number }>
  nowFn?: () => number
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const req = buildSignedWebhook({
      url: opts.url,
      secret: opts.secret,
      event,
      nowMs: opts.nowFn ? opts.nowFn() : undefined,
    })
    const res = await opts.httpPost(req)
    if (res.status < 200 || res.status >= 300) {
      throw new ConnectorDeliveryError(`webhook POST returned ${res.status}`, res.status)
    }
  }
}
