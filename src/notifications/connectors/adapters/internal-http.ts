// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Internal-HTTP sink
// ══════════════════════════════════════════════════════════════════
// A plain signed POST of the versioned envelope to a customer-run HTTP
// endpoint. Same signing as the webhook sink (HMAC + gateway JWS + nonce +
// timestamp) so the receiver verifies at the edge. Distinct from the
// registered-webhook fan-out: this is a single ad-hoc internal target a caller
// wires directly, e.g. an internal automation bus the customer operates. The
// target is still SSRF-validated by the caller before use.
// ══════════════════════════════════════════════════════════════════

import { buildSignedWebhook, type SignedWebhookRequest } from '../webhook-sink.js'
import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'

/** Build an internal-HTTP ConnectorSink. Reuses the signed-webhook envelope so
 *  the internal receiver verifies with the same HMAC + JWS logic. */
export function makeInternalHttpSink(opts: {
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
      throw new ConnectorDeliveryError(`internal-http POST returned ${res.status}`, res.status)
    }
  }
}
