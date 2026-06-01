// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - ServiceNow adapter (tickets)
// ══════════════════════════════════════════════════════════════════
// Opens a ServiceNow incident (POST /api/now/table/incident) for a
// ticket-worthy gateway event. Same posture as the Jira adapter: the gateway
// emits the create-record request, the customer's ServiceNow instance and its
// own workflows own everything after, and auth is the customer's own credential
// passed as an injected header. HTTP POST injected for testability.
// ══════════════════════════════════════════════════════════════════

import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'
import type { TicketPostRequest } from './jira.js'

/** Map a connector event to a ServiceNow incident payload. urgency/impact map
 *  from the event's severity; ServiceNow uses 1 (high) .. 3 (low). */
export function toServiceNowIncident(event: ConnectorEvent): Record<string, unknown> {
  const sev = (event.data?.severity as string | undefined)?.toLowerCase()
  const urgency = sev === 'critical' || sev === 'high' ? 1 : sev === 'medium' ? 2 : 3
  const lines = [
    `Event type: ${event.event_type}`,
    `Tenant: ${event.tenant_id}`,
    `Emitted at: ${event.emitted_at}`,
    `Event ID: ${event.event_id}`,
  ]
  if (event.batch) {
    lines.push(`Merkle root: ${event.batch.merkleRoot}`)
    lines.push(`Receipt count: ${event.batch.receiptCount}`)
  }
  return {
    short_description: `[AEOESS] ${event.event_type} (${event.event_id.slice(0, 8)})`,
    description: lines.join('\n'),
    urgency,
    impact: urgency,
    category: 'security',
    u_source: 'aeoess-gateway',
  }
}

/** Build a ServiceNow ConnectorSink. */
export function makeServiceNowSink(opts: {
  url: string
  httpPost: (req: TicketPostRequest) => Promise<{ status: number }>
  headers?: Record<string, string>
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const body = JSON.stringify(toServiceNowIncident(event))
    const res = await opts.httpPost({
      url: opts.url,
      body,
      headers: { 'content-type': 'application/json', accept: 'application/json', ...(opts.headers ?? {}) },
    })
    if (res.status < 200 || res.status >= 300) {
      throw new ConnectorDeliveryError(`ServiceNow incident create returned ${res.status}`, res.status)
    }
  }
}
