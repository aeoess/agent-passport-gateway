// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Microsoft Teams adapter (approvals / alerts)
// ══════════════════════════════════════════════════════════════════
// Posts an approval request or alert into a Teams channel via an Incoming
// Webhook using the Adaptive Card / MessageCard shape. Same posture as the
// Slack adapter: the gateway emits, the customer's Teams workspace runs the
// human reaction. The target URL is SSRF-validated upstream. HTTP POST injected.
// ══════════════════════════════════════════════════════════════════

import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'
import type { ChatPostRequest } from './slack.js'

/** Map a connector event to a Teams MessageCard. */
export function toTeamsMessage(event: ConnectorEvent): Record<string, unknown> {
  const facts: Array<{ name: string; value: string }> = [
    { name: 'Event', value: event.event_type },
    { name: 'Tenant', value: event.tenant_id },
    { name: 'Time', value: event.emitted_at },
    { name: 'Event ID', value: event.event_id },
  ]
  if (event.batch) {
    facts.push({ name: 'Merkle root', value: `${event.batch.merkleRoot.slice(0, 24)}...` })
    facts.push({ name: 'Receipts', value: String(event.batch.receiptCount) })
  }
  return {
    '@type': 'MessageCard',
    '@context': 'https://schema.org/extensions',
    summary: `Gateway event: ${event.event_type}`,
    themeColor: themeColor(event),
    sections: [
      {
        activityTitle: titleFor(event),
        facts,
        markdown: true,
      },
    ],
  }
}

function titleFor(event: ConnectorEvent): string {
  switch (event.event_type) {
    case 'approval_requested':
      return 'Approval requested'
    case 'revocation':
      return 'Revocation emitted'
    case 'alert':
      return 'Gateway alert'
    case 'identity_offboard':
      return 'Identity offboard processed'
    default:
      return `Gateway event: ${event.event_type}`
  }
}

function themeColor(event: ConnectorEvent): string {
  const sev = (event.data?.severity as string | undefined)?.toLowerCase()
  if (event.event_type === 'revocation' || sev === 'critical') return 'D7263D'
  if (sev === 'high') return 'F46036'
  return '2E86AB'
}

/** Build a Teams ConnectorSink. */
export function makeTeamsSink(opts: {
  url: string
  httpPost: (req: ChatPostRequest) => Promise<{ status: number }>
  headers?: Record<string, string>
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const body = JSON.stringify(toTeamsMessage(event))
    const res = await opts.httpPost({
      url: opts.url,
      body,
      headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
    })
    if (res.status < 200 || res.status >= 300) {
      throw new ConnectorDeliveryError(`Teams post returned ${res.status}`, res.status)
    }
  }
}
