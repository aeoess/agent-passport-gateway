// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Slack adapter (approvals / alerts)
// ══════════════════════════════════════════════════════════════════
// Posts an approval request or alert into a Slack channel the customer already
// controls (an Incoming Webhook URL or a chat.postMessage call). The gateway
// EMITS the message; the customer's Slack workspace runs the human reaction.
// The target URL is SSRF-validated by the endpoint registry before it reaches
// here. The HTTP POST is injected for testability.
// ══════════════════════════════════════════════════════════════════

import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'

export interface ChatPostRequest {
  url: string
  body: string
  headers: Record<string, string>
}

/** Map a connector event to a Slack Block Kit message. */
export function toSlackMessage(event: ConnectorEvent): Record<string, unknown> {
  const title = slackTitle(event)
  const fields: Array<Record<string, unknown>> = [
    { type: 'mrkdwn', text: `*Event:* ${event.event_type}` },
    { type: 'mrkdwn', text: `*Tenant:* ${event.tenant_id}` },
    { type: 'mrkdwn', text: `*Time:* ${event.emitted_at}` },
    { type: 'mrkdwn', text: `*Event ID:* ${event.event_id}` },
  ]
  if (event.batch) {
    fields.push({ type: 'mrkdwn', text: `*Merkle root:* \`${event.batch.merkleRoot.slice(0, 24)}...\`` })
    fields.push({ type: 'mrkdwn', text: `*Receipts:* ${event.batch.receiptCount}` })
  }
  return {
    text: title,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: title } },
      { type: 'section', fields: fields.slice(0, 10) },
    ],
  }
}

function slackTitle(event: ConnectorEvent): string {
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

/** Build a Slack ConnectorSink. */
export function makeSlackSink(opts: {
  url: string
  httpPost: (req: ChatPostRequest) => Promise<{ status: number }>
  headers?: Record<string, string>
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const body = JSON.stringify(toSlackMessage(event))
    const res = await opts.httpPost({
      url: opts.url,
      body,
      headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
    })
    if (res.status < 200 || res.status >= 300) {
      throw new ConnectorDeliveryError(`Slack post returned ${res.status}`, res.status)
    }
  }
}
