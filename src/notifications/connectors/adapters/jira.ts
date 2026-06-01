// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Jira adapter (tickets)
// ══════════════════════════════════════════════════════════════════
// Opens a Jira issue (POST /rest/api/3/issue) for a ticket-worthy gateway
// event. The gateway emits the create-issue request; the customer's Jira
// project and its own automation own everything after. Auth is the customer's
// own Jira credential, attached as an injected header by the caller; the
// gateway does not hold a privileged central Jira identity. HTTP POST injected.
// ══════════════════════════════════════════════════════════════════

import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'

export interface TicketPostRequest {
  url: string
  body: string
  headers: Record<string, string>
}

/** Map a connector event to a Jira issue-create payload. */
export function toJiraIssue(event: ConnectorEvent, projectKey: string, issueType = 'Task'): Record<string, unknown> {
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
    fields: {
      project: { key: projectKey },
      summary: `[AEOESS] ${event.event_type} (${event.event_id.slice(0, 8)})`,
      issuetype: { name: issueType },
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [{ type: 'text', text: lines.join('\n') }],
          },
        ],
      },
    },
  }
}

/** Build a Jira ConnectorSink. The customer's Jira base URL and auth header are
 *  supplied by the caller; the gateway holds no privileged Jira credential. */
export function makeJiraSink(opts: {
  url: string
  projectKey: string
  issueType?: string
  httpPost: (req: TicketPostRequest) => Promise<{ status: number }>
  headers?: Record<string, string>
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const body = JSON.stringify(toJiraIssue(event, opts.projectKey, opts.issueType))
    const res = await opts.httpPost({
      url: opts.url,
      body,
      headers: { 'content-type': 'application/json', accept: 'application/json', ...(opts.headers ?? {}) },
    })
    if (res.status < 200 || res.status >= 300) {
      throw new ConnectorDeliveryError(`Jira issue create returned ${res.status}`, res.status)
    }
  }
}
