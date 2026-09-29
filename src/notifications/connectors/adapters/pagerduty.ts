// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - PagerDuty Events API v2 adapter
// ══════════════════════════════════════════════════════════════════

import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'

export const PAGERDUTY_EVENTS_ENDPOINT = 'https://events.pagerduty.com/v2/enqueue'

export interface PagerDutyEvent {
  routing_key: string
  event_action: 'trigger'
  dedup_key: string
  payload: {
    summary: string
    source: string
    severity: 'critical' | 'error' | 'warning' | 'info'
    custom_details: Record<string, unknown>
  }
}

export interface PagerDutyPostRequest {
  url: string
  body: string
  headers: Record<string, string>
}

/** Map a connector event to a PagerDuty Events API v2 trigger event. */
export function toPagerDutyEvent(event: ConnectorEvent, routingKey: string): PagerDutyEvent {
  return {
    routing_key: routingKey,
    event_action: 'trigger',
    dedup_key: event.event_id,
    payload: {
      summary: `Gateway event: ${event.event_type}`,
      source: 'aeoess-gateway',
      severity: pagerDutySeverity(event.data.severity),
      custom_details: {
        event_type: event.event_type,
        event_id: event.event_id,
        tenant_id: event.tenant_id,
        emitted_at: event.emitted_at,
        ...(event.batch ? { batch: event.batch } : {}),
      },
    },
  }
}

function pagerDutySeverity(value: unknown): PagerDutyEvent['payload']['severity'] {
  switch (typeof value === 'string' ? value.toLowerCase() : '') {
    case 'critical':
      return 'critical'
    case 'high':
      return 'error'
    case 'medium':
    case 'warning':
      return 'warning'
    default:
      return 'info'
  }
}

/** Build a PagerDuty Events API v2 ConnectorSink. */
export function makePagerDutySink(opts: {
  routingKey: string
  httpPost: (req: PagerDutyPostRequest) => Promise<{ status: number }>
  endpoint?: string
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const res = await opts.httpPost({
      url: opts.endpoint ?? PAGERDUTY_EVENTS_ENDPOINT,
      body: JSON.stringify(toPagerDutyEvent(event, opts.routingKey)),
      headers: { 'content-type': 'application/json' },
    })
    if (res.status !== 202) {
      throw new ConnectorDeliveryError(`PagerDuty event enqueue returned ${res.status}`, res.status)
    }
  }
}
