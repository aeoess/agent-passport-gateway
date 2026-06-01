// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Versioned Connector Event Schema
// ══════════════════════════════════════════════════════════════════
// The "clear versioned event schema" the spec mandates. Every outbound
// envelope a connector delivers carries an explicit schema_version so a
// customer who runs their own reaction logic can branch on it and we can
// evolve the shape without silently breaking their parsers. The envelope
// is intentionally aggregate and structural: it carries the G-A1 batch
// root plus a small summary, never the granular leaves. Customers fetch
// leaves out of band on anomaly through the G-A1 surface.
//
// Thin gateway: this module only describes and validates a shape. It holds
// no enforcement state. Verification of a delivered envelope happens at the
// edge (the sink, the customer SIEM), not in a central gateway brain.
// ══════════════════════════════════════════════════════════════════

// G-A1 egress is now merged. The connector batch reference and summary are the
// real egress types, re-exported under the connector names the barrel already
// publishes so existing callers keep their import sites unchanged.
import type { EgressEnvelope, SummaryMatrix } from '../../gateway/egress/index.js'

/** The current connector event schema version. Bumped on any breaking
 *  change to the envelope shape. Customers branch on this. */
export const CONNECTOR_SCHEMA_VERSION = 'connector_event_v1' as const

/** Lifecycle event types a connector subscription can filter on. These are
 *  the customer-facing event names carried in the envelope, distinct from the
 *  in-process gateway EventBus literals. */
export type ConnectorEventType =
  | 'batch_committed'      // a G-A1 Merkle batch was committed and is being emitted
  | 'revocation'           // a delegation / agent / data source was revoked
  | 'alert'                // a gateway alert (e.g. revocation, anomaly)
  | 'approval_requested'   // a human-approval gate opened (Slack / Teams)
  | 'ticket_requested'     // a ticket should be opened (Jira / ServiceNow)
  | 'identity_offboard'    // an inbound identity-provider offboard mapped to a revoke
  | 'connector_test'       // a delivery test ping for a freshly registered endpoint

/** G-A1's structural summary. Counts only, no payload. Re-exported under the
 *  connector name the barrel publishes; it IS the real egress type now. */
export type ConnectorSummaryMatrix = SummaryMatrix

/** G-A1's downstream batch envelope: the batch root and a structural summary
 *  travel, the leaves never do. The connector name is an alias for the real
 *  EgressEnvelope so batch_committed events carry exactly what G-A1 emits. */
export type ConnectorBatchRef = EgressEnvelope

/** The versioned envelope every connector delivers. */
export interface ConnectorEvent {
  /** Always present; lets customers branch and lets us evolve the shape. */
  schema_version: typeof CONNECTOR_SCHEMA_VERSION
  /** Stable per-event id; also the idempotency key for the receiving side. */
  event_id: string
  /** One of the filterable connector event types. */
  event_type: ConnectorEventType
  /** Owning tenant. */
  tenant_id: string
  /** ISO 8601 emission time. */
  emitted_at: string
  /** Optional batch reference for batch-derived events. */
  batch?: ConnectorBatchRef
  /** Opaque, event-type-specific structural detail. No granular leaves. */
  data: Record<string, unknown>
}

/** Construct a versioned connector event. Centralizing construction keeps the
 *  schema_version and required fields consistent across every adapter. */
export function buildConnectorEvent(opts: {
  eventId: string
  eventType: ConnectorEventType
  tenantId: string
  emittedAt?: string
  batch?: ConnectorBatchRef
  data?: Record<string, unknown>
}): ConnectorEvent {
  return {
    schema_version: CONNECTOR_SCHEMA_VERSION,
    event_id: opts.eventId,
    event_type: opts.eventType,
    tenant_id: opts.tenantId,
    emitted_at: opts.emittedAt ?? new Date().toISOString(),
    ...(opts.batch ? { batch: opts.batch } : {}),
    data: opts.data ?? {},
  }
}

/** Structural validity check a receiving edge can run before trusting an
 *  envelope. Returns a reason string on failure, null on success. This is a
 *  shape check, not an authenticity check; authenticity is the HMAC + JWS the
 *  webhook sink attaches and the customer verifies. */
export function validateConnectorEvent(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return 'event is not an object'
  const e = value as Record<string, unknown>
  if (e.schema_version !== CONNECTOR_SCHEMA_VERSION) {
    return `unsupported schema_version: ${String(e.schema_version)}`
  }
  if (typeof e.event_id !== 'string' || e.event_id.length === 0) return 'event_id missing'
  if (typeof e.event_type !== 'string') return 'event_type missing'
  if (typeof e.tenant_id !== 'string' || e.tenant_id.length === 0) return 'tenant_id missing'
  if (typeof e.emitted_at !== 'string' || Number.isNaN(Date.parse(e.emitted_at))) {
    return 'emitted_at is not a valid ISO 8601 timestamp'
  }
  if (typeof e.data !== 'object' || e.data === null) return 'data missing'
  return null
}
