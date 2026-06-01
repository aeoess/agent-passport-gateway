// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - OCSF formatting
// ══════════════════════════════════════════════════════════════════
// Maps a versioned ConnectorEvent into an OCSF (Open Cybersecurity Schema
// Framework) record so a customer SIEM ingests gateway events in a standard
// shape rather than a bespoke one. OCSF is the format; OpenTelemetry is the
// transport (see otel-ocsf.ts). This module is pure shaping, like
// audit-export.ts's toJsonLines/toCsv: it reads a ConnectorEvent and returns a
// plain object. No I/O, no enforcement.
//
// OCSF mapping reference: events map to the "API Activity" (class_uid 6003) and
// "Account Change" (class_uid 3001) classes under the Application / IAM
// categories. The values used here are the published OCSF identifiers; the
// mapping is validated structurally in the connector tests.
// ══════════════════════════════════════════════════════════════════

import type { ConnectorEvent } from './event-schema.js'

/** Minimal OCSF base record fields shared by every class. */
export interface OcsfRecord {
  /** OCSF metadata block. */
  metadata: {
    version: string
    product: { name: string; vendor_name: string }
    /** Maps to ConnectorEvent.event_id for end-to-end correlation. */
    uid: string
  }
  /** OCSF category (high level). */
  category_uid: number
  category_name: string
  /** OCSF class within the category. */
  class_uid: number
  class_name: string
  /** OCSF activity within the class. */
  activity_id: number
  /** Severity 0..6 per OCSF severity_id. */
  severity_id: number
  /** Event time in epoch milliseconds, per OCSF `time`. */
  time: number
  /** Human-readable summary. */
  message: string
  /** Structural, non-leaf detail. */
  unmapped: Record<string, unknown>
}

const OCSF_VERSION = '1.3.0'
const PRODUCT = { name: 'AEOESS Gateway', vendor_name: 'AEOESS' }

// OCSF category / class identifiers used by this gateway's mapping.
const CAT_APPLICATION = { uid: 6, name: 'Application Activity' }
const CAT_IAM = { uid: 3, name: 'Identity & Access Management' }
const CLASS_API_ACTIVITY = { uid: 6003, name: 'API Activity' }
const CLASS_ACCOUNT_CHANGE = { uid: 3001, name: 'Account Change' }

/**
 * Format a connector event as an OCSF record. The class is selected by event
 * type: identity offboard and revocation map to Account Change (IAM); batch and
 * alert events map to API Activity (Application). Counts and the Merkle root
 * travel in `unmapped`; no granular leaves are ever included.
 */
export function toOcsf(event: ConnectorEvent): OcsfRecord {
  const time = Date.parse(event.emitted_at) || Date.now()
  const base = {
    metadata: { version: OCSF_VERSION, product: PRODUCT, uid: event.event_id },
    time,
    unmapped: buildUnmapped(event),
  }

  switch (event.event_type) {
    case 'identity_offboard':
      return {
        ...base,
        category_uid: CAT_IAM.uid,
        category_name: CAT_IAM.name,
        class_uid: CLASS_ACCOUNT_CHANGE.uid,
        class_name: CLASS_ACCOUNT_CHANGE.name,
        activity_id: 4, // Delete / Disable
        severity_id: 3, // Medium
        message: `Identity offboard mapped to gateway revoke for tenant ${event.tenant_id}`,
      }
    case 'revocation':
      return {
        ...base,
        category_uid: CAT_IAM.uid,
        category_name: CAT_IAM.name,
        class_uid: CLASS_ACCOUNT_CHANGE.uid,
        class_name: CLASS_ACCOUNT_CHANGE.name,
        activity_id: 4, // Delete / Disable
        severity_id: 4, // High
        message: `Revocation emitted for tenant ${event.tenant_id}`,
      }
    case 'alert':
      return {
        ...base,
        category_uid: CAT_APPLICATION.uid,
        category_name: CAT_APPLICATION.name,
        class_uid: CLASS_API_ACTIVITY.uid,
        class_name: CLASS_API_ACTIVITY.name,
        activity_id: 0, // Unknown / generic
        severity_id: severityForAlert(event),
        message: `Gateway alert for tenant ${event.tenant_id}`,
      }
    default:
      return {
        ...base,
        category_uid: CAT_APPLICATION.uid,
        category_name: CAT_APPLICATION.name,
        class_uid: CLASS_API_ACTIVITY.uid,
        class_name: CLASS_API_ACTIVITY.name,
        activity_id: 1, // Create
        severity_id: 1, // Informational
        message: `${event.event_type} emitted for tenant ${event.tenant_id}`,
      }
  }
}

function severityForAlert(event: ConnectorEvent): number {
  const sev = (event.data?.severity as string | undefined)?.toLowerCase()
  if (sev === 'critical') return 5
  if (sev === 'high') return 4
  if (sev === 'medium') return 3
  if (sev === 'low') return 2
  return 1
}

function buildUnmapped(event: ConnectorEvent): Record<string, unknown> {
  const unmapped: Record<string, unknown> = {
    schema_version: event.schema_version,
    connector_event_type: event.event_type,
    tenant_id: event.tenant_id,
    ...event.data,
  }
  if (event.batch) {
    // Aggregate-only: root + summary + counts. No leaves.
    unmapped.batch = {
      batch_id: event.batch.batchId,
      merkle_root: event.batch.merkleRoot,
      epoch: event.batch.epoch,
      receipt_count: event.batch.receiptCount,
      committed_at: event.batch.committedAt,
      summary: event.batch.summary,
    }
  }
  return unmapped
}

/**
 * Structural validity check for an OCSF record. Confirms the required OCSF base
 * fields are present and well-typed. Returns a reason on failure, null on
 * success. Used by the connector tests to assert "OCSF format is valid".
 */
export function validateOcsf(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return 'record is not an object'
  const r = value as Record<string, any>
  if (typeof r.metadata !== 'object' || r.metadata === null) return 'metadata missing'
  if (r.metadata.version !== OCSF_VERSION) return `unexpected OCSF version: ${r.metadata.version}`
  if (typeof r.metadata.uid !== 'string' || !r.metadata.uid) return 'metadata.uid missing'
  if (typeof r.metadata.product?.name !== 'string') return 'metadata.product.name missing'
  for (const f of ['category_uid', 'class_uid', 'activity_id', 'severity_id', 'time'] as const) {
    if (typeof r[f] !== 'number') return `${f} missing or not a number`
  }
  if (r.severity_id < 0 || r.severity_id > 6) return 'severity_id out of OCSF range 0..6'
  if (typeof r.class_name !== 'string') return 'class_name missing'
  if (typeof r.message !== 'string') return 'message missing'
  return null
}
