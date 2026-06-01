// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - Air-gapped export bundle
// ══════════════════════════════════════════════════════════════════
// An air-gapped deployment has no outbound network path: no Rekor anchor,
// no cross-tenant emission, no remote license check. The customer still
// needs to get a verifiable audit bundle OUT of the appliance and into an
// auditor's hands offline. This module assembles that bundle by reusing
// the existing audit-export surface (queryAuditRecords / toJsonLines /
// toCsv) plus the gateway JWKS, so an offline verifier can check every
// receipt hash and the gateway signature WITHOUT contacting AEOESS.
//
// THIN-GATEWAY: the bundle is self-verifying at the edge. Verification is
// the auditor's offline verifier checking hashes against the customer-pinned
// trust root + the bundled JWKS. AEOESS is not in the verification path.
//
// Hash-and-pointer: the bundle carries receipt HASHES, never raw payloads,
// so an air-gapped regulated tenant can export audit evidence without PHI
// ever leaving the appliance.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import {
  queryAuditRecords,
  toJsonLines,
  toCsv,
  type AuditRecord,
} from '../audit-export.js'
import { getJwks } from '../identity.js'

/** A fully offline-verifiable export bundle. */
export interface AirGapBundle {
  schema_version: '1.0.0'
  tenant_id: string
  period: { from: string; to: string }
  generated_at: string
  /** JWKS so an offline verifier can check the gateway signature without
   *  fetching /.well-known/jwks.json over a (nonexistent) network. */
  jwks: ReturnType<typeof getJwks>
  /** Audit records (receipt HASHES only, never raw payloads). */
  records: AuditRecord[]
  /** sha256 over the canonical JSON of records, the bundle integrity seal. */
  records_digest: string
  /** Count for a quick offline sanity check. */
  record_count: number
  /** Marks that this bundle is meant for offline verification. */
  offline_verifiable: true
}

/**
 * Assemble an air-gapped audit bundle for a tenant and period. Reuses the
 * existing audit-export query so the in-tenant bundle and the hosted export
 * stay byte-for-byte consistent.
 */
export function buildAirGapBundle(opts: {
  tenantId: string
  from: string
  to: string
  scope?: string
}): AirGapBundle {
  const records = queryAuditRecords(opts.tenantId, opts.from, opts.to, opts.scope)
  const canonical = JSON.stringify(records)
  const recordsDigest = createHash('sha256').update(canonical).digest('hex')
  return {
    schema_version: '1.0.0',
    tenant_id: opts.tenantId,
    period: { from: opts.from, to: opts.to },
    generated_at: new Date().toISOString(),
    jwks: getJwks(),
    records,
    records_digest: recordsDigest,
    record_count: records.length,
    offline_verifiable: true,
  }
}

/**
 * Offline verification: recompute the records digest and confirm it matches
 * the sealed value. An auditor runs this on the appliance with no network.
 * Returns true if the bundle is internally consistent. Signature / trust-root
 * verification against the customer-pinned anchor is the verifier's job and
 * uses the bundled JWKS (or the customer trust root for BYO-root tenants).
 */
export function verifyAirGapBundleOffline(bundle: AirGapBundle): {
  consistent: boolean
  reason: string
} {
  const recomputed = createHash('sha256').update(JSON.stringify(bundle.records)).digest('hex')
  if (recomputed !== bundle.records_digest) {
    return { consistent: false, reason: 'records digest mismatch: bundle was altered' }
  }
  if (bundle.record_count !== bundle.records.length) {
    return { consistent: false, reason: 'record_count does not match records length' }
  }
  if (!bundle.jwks || !Array.isArray(bundle.jwks.keys) || bundle.jwks.keys.length === 0) {
    return { consistent: false, reason: 'bundle carries no JWKS; offline signature check impossible' }
  }
  return { consistent: true, reason: 'digest and JWKS present; offline-verifiable' }
}

/** Serialize the bundle to JSON Lines for SIEM ingest of the records side
 *  (reuses the existing audit-export formatter). */
export function bundleRecordsToJsonLines(bundle: AirGapBundle): string {
  return toJsonLines(bundle.records)
}

/** Serialize the bundle records to CSV (reuses audit-export formatter). */
export function bundleRecordsToCsv(bundle: AirGapBundle): string {
  return toCsv(bundle.records)
}
