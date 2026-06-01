// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Public Receipt Body Projection
// ══════════════════════════════════════════════════════════════════
// Security triage 2026-04-11 fix 2.
//
// The public receipt resolution endpoint at /.well-known/receipts/:id
// is unauthenticated by design (it is a cross-system lineage resolver
// for WG interop). Before this fix, the endpoint returned
// JSON.parse(row[payloadField]) verbatim, which meant tenant IDs,
// delegation details, spend amounts, principal IDs, and any other
// field the writer had stored would leak to any caller who knew a
// receipt ID. Receipt IDs leak via logs, shared URLs, screenshots,
// and response headers on sibling endpoints, so treating the ID as
// a soft authorization mechanism was not defensible.
//
// This module projects the parsed payload to a whitelist of
// public-safe fields per receipt type. Anything outside the
// whitelist is silently dropped. Relying parties that need the full
// canonical payload to verify the signature themselves must fetch it
// through an authenticated endpoint.
//
// The public endpoint additionally returns payloadSha256 (a SHA-256
// fingerprint of the canonical payload bytes) so that a consumer who
// obtains the full payload elsewhere can confirm it matches what the
// gateway signed. This preserves the "public transparency fingerprint"
// use case without leaking the payload contents.
//
// Reference: CODE-AUDIT-2026-04-11.md §2.9.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'

// Per-type whitelists. Any field not listed here is silently dropped.
// Whitelists are intentionally conservative: if a consumer needs a new
// field to be exposed publicly, it should be an explicit policy decision
// and a separate PR, not a leak by default.
export const PUBLIC_BODY_WHITELISTS: Record<string, readonly string[]> = {
  policy_receipt: [
    'schema_version', 'verdict', 'receipt_hash', 'action_type',
    'action_hash', 'scope_hash', 'evaluation_id', 'issued_at',
    'timestamp', 'duration_ms', 'task_class',
  ],
  access_receipt: [
    'schema_version', 'receipt_hash', 'issued_at', 'timestamp',
    'purpose_hash', 'source_hash',
  ],
  derivation_receipt: [
    'schema_version', 'receipt_id', 'receipt_hash', 'derivative_type',
    'transform_class', 'lineage_confidence', 'timestamp',
    'external_boundary_break', 'is_synthetic_derivative',
  ],
  settlement: [
    'schema_version', 'merkle_root', 'period', 'timestamp', 'receipt_hash',
  ],
  // G-C3 scoped approval. Public-safe fields ONLY: class/tier/verdict, the
  // scope and approver fingerprints (hashes), counts, and the issued_at
  // timestamp. Deliberately excludes reason text, raw approver public keys,
  // approver ids, subject internals, requested_by, and tenant id - none of
  // those names appear here, so projectPublicBody drops them by default.
  approval_receipt: [
    'schema_version', 'proof_type', 'request_id', 'action_class',
    'risk_tier', 'verdict', 'subject_type', 'scope_hash', 'approvers_hash',
    'signature_count', 'sampled', 'issued_at', 'receipt_hash', 'statement',
  ],
}

/** Fields that a row fallback is allowed to expose when no parsed
 *  payload is available. These correspond to top-level columns on the
 *  receipt tables that are safe to show publicly. */
function rowFallbackBody(row: any): Record<string, any> {
  return {
    id: row.id,
    event_type: row.event_type || row.action_type || null,
    verdict: row.verdict || null,
    created_at: row.created_at,
    schema_version: row.schema_version || null,
    receipt_hash: row.receipt_hash || null,
  }
}

/**
 * Project a receipt body to its public-safe fields.
 *
 * @param proofType       e.g. 'policy_receipt', 'access_receipt'
 * @param row             The raw DB row for the receipt
 * @param parsedPayload   The JSON-parsed payload field (if any), or null
 * @returns               Whitelisted projection; never contains tenant
 *                        IDs, spend amounts, delegation details, or
 *                        principal IDs unless one of those names is
 *                        explicitly added to the whitelist.
 */
export function projectPublicBody(
  proofType: string,
  row: any,
  parsedPayload: any,
): Record<string, any> {
  const fallback = rowFallbackBody(row)
  if (!parsedPayload || typeof parsedPayload !== 'object' || Array.isArray(parsedPayload)) {
    return fallback
  }
  const safe = PUBLIC_BODY_WHITELISTS[proofType] || []
  const projected: Record<string, any> = { ...fallback }
  for (const key of safe) {
    if (Object.prototype.hasOwnProperty.call(parsedPayload, key)) {
      projected[key] = parsedPayload[key]
    }
  }
  return projected
}

/** Hex-encoded SHA-256 fingerprint of the canonical payload bytes.
 *  Exposed publicly so that a consumer who obtains the full payload
 *  elsewhere can confirm it matches what the gateway signed. */
export function payloadFingerprint(payload: string | Buffer): string {
  return createHash('sha256').update(payload).digest('hex')
}
