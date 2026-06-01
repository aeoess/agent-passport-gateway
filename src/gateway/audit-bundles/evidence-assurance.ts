// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D2 - Wave 2 integration seam: evidence-assurance descriptor.
// ══════════════════════════════════════════════════════════════════
// The net-new 'evidence-assurance descriptor' is a VERIFIER-DERIVED assurance
// level attached to each evidence item in a bundle. The authoritative producer
// lives in the SDK Wave 2 module and is NOT part of the installed alpha.3 pin.
//
// This file is the typed boundary the bundle assembler derives assurance
// against, so the Wave 2 surface can drop in without touching the assembler.
//
// Until Wave 2 lands, a PROVISIONAL assurance is derived from the installed
// SDK surface (classifyEvidenceQuality + isEvidenceFresh) so the field is
// populated but clearly marked verifier-derived and non-authoritative. The
// gateway never sets assurance as an issuer; assurance is always derived from
// observable evidence properties so an edge verifier can reach the same result.
// ══════════════════════════════════════════════════════════════════

import {
  classifyEvidenceQuality,
  isEvidenceFresh,
} from 'agent-passport-system'
import type { EvidenceAssuranceDescriptor } from './types.js'

/** Input to the provisional assurance derivation, kept SDK-shaped. */
export interface EvidenceAssuranceInput {
  evidenceRef: string
  /** SDK EvidenceType taxonomy value (receipt | witness_attestation | ...). */
  evidenceType: string
  /** Identity method prefix, when known (did:key, spiffe, oauth). */
  method?: string
  hasIssuerSignature?: boolean
  hasPrincipalBinding?: boolean
  /** Raw evidence payload, checked loosely for infrastructure-binding keys. */
  evidence?: Record<string, unknown>
  /** ISO 8601 timestamp the evidence was produced, for freshness. */
  validAt?: string
  /** Recommended staleness window in seconds (snapshot evidence). */
  maxAgeSeconds?: number
}

/** Map the SDK EvidenceQuality vocabulary to the bundle descriptor level. */
function qualityToLevel(
  quality: 'none' | 'issuer_vouched' | 'infrastructure' | 'principal_bound',
): EvidenceAssuranceDescriptor['level'] {
  return quality === 'none' ? 'unverified' : quality
}

/**
 * Derive a verifier-derived evidence-assurance descriptor.
 *
 * STUB: authoritative is false until the Wave 2 module is wired. The level is
 * derived from the installed SDK so the field is meaningful, but a reader must
 * treat it as provisional. The plain receipt-chain + Merkle root remain the
 * authoritative tamper-evidence in the meantime.
 *
 * // TODO(W2-evidence-descriptor): replace this provisional derivation with the
 * //   SDK Wave 2 evidence-assurance descriptor
 * //   (deriveEvidenceAssurance / classifyEvidenceAssurance), which will return
 * //   a verifier-derived assurance level per TypedEvidence item. Until then we
 * //   approximate with classifyEvidenceQuality + isEvidenceFresh.
 */
export function deriveEvidenceAssurance(
  input: EvidenceAssuranceInput,
  now: Date = new Date(),
): EvidenceAssuranceDescriptor {
  const quality = classifyEvidenceQuality({
    method: input.method,
    hasIssuerSignature: input.hasIssuerSignature,
    hasPrincipalBinding: input.hasPrincipalBinding,
    evidence: input.evidence,
  })

  let fresh = true
  if (input.validAt) {
    try {
      fresh = isEvidenceFresh(
        {
          type: 'snapshot',
          validAt: input.validAt,
          maxAge: input.maxAgeSeconds,
        },
        now,
      )
    } catch {
      // A malformed timestamp cannot be asserted fresh.
      fresh = false
    }
  }

  return {
    evidenceRef: input.evidenceRef,
    evidenceType: input.evidenceType,
    level: qualityToLevel(quality),
    fresh,
    derivation: 'verifier_derived',
    authoritative: false,
    note: 'wave2_evidence_descriptor_not_installed; provisional level from classifyEvidenceQuality',
  }
}

/** Whether the authoritative Wave 2 evidence-assurance path is available.
 *  Always false against the installed alpha; flips when Wave 2 is wired. */
export function evidenceAssuranceAuthoritative(): boolean {
  return false
}
