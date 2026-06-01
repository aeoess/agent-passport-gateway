// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Source-class evaluator
// ══════════════════════════════════════════════════════════════════
// Reads a connector source label, records the class + confidence, and
// derives an ASSURANCE GRADE. The class is itself an assurance-graded
// claim: the connector says WHAT the class is and HOW it knows
// (declared / detected / inferred); the gateway derives HOW MUCH
// assurance that carries. The grade is VERIFIER-DERIVED via the SDK
// classifyEvidenceQuality -> evidenceQualityToGrade pattern. It is NOT
// an issuer-set field - the connector cannot hand us a grade.
//
// Thin verdict shape copied from type-interceptor.ts: this function owns
// no state, never logs, never mutates, never fans out. It returns a
// typed SourceClassification and the caller (the router) decides whether
// to persist, sign, and emit.
//
// The class comes ONLY from the label. There is no payload-scanning path
// here. classifyFromLabel never sees source content, only the label.
// ══════════════════════════════════════════════════════════════════

import { classifyEvidenceQuality, evidenceQualityToGrade } from 'agent-passport-system'
import type { PassportGrade, EvidenceQuality } from 'agent-passport-system'
import type { ConnectorSourceLabel, SourceConfidence } from './connector-label.js'

/** The recorded classification of a source. The class string is verbatim
 *  from the connector; confidence is the connector's self-report; grade
 *  is gateway-derived. */
export interface SourceClassification {
  sourceId: string
  /** Verbatim from the connector label. May be outside DATA_CLASSES. */
  dataClass: string
  /** Source-supplied: how the connector arrived at the class. */
  confidence: SourceConfidence
  /** Verifier-derived assurance grade (0..3). Computed, never asserted. */
  grade: PassportGrade
  /** The SDK evidence-quality bucket the grade came from, for audit. */
  evidenceQuality: EvidenceQuality
  /** Provenance of the label, kept for the audit trail. */
  evidence: {
    connectorId: string
    recordType?: string
    fieldRef?: string
  }
}

/**
 * Map a connector's source-confidence to the SDK evidence-quality inputs.
 *
 * The SDK classifyEvidenceQuality precedence is:
 *   principal binding -> 'principal_bound'    (grade 3)
 *   infrastructure evidence -> 'infrastructure' (grade 2)
 *   issuer signature -> 'issuer_vouched'       (grade 1)
 *   none -> 'none'                             (grade 0)
 *
 * We do not have an LLM or a payload scan in this path, so the grade is a
 * function of how the SOURCE labeled itself plus what backs the label:
 *
 *   declared  - the source/custodian declared the class against a concrete
 *               field or record type. That is an issuer-vouched assertion
 *               about its own data; if a field/record reference backs it we
 *               treat the connector as infrastructure evidence (the label
 *               is bound to a system-of-record location). Highest assurance
 *               available without a principal binding.
 *   detected  - the connector detected the class from a system signal but
 *               not a declared field. Issuer-vouched.
 *   inferred  - the class was inferred. No issuer signature, no
 *               infrastructure binding. Lowest assurance ('none').
 *
 * TODO(W2-classification): when the SDK ships classifyDataClass, this
 *   mapping and the grade derivation move into the SDK and we consume the
 *   returned grade directly instead of re-deriving it here.
 */
function gradeForLabel(label: ConnectorSourceLabel): {
  grade: PassportGrade
  evidenceQuality: EvidenceQuality
} {
  // A field/record reference means the label is bound to a concrete
  // system-of-record location - we surface that as infrastructure
  // evidence to the SDK classifier.
  const hasRecordBinding = Boolean(label.fieldRef || label.recordType)

  let evidenceQuality: EvidenceQuality
  switch (label.confidence) {
    case 'declared':
      evidenceQuality = classifyEvidenceQuality({
        method: 'connector',
        hasIssuerSignature: true,
        evidence: hasRecordBinding
          ? { spiffe_id: `connector:${label.connectorId}` }
          : undefined,
      })
      break
    case 'detected':
      evidenceQuality = classifyEvidenceQuality({
        method: 'connector',
        hasIssuerSignature: true,
      })
      break
    case 'inferred':
    default:
      evidenceQuality = classifyEvidenceQuality({ method: 'connector' })
      break
  }

  return { grade: evidenceQualityToGrade(evidenceQuality), evidenceQuality }
}

/**
 * Classify a source from its connector label. Pure, deterministic, thin.
 *
 * @param label  A connector-emitted source label. The ONLY input. There
 *               is no payload argument by design: classification never
 *               scans gateway payload in the default path.
 * @returns      A SourceClassification with a verifier-derived grade.
 */
export function classifyFromLabel(label: ConnectorSourceLabel): SourceClassification {
  const { grade, evidenceQuality } = gradeForLabel(label)
  return {
    sourceId: label.sourceId,
    dataClass: label.declaredClass,
    confidence: label.confidence,
    grade,
    evidenceQuality,
    evidence: {
      connectorId: label.connectorId,
      recordType: label.recordType,
      fieldRef: label.fieldRef,
    },
  }
}
