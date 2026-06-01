// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway - Compliance Control Mapping (Build G-D2).
 *
 * This is the net-new evidence layer on top of the existing governance export.
 * It maps gateway-held evidence to named controls using SUPPORTS-EVIDENCE-FOR
 * language only. It NEVER states that a bundle makes a customer compliant, and
 * it never asserts an assurance level the way an issuer would; assurance is
 * verifier-derived elsewhere in the bundle.
 *
 * CLAIMS discipline (this file is the gated surface, founder review by Tima):
 *  - the only mapping verb is 'supports evidence for'
 *  - EU AI Act obligations are described as ones regulators 'increasingly
 *    require', never as obligations this product discharges
 *  - no 'instant revocation', no 'proved', no 'guaranteed', no 'makes you
 *    compliant', no 'certified'
 *  - every entry carries an explicit evidence-limits statement in the same
 *    voice as the decision-receipt disclaimer (enforce.ts line ~1799) and the
 *    governance-export scoping note (enforce.ts line ~2363)
 *  - no em dashes anywhere in this file
 */

import type { ControlMappingEntry } from './types.js'

/**
 * Shared evidence-limits voice. Mirrors the decision-receipt disclaimer style:
 * a structured evidentiary record that may support review, not a legal
 * determination and not a statement of compliance.
 */
export const BUNDLE_EVIDENCE_LIMITS =
  'This bundle is a structured evidentiary record that may support audit, ' +
  'compliance review, contractual enforcement, or legal review depending on ' +
  'jurisdiction and context. It supports evidence for the controls listed and ' +
  'does not by itself make any organization compliant, does not constitute a ' +
  'legal determination, and covers gateway-tracked interactions only. Absence ' +
  'of a receipt does not prove absence of an event.'

/**
 * The control catalog. Each entry says what gateway evidence SUPPORTS EVIDENCE
 * FOR a named control, what bundle sections back it, and what the evidence does
 * not establish. Frameworks covered: EU AI Act, GDPR, SOC 2, ISO 42001, NIST.
 *
 * The catalog is intentionally conservative. A control appears only where the
 * bundle carries a record that an auditor can independently re-derive.
 */
const CONTROL_CATALOG: ControlMappingEntry[] = [
  {
    framework: 'EU AI Act',
    controlId: 'Article 12',
    controlName: 'Record-keeping and automatic logging',
    supportsEvidenceFor:
      'High-risk AI system providers are increasingly required to keep ' +
      'automatically generated logs of events over the system lifetime. The ' +
      'signed receipt chain and hash-manifest in this bundle support evidence ' +
      'for the existence, ordering, and tamper-evidence of those logs.',
    backedBy: ['receiptChain', 'hashManifest', 'records'],
    evidenceLimits:
      'Supports evidence that logged events were recorded and have not been ' +
      'altered since sealing. Does not establish that logging coverage is ' +
      'complete or that the logged system is the regulated system.',
  },
  {
    framework: 'EU AI Act',
    controlId: 'Article 14',
    controlName: 'Human oversight',
    supportsEvidenceFor:
      'Human oversight measures are increasingly required for high-risk AI ' +
      'systems. The approval and decision evidence in this bundle supports ' +
      'evidence for where a human-in-the-loop approval or a policy decision ' +
      'gated an action.',
    backedBy: ['approvalEvidence', 'records'],
    evidenceLimits:
      'Supports evidence that an approval or decision was recorded at decision ' +
      'time. Does not establish that the human reviewer was competent, ' +
      'attentive, or authorized beyond what the record states.',
  },
  {
    framework: 'EU AI Act',
    controlId: 'Article 10',
    controlName: 'Data and data governance',
    supportsEvidenceFor:
      'Data governance practices are increasingly required for high-risk AI ' +
      'systems. The scope, action-type, and delegation-chain records in this ' +
      'bundle support evidence for which authorities and data scopes were in ' +
      'effect for each recorded action.',
    backedBy: ['records', 'approvalEvidence'],
    evidenceLimits:
      'Supports evidence about authorized scope at decision time. Does not ' +
      'establish data quality, representativeness, or lawful basis for the ' +
      'underlying data.',
  },
  {
    framework: 'GDPR',
    controlId: 'Article 30',
    controlName: 'Records of processing activities',
    supportsEvidenceFor:
      'Controllers and processors maintain records of processing activities. ' +
      'The machine-readable record set and receipt chain support evidence for ' +
      'a record of automated processing events, the agents involved, and the ' +
      'scopes exercised.',
    backedBy: ['records', 'receiptChain'],
    evidenceLimits:
      'Supports evidence for a log of recorded processing events. Does not ' +
      'establish purpose limitation, lawful basis, or that all processing ' +
      'activities are captured.',
  },
  {
    framework: 'GDPR',
    controlId: 'Article 17',
    controlName: 'Right to erasure and revocation handling',
    supportsEvidenceFor:
      'Erasure and withdrawal of authorization leave an evidentiary trail. ' +
      'The revocation checks in this bundle support evidence for whether a ' +
      'delegation or agent authority was revoked at bundle time and whether ' +
      'any ancestor authority was revoked.',
    backedBy: ['revocationChecks'],
    evidenceLimits:
      'Supports evidence for the revocation state observed at bundle time. ' +
      'Revocation propagation to downstream sinks is enforced at the edge ' +
      'through the epoch check and is not asserted as immediate here.',
  },
  {
    framework: 'SOC 2',
    controlId: 'CC7.2',
    controlName: 'System monitoring and anomaly detection',
    supportsEvidenceFor:
      'The trust services criteria call for monitoring of system components. ' +
      'The sealed receipt windows and Merkle commitments support evidence for ' +
      'continuous, tamper-evident monitoring of authorization decisions.',
    backedBy: ['hashManifest', 'receiptChain'],
    evidenceLimits:
      'Supports evidence that monitoring records exist and are tamper-evident. ' +
      'Does not establish that monitoring detected every relevant anomaly.',
  },
  {
    framework: 'SOC 2',
    controlId: 'CC6.1',
    controlName: 'Logical access controls',
    supportsEvidenceFor:
      'The criteria call for logical access controls over system resources. ' +
      'The delegation-chain and scope records support evidence for which ' +
      'authority permitted each recorded action.',
    backedBy: ['records', 'approvalEvidence'],
    evidenceLimits:
      'Supports evidence for the authority asserted at decision time. Does not ' +
      'establish the correctness of the access policy itself.',
  },
  {
    framework: 'ISO 42001',
    controlId: 'A.6.2.8',
    controlName: 'AI system recording of events',
    supportsEvidenceFor:
      'The AI management system standard calls for recording of system ' +
      'events. The receipt chain and hash-manifest support evidence for a ' +
      'recorded, tamper-evident event history.',
    backedBy: ['receiptChain', 'hashManifest'],
    evidenceLimits:
      'Supports evidence for recorded events within gateway scope. Does not ' +
      'establish conformance of the broader management system.',
  },
  {
    framework: 'NIST AI RMF',
    controlId: 'MEASURE 2.7',
    controlName: 'AI system security and resilience tracking',
    supportsEvidenceFor:
      'The framework calls for tracking that supports measurement of AI ' +
      'system behavior. The signed manifest and inclusion proofs support ' +
      'evidence for independently verifiable tracking of recorded decisions.',
    backedBy: ['hashManifest', 'records'],
    evidenceLimits:
      'Supports evidence for verifiable tracking of recorded decisions. Does ' +
      'not establish a security or resilience outcome.',
  },
]

/**
 * Return the control mapping entries relevant to a bundle.
 *
 * For a per-compliance-control bundle a specific control may be requested via
 * controlId. Otherwise the full catalog is returned so the bundle can disclose
 * what evidence it carries against each control, in supports-evidence-for terms.
 */
export function buildControlMapping(opts?: {
  controlId?: string
  framework?: string
}): ControlMappingEntry[] {
  let entries = CONTROL_CATALOG
  if (opts?.framework) {
    const f = opts.framework.toLowerCase()
    entries = entries.filter((e) => e.framework.toLowerCase() === f)
  }
  if (opts?.controlId) {
    const c = opts.controlId.toLowerCase()
    entries = entries.filter((e) => e.controlId.toLowerCase() === c)
  }
  // Return copies so callers cannot mutate the catalog.
  return entries.map((e) => ({ ...e, backedBy: [...e.backedBy] }))
}

/** Distinct frameworks the catalog covers, for discovery endpoints. */
export function listControlFrameworks(): string[] {
  return Array.from(new Set(CONTROL_CATALOG.map((e) => e.framework)))
}

/**
 * Claims-language guard. Returns the list of forbidden phrases found in a
 * string, empty when the copy passes. Used by the assembler and the tests to
 * keep every customer-facing line within the claims discipline. The check is
 * deliberately strict so a regression in the catalog copy fails the suite.
 */
const FORBIDDEN_CLAIMS = [
  'makes you compliant',
  'make you compliant',
  'makes your organization compliant',
  'makes any organization compliant',
  'ensures compliance',
  'guarantees compliance',
  'instant revocation',
  'instantly revoke',
  'guaranteed',
  'guarantee compliance',
  'we guarantee',
  'proved',
  'proven compliant',
  'certified compliant',
  'fully compliant',
  'legally compliant',
]

export function findForbiddenClaims(text: string): string[] {
  const lower = text.toLowerCase()
  const found: string[] = []
  for (const phrase of FORBIDDEN_CLAIMS) {
    if (lower.includes(phrase)) found.push(phrase)
  }
  // Em dash is forbidden in all written copy.
  if (text.includes('\u2014')) found.push('em-dash')
  return found
}

/**
 * Assert that every control mapping entry passes the claims check. Throws with
 * the offending phrases if any line regresses. The assembler calls this before
 * a bundle is signed so a claims regression can never be emitted to a customer.
 */
export function assertControlMappingClaimsSafe(
  entries: ControlMappingEntry[],
): void {
  for (const e of entries) {
    const fields = [
      e.supportsEvidenceFor,
      e.controlName,
      e.evidenceLimits,
    ]
    for (const field of fields) {
      const bad = findForbiddenClaims(field)
      if (bad.length > 0) {
        throw new Error(
          `Control mapping claims violation in ${e.framework} ${e.controlId}: ${bad.join(', ')}`,
        )
      }
    }
    // Every entry must use the supports-evidence-for verb explicitly.
    if (!/supports? evidence for/i.test(e.supportsEvidenceFor)) {
      throw new Error(
        `Control mapping ${e.framework} ${e.controlId} must use supports-evidence-for language`,
      )
    }
  }
}
