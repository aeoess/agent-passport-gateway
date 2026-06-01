// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway - Signed Audit Evidence Bundles (Build G-D2): shared types.
 *
 * The real artifact is a SIGNED BUNDLE MANIFEST (canonical JSON), not a PDF.
 * The bundle is a pre-signed, customer-owned artifact. A verifier checks it at
 * the edge against the gateway JWKS at /.well-known/jwks.json. The gateway
 * coordinates, hashes, signs, and emits. It holds no enforcement authority over
 * the bundle once it has been handed to the customer.
 *
 * Assurance attached to each evidence item is VERIFIER-DERIVED, never
 * issuer-set. See evidence-assurance.ts.
 */

/** The five bundle scopes G-D2 supports. */
export type BundleType =
  | 'per-action'
  | 'per-agent'
  | 'per-policy'
  | 'per-incident'
  | 'per-compliance-control'

/** Stable schema discriminator for the signed manifest. Distinct from the
 *  payment 'settlement' schema and from the egress batch schema. */
export const AUDIT_BUNDLE_SCHEMA_VERSION = 'audit_bundle_v1'

/**
 * A single leaf in the bundle hash-manifest. The leafHash is the canonical
 * hash (SDK canonicalHash over the canonical form) of the referenced record,
 * so any verifier can recompute it independently from the embedded record.
 */
export interface BundleLeaf {
  /** What kind of record this leaf commits to. */
  kind:
    | 'audit_record'
    | 'decision_record'
    | 'receipt_seal'
    | 'policy_version'
    | 'revocation_check'
    | 'approval_evidence'
  /** Stable identifier of the source row (receipt id, seal id, etc). */
  sourceRef: string
  /** Canonical hash of the embedded record (hex). */
  leafHash: string
}

/**
 * Verifier-derived assurance descriptor attached to each evidence item.
 *
 * PROVISIONAL today: derived from the installed SDK classifyEvidenceQuality +
 * isEvidenceFresh. The net-new SDK Wave 2 evidence-assurance descriptor
 * replaces the producer (see evidence-assurance.ts). The field is always
 * marked verifier-derived so no reader mistakes it for an issuer claim.
 */
export interface EvidenceAssuranceDescriptor {
  /** The evidence item this assurance is about. */
  evidenceRef: string
  /** SDK evidence type taxonomy value. */
  evidenceType: string
  /** Provisional assurance level. Ordered weakest to strongest. */
  level: 'unverified' | 'issuer_vouched' | 'infrastructure' | 'principal_bound'
  /** True when the evidence freshness window still holds at bundle time. */
  fresh: boolean
  /** Where this assurance came from. Always 'verifier_derived' so it can
   *  never be read as an issuer-set assurance claim. */
  derivation: 'verifier_derived'
  /** Whether the authoritative SDK Wave 2 descriptor produced this. While the
   *  Wave 2 module is stubbed this is false and 'level' is provisional. */
  authoritative: boolean
  /** Stub marker when not authoritative. */
  note?: string
}

/** Backbone tamper-evidence reference for the hash-manifest. */
export interface BundleHashManifest {
  /** Canonicalization + hash algorithm identifiers a verifier must use. */
  canonicalization: 'sdk-canonicalize'
  hashAlgorithm: 'sha-256'
  /** Per-record canonical leaf hashes. */
  leaves: BundleLeaf[]
  /** Merkle root over the leaves. */
  merkleRoot: string
  /** Which Merkle backbone produced the root. See merkle-backbone.ts. */
  rootSource: 'gem_batch' | 'receipt_window_seal' | 'sdk_leaf_merkle'
  /** Inclusion proofs keyed by leafHash, when the backbone can produce them. */
  inclusionProofs?: Record<string, unknown>
  /** Optional independent temporal anchor reference (Rekor), when available. */
  temporalAnchor?: { backbone: 'rekor'; anchored: boolean; note?: string }
}

/** A control mapping line. SUPPORTS-EVIDENCE-FOR only, never makes-you-compliant. */
export interface ControlMappingEntry {
  framework: string
  controlId: string
  controlName: string
  /** SUPPORTS-EVIDENCE-FOR statement. Verb is always 'supports evidence for'. */
  supportsEvidenceFor: string
  /** Which bundle sections back this control. */
  backedBy: string[]
  /** Explicit limits on the evidence, in the line-1799 / line-2363 voice. */
  evidenceLimits: string
}

/** Human-readable summary, mirrors the audit-export PDF precedent. */
export interface BundleSummary {
  bundleType: BundleType
  tenantId: string
  period: { from: string; to: string }
  recordCount: number
  permits: number
  denials: number
  revocationsObserved: number
  narrative: string[]
}

/**
 * The signed bundle manifest. The whole object below `signature` is what the
 * gateway identity signs, after SDK-canonicalization. A verifier recomputes
 * the canonical form, checks the JWS against the JWKS, then recomputes leaf
 * hashes and the Merkle root to confirm the embedded records are intact.
 */
export interface BundleManifest {
  schemaVersion: typeof AUDIT_BUNDLE_SCHEMA_VERSION
  bundleId: string
  bundleType: BundleType
  tenantId: string
  /** Free-form selector this bundle was built for (receiptId, agentId, etc). */
  subject: Record<string, unknown>
  generatedAt: string
  period: { from: string; to: string }
  /** Machine-readable record set (reuses the audit-export AuditRecord shape). */
  records: unknown[]
  hashManifest: BundleHashManifest
  /** Per-record receipt chain references (receipt hashes + seal linkage). */
  receiptChain: Array<Record<string, unknown>>
  /** Distinct policy_hash values in scope (the 'policy versions'). */
  policyVersions: string[]
  /** Approval / decision evidence (reuses enforce decisionRecord shape). */
  approvalEvidence: Array<Record<string, unknown>>
  /** Revocation checks at bundle time. */
  revocationChecks: Array<Record<string, unknown>>
  /** Verifier-derived evidence-assurance descriptors. */
  evidenceAssurance: EvidenceAssuranceDescriptor[]
  /** SUPPORTS-EVIDENCE-FOR control mapping (only on per-compliance-control,
   *  optional disclosure on others). */
  controlMapping: ControlMappingEntry[]
  summary: BundleSummary
  /** Verifier instructions and evidence-limits disclaimer. */
  verification: {
    jwksUrl: string
    kid: string
    instructions: string[]
    evidenceLimits: string
  }
}

/** The signed envelope handed to the customer. */
export interface SignedBundle {
  manifest: BundleManifest
  /** Canonical hash of the manifest (hex), the value that was signed over. */
  manifestHash: string
  /** JWS compact (EdDSA) over the canonical manifest, from the gateway identity. */
  signature: string
  kid: string
}
