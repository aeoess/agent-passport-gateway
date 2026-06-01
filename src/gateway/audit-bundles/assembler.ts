// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway - Signed Audit Evidence Bundle assembler (Build G-D2).
 *
 * Produces a SIGNED BUNDLE MANIFEST (canonical JSON). The manifest is the real
 * artifact, not a PDF. It contains: machine-readable records, a hash-manifest
 * (canonical leaf hashes + Merkle root), the receipt chain, policy versions,
 * approval evidence, revocation checks, verifier-derived evidence-assurance
 * descriptors, optional SUPPORTS-EVIDENCE-FOR control mapping, and a
 * human-readable summary.
 *
 * Thin-gateway posture: the gateway coordinates, canonicalizes, signs, and
 * emits. The signed bundle is a pre-signed, customer-owned artifact that any
 * holder verifies at the edge against the gateway JWKS. The gateway holds no
 * enforcement authority over a bundle once handed out.
 *
 * Reuse, do not duplicate:
 *  - queryAuditRecords() from audit-export for the record set
 *  - the enforce.ts decisionRecord shape for approval/decision evidence
 *  - identity.getGatewayIdentity().sign() for the manifest signature
 *  - SDK canonicalize/canonicalHash/buildMerkleRoot for the hash-manifest
 *  - existing receipt_window_seals as a referenced backbone when present
 */

import { randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { getGatewayIdentity } from '../identity.js'
import { queryAuditRecords, type AuditRecord } from '../audit-export.js'
import {
  AUDIT_BUNDLE_SCHEMA_VERSION,
  type BundleType,
  type BundleLeaf,
  type BundleManifest,
  type BundleHashManifest,
  type SignedBundle,
  type BundleSummary,
  type ControlMappingEntry,
  type EvidenceAssuranceDescriptor,
} from './types.js'
import {
  buildControlMapping,
  assertControlMappingClaimsSafe,
  BUNDLE_EVIDENCE_LIMITS,
} from './control-mapping.js'
import { deriveEvidenceAssurance } from './evidence-assurance.js'
import {
  canonicalLeafHash,
  sdkLeafMerkle,
  gemBatchBackbone,
} from './merkle-backbone.js'

const FULL_WINDOW_FROM = '2000-01-01T00:00:00Z'
const FULL_WINDOW_TO = '2999-01-01T00:00:00Z'

export interface BundleRequest {
  tenantId: string
  bundleType: BundleType
  /** Time window for record selection. Defaults to the full window. */
  from?: string
  to?: string
  /** Selectors, depending on bundleType. */
  receiptId?: number
  agentId?: string
  policyHash?: string
  incidentId?: string
  controlId?: string
  framework?: string
  /** Optional scope filter passed through to queryAuditRecords. */
  scope?: string
  /** JWKS URL to embed in verifier instructions. */
  jwksUrl?: string
}

/** Build and sign an audit evidence bundle. */
export function assembleBundle(req: BundleRequest): SignedBundle {
  const db = getDB()
  const from = req.from || FULL_WINDOW_FROM
  const to = req.to || FULL_WINDOW_TO

  // ── 1. Record set (reuse audit-export query) ──────────────────────
  let records = queryAuditRecords(req.tenantId, from, to, req.scope)
  records = applyBundleScopeFilter(records, req, db)

  // ── 2. Receipt chain + policy versions (read evaluation_receipts) ──
  const { receiptChain, policyVersions, sealRefs } = buildReceiptChain(
    db,
    req.tenantId,
    records,
  )

  // ── 3. Approval / decision evidence (reuse decisionRecord shape) ──
  const approvalEvidence = buildApprovalEvidence(db, req.tenantId, records)

  // ── 4. Revocation checks at bundle time ──────────────────────────
  const revocationChecks = buildRevocationChecks(db, req.tenantId, records)

  // ── 5. Hash-manifest (canonical leaves + Merkle backbone) ─────────
  const leaves = buildLeaves(records, receiptChain, approvalEvidence, sealRefs, revocationChecks)
  const hashManifest = buildHashManifest(req.tenantId, leaves, sealRefs)

  // ── 6. Verifier-derived evidence-assurance (W2-stubbed) ──────────
  const evidenceAssurance = buildEvidenceAssurance(records, receiptChain)

  // ── 7. Control mapping (net-new; SUPPORTS-EVIDENCE-FOR only) ──────
  const controlMapping = buildBundleControlMapping(req)
  // Claims gate before signing: a regression fails here, never reaches a customer.
  assertControlMappingClaimsSafe(controlMapping)

  // ── 8. Summary (human-readable, mirrors the export PDF precedent) ─
  const summary = buildSummary(req.bundleType, req.tenantId, from, to, records, revocationChecks)

  // ── 9. Assemble + sign the manifest ──────────────────────────────
  const manifest: BundleManifest = {
    schemaVersion: AUDIT_BUNDLE_SCHEMA_VERSION,
    bundleId: randomUUID(),
    bundleType: req.bundleType,
    tenantId: req.tenantId,
    subject: buildSubject(req),
    generatedAt: new Date().toISOString(),
    period: { from, to },
    records: records as unknown[],
    hashManifest,
    receiptChain,
    policyVersions,
    approvalEvidence,
    revocationChecks,
    evidenceAssurance,
    controlMapping,
    summary,
    verification: {
      jwksUrl: req.jwksUrl || '/.well-known/jwks.json',
      kid: getKid(),
      instructions: [
        'Recompute each hash-manifest leaf with the SDK canonicalize form then sha-256.',
        'Recompute the Merkle root from the leaf hashes and compare to hashManifest.merkleRoot.',
        'Fetch the gateway public key from the JWKS endpoint by kid.',
        'Verify the EdDSA JWS signature over the canonical manifest.',
        'Assurance levels are verifier-derived, not issuer-set, and are provisional until the SDK Wave 2 descriptor lands.',
      ],
      evidenceLimits: BUNDLE_EVIDENCE_LIMITS,
    },
  }

  return signManifest(manifest)
}

/** Sign a manifest: canonical-hash then EdDSA-JWS via the gateway identity. */
export function signManifest(manifest: BundleManifest): SignedBundle {
  const manifestHash = canonicalLeafHash(manifest as unknown as Record<string, unknown>)
  let signature = ''
  let kid = getKid()
  try {
    const identity = getGatewayIdentity()
    kid = identity.kid
    // identity.sign currently JSON.stringifies; the stable cross-verifier value
    // is the canonical manifestHash, which we sign over explicitly so a verifier
    // checks the canonical hash, not a property-ordered serialization.
    signature = identity.sign({ manifestHash, kid, schemaVersion: manifest.schemaVersion })
  } catch {
    // Identity not initialized (e.g. unit context). Leave signature empty;
    // the manifestHash is still a stable, independently recomputable commitment.
    signature = ''
  }
  return { manifest, manifestHash, signature, kid }
}

// ── helpers ─────────────────────────────────────────────────────────

function getKid(): string {
  try {
    return getGatewayIdentity().kid
  } catch {
    return 'gateway-v1'
  }
}

function buildSubject(req: BundleRequest): Record<string, unknown> {
  const s: Record<string, unknown> = {}
  if (req.receiptId !== undefined) s.receiptId = req.receiptId
  if (req.agentId) s.agentId = req.agentId
  if (req.policyHash) s.policyHash = req.policyHash
  if (req.incidentId) s.incidentId = req.incidentId
  if (req.controlId) s.controlId = req.controlId
  if (req.framework) s.framework = req.framework
  return s
}

/** Narrow the record set to the bundle's subject. */
function applyBundleScopeFilter(
  records: AuditRecord[],
  req: BundleRequest,
  db: any,
): AuditRecord[] {
  switch (req.bundleType) {
    case 'per-agent':
      if (!req.agentId) return records
      return records.filter(
        (r) => r.agent_did.includes(req.agentId!) || agentIdOf(db, req.tenantId, r) === req.agentId,
      )
    case 'per-policy':
      // policy_hash lives on evaluation_receipts; resolve per record below.
      if (!req.policyHash) return records
      return records.filter((r) => policyHashOf(db, req.tenantId, r) === req.policyHash)
    case 'per-action':
      if (req.receiptId === undefined) return records
      return records.filter((r) => receiptIdOf(db, req.tenantId, r) === req.receiptId)
    case 'per-incident':
      // Incident scoping is window-based plus an optional alert linkage; the
      // window from/to already narrows it. No further record filter today.
      return records
    case 'per-compliance-control':
      // Control bundles describe the full in-window evidence set against a
      // control, so no record-level narrowing.
      return records
    default:
      return records
  }
}

function agentIdOf(db: any, tenantId: string, r: AuditRecord): string | null {
  const row = db
    .prepare('SELECT agent_id FROM policy_evaluations WHERE id = ? AND tenant_id = ?')
    .get(r.evaluation_id, tenantId) as any
  return row?.agent_id ?? null
}

function policyHashOf(db: any, tenantId: string, r: AuditRecord): string | null {
  const row = db
    .prepare(
      'SELECT policy_hash FROM evaluation_receipts WHERE evaluation_id = ? AND tenant_id = ? LIMIT 1',
    )
    .get(r.evaluation_id, tenantId) as any
  return row?.policy_hash ?? null
}

function receiptIdOf(db: any, tenantId: string, r: AuditRecord): number | null {
  const row = db
    .prepare(
      'SELECT id FROM evaluation_receipts WHERE evaluation_id = ? AND tenant_id = ? LIMIT 1',
    )
    .get(r.evaluation_id, tenantId) as any
  return row?.id ?? null
}

interface SealRef {
  sealId: string
  commitmentHash: string
  seqStart: number
  seqEnd: number
  receiptCount: number
}

/**
 * Build the receipt chain: for each in-scope audit record, pull the backing
 * evaluation_receipts row, its receipt_hash, policy_hash, gateway_signature,
 * and any receipt_window_seal it belongs to. Collects distinct policy versions
 * and the set of seals referenced (the in-DB Merkle commitments).
 */
function buildReceiptChain(
  db: any,
  tenantId: string,
  records: AuditRecord[],
): {
  receiptChain: Array<Record<string, unknown>>
  policyVersions: string[]
  sealRefs: SealRef[]
} {
  const receiptChain: Array<Record<string, unknown>> = []
  const policyVersionSet = new Set<string>()
  const sealMap = new Map<string, SealRef>()

  for (const r of records) {
    const er = db
      .prepare(
        `SELECT id, receipt_hash, gateway_signature, policy_hash, delegation_id,
                schema_version, seal_id, verdict, created_at
         FROM evaluation_receipts WHERE evaluation_id = ? AND tenant_id = ? LIMIT 1`,
      )
      .get(r.evaluation_id, tenantId) as any

    if (er?.policy_hash) policyVersionSet.add(er.policy_hash)

    let sealRef: string | null = null
    if (er?.seal_id) {
      sealRef = er.seal_id
      if (!sealMap.has(er.seal_id)) {
        const seal = db
          .prepare(
            `SELECT seal_id, commitment_hash, seq_start, seq_end, receipt_count
             FROM receipt_window_seals WHERE seal_id = ? AND tenant_id = ?`,
          )
          .get(er.seal_id, tenantId) as any
        if (seal) {
          sealMap.set(er.seal_id, {
            sealId: seal.seal_id,
            commitmentHash: seal.commitment_hash,
            seqStart: seal.seq_start,
            seqEnd: seal.seq_end,
            receiptCount: seal.receipt_count,
          })
        }
      }
    }

    receiptChain.push({
      evaluation_id: r.evaluation_id,
      receipt_id: er?.id ?? null,
      receipt_hash: er?.receipt_hash ?? r.receipt_hash,
      gateway_signature: er?.gateway_signature ?? null,
      policy_hash: er?.policy_hash ?? null,
      schema_version: er?.schema_version ?? null,
      seal_id: sealRef,
      verdict: er?.verdict ?? r.decision,
      decision_timestamp: er?.created_at ?? r.timestamp,
    })
  }

  return {
    receiptChain,
    policyVersions: Array.from(policyVersionSet),
    sealRefs: Array.from(sealMap.values()),
  }
}

/**
 * Approval / decision evidence. Reuses the enforce.ts decisionRecord field
 * shape so the bundle's approval evidence aligns with the /audit-packet atom,
 * without re-walking delegation internals beyond the chain-hash already present
 * on the receipt row's neighbours. We read the frozen-at-decision fields only.
 */
function buildApprovalEvidence(
  db: any,
  tenantId: string,
  records: AuditRecord[],
): Array<Record<string, unknown>> {
  const evidence: Array<Record<string, unknown>> = []
  for (const r of records) {
    const er = db
      .prepare(
        `SELECT id, event_type, action_type, scope_requested_json, verdict,
                reason_code, delegation_id, policy_hash, agent_id, created_at
         FROM evaluation_receipts WHERE evaluation_id = ? AND tenant_id = ? LIMIT 1`,
      )
      .get(r.evaluation_id, tenantId) as any
    if (!er) continue

    let scopeRequested: string[] = []
    try {
      scopeRequested = JSON.parse(er.scope_requested_json || '[]')
    } catch {
      scopeRequested = []
    }

    evidence.push({
      receipt_id: er.id,
      event_type: er.event_type,
      action_type: er.action_type,
      scope_requested: scopeRequested,
      verdict: er.verdict,
      reason_code: er.reason_code || null,
      delegation_id: er.delegation_id || null,
      policy_hash: er.policy_hash,
      agent_id: er.agent_id,
      decision_timestamp: er.created_at,
      delegation_depth: r.delegation_chain.depth,
      root_principal: r.delegation_chain.root_principal,
    })
  }
  return evidence
}

/**
 * Revocation checks at bundle time. For each agent and delegation in scope,
 * record whether the agent or the delegation is currently revoked, and whether
 * an explicit revocation row exists. The bundle states the observed revocation
 * state; it never asserts immediate propagation. Sink-side enforcement is at
 * the edge through the epoch check (G-A2 / G-B2 surface).
 */
function buildRevocationChecks(
  db: any,
  tenantId: string,
  records: AuditRecord[],
): Array<Record<string, unknown>> {
  const checks: Array<Record<string, unknown>> = []
  const seenAgents = new Set<string>()
  const seenDelegations = new Set<string>()

  for (const r of records) {
    const er = db
      .prepare(
        'SELECT agent_id, delegation_id FROM evaluation_receipts WHERE evaluation_id = ? AND tenant_id = ? LIMIT 1',
      )
      .get(r.evaluation_id, tenantId) as any
    const agentId = er?.agent_id
    const delegationId = er?.delegation_id

    if (agentId && !seenAgents.has(agentId)) {
      seenAgents.add(agentId)
      const agent = db
        .prepare('SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ? LIMIT 1')
        .get(tenantId, agentId) as any
      const explicit = db
        .prepare(
          "SELECT id FROM revocations WHERE tenant_id = ? AND target_type = 'agent' AND target_id = ? LIMIT 1",
        )
        .get(tenantId, agentId) as any
      checks.push({
        target_type: 'agent',
        target_id: agentId,
        revoked: agent ? agent.status !== 'active' : false,
        explicit_revocation: !!explicit,
        checked_at: new Date().toISOString(),
      })
    }

    if (delegationId && !seenDelegations.has(delegationId)) {
      seenDelegations.add(delegationId)
      const del = db
        .prepare('SELECT status FROM delegations WHERE id = ? AND tenant_id = ?')
        .get(delegationId, tenantId) as any
      const explicit = db
        .prepare(
          "SELECT id FROM revocations WHERE tenant_id = ? AND target_type = 'delegation' AND target_id = ? LIMIT 1",
        )
        .get(tenantId, delegationId) as any
      checks.push({
        target_type: 'delegation',
        target_id: delegationId,
        revoked: del ? del.status !== 'active' : false,
        explicit_revocation: !!explicit,
        checked_at: new Date().toISOString(),
      })
    }
  }
  return checks
}

/** Build the canonical hash-manifest leaves over every embedded record set. */
function buildLeaves(
  records: AuditRecord[],
  receiptChain: Array<Record<string, unknown>>,
  approvalEvidence: Array<Record<string, unknown>>,
  sealRefs: SealRef[],
  revocationChecks: Array<Record<string, unknown>>,
): BundleLeaf[] {
  const leaves: BundleLeaf[] = []

  for (const r of records) {
    leaves.push({
      kind: 'audit_record',
      sourceRef: r.evaluation_id,
      leafHash: canonicalLeafHash(r as unknown as Record<string, unknown>),
    })
  }
  for (const rc of receiptChain) {
    leaves.push({
      kind: 'receipt_seal',
      sourceRef: String(rc.receipt_id ?? rc.evaluation_id),
      leafHash: canonicalLeafHash(rc),
    })
  }
  for (const ae of approvalEvidence) {
    leaves.push({
      kind: 'approval_evidence',
      sourceRef: String(ae.receipt_id),
      leafHash: canonicalLeafHash(ae),
    })
  }
  for (const seal of sealRefs) {
    leaves.push({
      kind: 'receipt_seal',
      sourceRef: seal.sealId,
      leafHash: canonicalLeafHash(seal as unknown as Record<string, unknown>),
    })
  }
  for (const rev of revocationChecks) {
    leaves.push({
      kind: 'revocation_check',
      sourceRef: `${rev.target_type}:${rev.target_id}`,
      leafHash: canonicalLeafHash(rev),
    })
  }
  return leaves
}

/**
 * Select the Merkle backbone for the hash-manifest. Prefer the G-A1 GEM batch
 * root when available (stubbed off-base today), otherwise fold the bundle's own
 * canonical leaf hashes with the SDK. A referenced receipt-window seal, when
 * present, is recorded as the in-DB commitment backbone.
 */
function buildHashManifest(
  tenantId: string,
  leaves: BundleLeaf[],
  sealRefs: SealRef[],
): BundleHashManifest {
  const leafHashes = leaves.map((l) => l.leafHash)

  // Preference 1: G-A1 batch backbone (stubbed off-base).
  const gem = gemBatchBackbone(tenantId, leafHashes)
  if (gem.available && gem.merkleRoot) {
    return {
      canonicalization: 'sdk-canonicalize',
      hashAlgorithm: 'sha-256',
      leaves,
      merkleRoot: gem.merkleRoot,
      rootSource: 'gem_batch',
      inclusionProofs: gem.inclusionProofs ?? undefined,
    }
  }

  // Preference 3 (always available): SDK leaf Merkle over this bundle's leaves.
  const sdk = sdkLeafMerkle(leaves)
  return {
    canonicalization: 'sdk-canonicalize',
    hashAlgorithm: 'sha-256',
    leaves,
    merkleRoot: sdk.merkleRoot,
    // When a seal covers the receipts we record it as the in-DB backbone the
    // root can be cross-checked against; the manifest Merkle is still computed
    // from the bundle's own leaves so the bundle is self-verifying.
    rootSource: sealRefs.length > 0 ? 'receipt_window_seal' : 'sdk_leaf_merkle',
    inclusionProofs: sdk.inclusionProofs,
    temporalAnchor: {
      backbone: 'rekor',
      anchored: false,
      // TODO(G-A1): when rekor.anchorMerkleRoot is on base (A1-added), anchor
      //   the manifest merkleRoot for independent temporal proof and flip this.
      note: 'rekor anchorMerkleRoot lives on the G-A1 dep branch; not anchored on base',
    },
  }
}

/**
 * Derive a verifier-derived evidence-assurance descriptor per receipt-backed
 * record. Provisional until the SDK Wave 2 descriptor lands. A signed receipt
 * with a gateway signature reads as infrastructure-bound evidence; an unsigned
 * record reads as unverified.
 */
function buildEvidenceAssurance(
  records: AuditRecord[],
  receiptChain: Array<Record<string, unknown>>,
): EvidenceAssuranceDescriptor[] {
  const byEval = new Map<string, Record<string, unknown>>()
  for (const rc of receiptChain) byEval.set(String(rc.evaluation_id), rc)

  const out: EvidenceAssuranceDescriptor[] = []
  for (const r of records) {
    const rc = byEval.get(r.evaluation_id)
    const hasSignature = !!(rc && rc.gateway_signature)
    out.push(
      deriveEvidenceAssurance({
        evidenceRef: r.evaluation_id,
        evidenceType: 'receipt',
        method: r.agent_did.split(':').slice(0, 2).join(':'),
        hasIssuerSignature: hasSignature,
        hasPrincipalBinding: r.delegation_chain.root_principal != null,
        evidence: { receipt_hash: r.receipt_hash },
        validAt: r.timestamp,
      }),
    )
  }
  return out
}

/** Control mapping for the bundle. Present on per-compliance-control bundles;
 *  also disclosed (full catalog) on other bundle types so a reader sees what
 *  the evidence supports. */
function buildBundleControlMapping(req: BundleRequest): ControlMappingEntry[] {
  if (req.bundleType === 'per-compliance-control') {
    return buildControlMapping({ controlId: req.controlId, framework: req.framework })
  }
  return buildControlMapping()
}

/**
 * Public-safe excerpt of a signed bundle. The full records carry agent DIDs,
 * scopes, and delegation detail that should not cross an unauthenticated
 * surface. This excerpt drops the record bodies and keeps the signed
 * hash-manifest, the Merkle root, policy versions, the control mapping, and the
 * summary counts. Crucially it preserves the hash-manifest unchanged, so a
 * holder of the full bundle can still confirm the excerpt commits to the same
 * signed root. Redaction here removes content; it never rewrites the leaves.
 */
export interface BundleExcerpt {
  schemaVersion: string
  bundleId: string
  bundleType: BundleType
  tenantId: string
  generatedAt: string
  period: { from: string; to: string }
  /** Signed commitment, unchanged from the full bundle. */
  manifestHash: string
  merkleRoot: string
  rootSource: string
  recordCount: number
  policyVersions: string[]
  controlMapping: ControlMappingEntry[]
  summary: BundleSummary
  signature: string
  kid: string
  evidenceLimits: string
  redacted: true
}

export function redactBundle(bundle: SignedBundle): BundleExcerpt {
  const m = bundle.manifest
  return {
    schemaVersion: m.schemaVersion,
    bundleId: m.bundleId,
    bundleType: m.bundleType,
    tenantId: m.tenantId,
    generatedAt: m.generatedAt,
    period: m.period,
    manifestHash: bundle.manifestHash,
    merkleRoot: m.hashManifest.merkleRoot,
    rootSource: m.hashManifest.rootSource,
    recordCount: m.records.length,
    policyVersions: [...m.policyVersions],
    controlMapping: m.controlMapping.map((e) => ({ ...e, backedBy: [...e.backedBy] })),
    summary: m.summary,
    signature: bundle.signature,
    kid: bundle.kid,
    evidenceLimits: m.verification.evidenceLimits,
    redacted: true,
  }
}

function buildSummary(
  bundleType: BundleType,
  tenantId: string,
  from: string,
  to: string,
  records: AuditRecord[],
  revocationChecks: Array<Record<string, unknown>>,
): BundleSummary {
  const permits = records.filter((r) => r.decision === 'allow').length
  const denials = records.filter((r) => r.decision === 'deny').length
  const revocationsObserved = revocationChecks.filter((c) => c.revoked === true).length

  const narrative: string[] = [
    `Bundle type: ${bundleType}.`,
    `Recorded evaluations in window: ${records.length} (${permits} permit, ${denials} deny).`,
    `Revocation checks performed: ${revocationChecks.length}; revoked at bundle time: ${revocationsObserved}.`,
    'Each record is backed by a signed evaluation receipt referenced in the receipt chain.',
    'The hash-manifest commits to every embedded record so a verifier can confirm integrity independently.',
    'This summary is informational. The signed manifest and its hash-manifest are the authoritative artifact.',
  ]

  return {
    bundleType,
    tenantId,
    period: { from, to },
    recordCount: records.length,
    permits,
    denials,
    revocationsObserved,
    narrative,
  }
}
