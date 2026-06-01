// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Build G-D2: signed audit evidence bundles.
// Covers: manifest hash + Merkle integrity, signature verify against the
// gateway public key, redaction preserves the signed commitment, and the
// compliance control mapping passes the claims check.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity, getGatewayIdentity } from '../../src/gateway/identity.js'
import {
  assembleBundle,
  redactBundle,
  signManifest,
  type BundleExcerpt,
} from '../../src/gateway/audit-bundles/assembler.js'
import { verifyBundle } from '../../src/gateway/audit-bundles/verify.js'
import {
  buildControlMapping,
  assertControlMappingClaimsSafe,
  findForbiddenClaims,
  listControlFrameworks,
  BUNDLE_EVIDENCE_LIMITS,
} from '../../src/gateway/audit-bundles/control-mapping.js'
import { deriveEvidenceAssurance, evidenceAssuranceAuthoritative } from '../../src/gateway/audit-bundles/evidence-assurance.js'
import { sdkLeafMerkle, gemBatchBackboneAvailable, verifyLeafInclusion } from '../../src/gateway/audit-bundles/merkle-backbone.js'

const TENANT = 'tenant-d2'
const AGENT = 'agent-d2-001'
const POLICY_HASH = 'policyhash_v1_abc'
let dbPath: string

function seed(): { receiptId: number; evalId: string } {
  const db = getDB()
  db.prepare(
    `INSERT INTO tenants (id, name, email, plan, status) VALUES (?, ?, ?, 'free', 'active')`,
  ).run(TENANT, 'D2 Tenant', `d2-${randomUUID()}@example.com`)

  db.prepare(
    `INSERT INTO agents (id, tenant_id, agent_id, public_key, did, status)
     VALUES (?, ?, ?, ?, ?, 'active')`,
  ).run(randomUUID(), TENANT, AGENT, 'pk-hex', `did:key:z6Mk${AGENT}`)

  const rootAgent = 'agent-d2-root'
  db.prepare(
    `INSERT INTO agents (id, tenant_id, agent_id, public_key, status)
     VALUES (?, ?, ?, ?, 'active')`,
  ).run(randomUUID(), TENANT, rootAgent, 'pk-hex-root')

  const delId = randomUUID()
  db.prepare(
    `INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status)
     VALUES (?, ?, ?, ?, ?, 'active')`,
  ).run(delId, TENANT, rootAgent, AGENT, 'read:files')

  const evalId = randomUUID()
  db.prepare(
    `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, duration_ms, created_at)
     VALUES (?, ?, ?, 'tool_call', 'fs', 'read:files', 'permit', 11, '2026-04-01T10:00:00Z')`,
  ).run(evalId, TENANT, AGENT)

  const r = db.prepare(
    `INSERT INTO evaluation_receipts
       (tenant_id, agent_id, evaluation_id, event_type, action_type, scope_requested_json,
        verdict, reason_code, delegation_id, policy_hash, receipt_hash, gateway_signature, created_at)
     VALUES (?, ?, ?, 'authorization_permit', 'tool_call', '["read:files"]',
             'permit', NULL, ?, ?, 'receipthash_abc', 'jws.sig.here', '2026-04-01T10:00:00Z')`,
  ).run(TENANT, AGENT, evalId, delId, POLICY_HASH)

  // A second, denied evaluation under a different policy hash.
  const evalId2 = randomUUID()
  db.prepare(
    `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, duration_ms, created_at)
     VALUES (?, ?, ?, 'delegation_create', 'agent', 'admin:*', 'deny', 4, '2026-04-01T11:00:00Z')`,
  ).run(evalId2, TENANT, AGENT)
  db.prepare(
    `INSERT INTO evaluation_receipts
       (tenant_id, agent_id, evaluation_id, event_type, action_type, scope_requested_json,
        verdict, reason_code, delegation_id, policy_hash, receipt_hash, gateway_signature, created_at)
     VALUES (?, ?, ?, 'authorization_deny', 'delegation_create', '["admin:*"]',
             'deny', 'scope_exceeded', ?, 'policyhash_v2_def', 'receipthash_def', 'jws.sig.two', '2026-04-01T11:00:00Z')`,
  ).run(TENANT, AGENT, evalId2, delId)

  return { receiptId: Number(r.lastInsertRowid), evalId }
}

before(() => {
  dbPath = join(tmpdir(), `aeoess-d2-bundles-test-${randomUUID()}.db`)
  initDB(dbPath)
  initGatewayIdentity()
  seed()
})

after(() => {
  try { getDB().close() } catch {}
  try {
    const fs = require('node:fs')
    fs.unlinkSync(dbPath)
    fs.unlinkSync(dbPath + '-wal')
    fs.unlinkSync(dbPath + '-shm')
  } catch {}
})

// ── manifest hash + signature verification ───────────────────────────

describe('bundle manifest hash + signature', () => {
  it('assembles a per-agent bundle with records and a hash-manifest', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    assert.equal(signed.manifest.bundleType, 'per-agent')
    assert.equal(signed.manifest.schemaVersion, 'audit_bundle_v1')
    assert.ok(signed.manifest.records.length >= 2, 'should include seeded records')
    assert.ok(signed.manifest.hashManifest.leaves.length > 0, 'leaves present')
    assert.ok(signed.manifest.hashManifest.merkleRoot, 'merkle root present')
    assert.ok(signed.manifestHash.length === 64, 'manifest hash is sha-256 hex')
  })

  it('manifest hash recomputes and Merkle root verifies', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const result = verifyBundle(signed)
    assert.equal(result.manifestHashMatches, true, 'manifest hash must recompute')
    assert.equal(result.merkleRootMatches, true, 'Merkle root must recompute from leaves')
  })

  it('signature verifies against the gateway public key', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const pubHex = getGatewayIdentity().publicKeyHex
    const result = verifyBundle(signed, pubHex)
    assert.equal(result.signatureValid, true, 'EdDSA JWS must verify against the JWKS key')
    assert.equal(result.ok, true)
  })

  it('signature fails against a wrong public key', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const wrongHex = '00'.repeat(32)
    const result = verifyBundle(signed, wrongHex)
    assert.equal(result.signatureValid, false)
    assert.equal(result.ok, false)
  })

  it('tampering with a record breaks the manifest hash', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    // Mutate an embedded record after signing.
    ;(signed.manifest.records[0] as any).scope = 'admin:everything'
    const result = verifyBundle(signed, getGatewayIdentity().publicKeyHex)
    assert.equal(result.manifestHashMatches, false, 'mutation must invalidate the manifest hash')
    assert.equal(result.ok, false)
  })

  it('tampering with a leaf breaks the Merkle root', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    signed.manifest.hashManifest.leaves[0].leafHash = 'ff'.repeat(32)
    const result = verifyBundle(signed)
    assert.equal(result.merkleRootMatches, false)
  })
})

// ── redaction preserved ──────────────────────────────────────────────

describe('bundle redaction preserves the signed commitment', () => {
  it('redacted excerpt keeps the manifest hash, root, and signature', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const excerpt: BundleExcerpt = redactBundle(signed)
    assert.equal(excerpt.manifestHash, signed.manifestHash, 'manifest hash preserved')
    assert.equal(excerpt.merkleRoot, signed.manifest.hashManifest.merkleRoot, 'root preserved')
    assert.equal(excerpt.signature, signed.signature, 'signature preserved')
    assert.equal(excerpt.kid, signed.kid)
    assert.equal(excerpt.redacted, true)
  })

  it('redacted excerpt drops the record bodies but keeps counts', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const excerpt = redactBundle(signed) as any
    assert.equal(excerpt.records, undefined, 'record bodies must not be present')
    assert.equal(excerpt.receiptChain, undefined, 'receipt chain must not be present')
    assert.equal(excerpt.recordCount, signed.manifest.records.length, 'count preserved')
  })

  it('the original signed bundle still verifies after redaction was produced', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    redactBundle(signed)
    const result = verifyBundle(signed, getGatewayIdentity().publicKeyHex)
    assert.equal(result.ok, true, 'redaction must not mutate the signed bundle')
  })

  it('redacted excerpt JSON does not leak agent DIDs or scopes', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const json = JSON.stringify(redactBundle(signed))
    assert.ok(!json.includes('did:key'), 'no agent DID in excerpt')
    assert.ok(!json.includes('read:files'), 'no scope strings in excerpt')
  })
})

// ── compliance control mapping language ──────────────────────────────

describe('control mapping claims discipline', () => {
  it('the full catalog passes the claims check', () => {
    const entries = buildControlMapping()
    assert.doesNotThrow(() => assertControlMappingClaimsSafe(entries))
  })

  it('every entry uses supports-evidence-for language', () => {
    for (const e of buildControlMapping()) {
      assert.match(e.supportsEvidenceFor, /supports? evidence for/i, `${e.controlId} must use supports-evidence-for`)
    }
  })

  it('no entry contains forbidden compliance claims or em dashes', () => {
    for (const e of buildControlMapping()) {
      const text = `${e.controlName} ${e.supportsEvidenceFor} ${e.evidenceLimits}`
      assert.deepEqual(findForbiddenClaims(text), [], `${e.controlId} copy must be claims-safe`)
    }
  })

  it('EU AI Act entries use increasingly-required phrasing', () => {
    const euae = buildControlMapping({ framework: 'EU AI Act' })
    assert.ok(euae.length > 0)
    for (const e of euae) {
      assert.match(e.supportsEvidenceFor, /increasingly require/i, `${e.controlId} must say increasingly required`)
    }
  })

  it('the shared evidence-limits string is claims-safe', () => {
    assert.deepEqual(findForbiddenClaims(BUNDLE_EVIDENCE_LIMITS), [])
  })

  it('the claims guard catches a forbidden phrase', () => {
    assert.ok(findForbiddenClaims('this makes you compliant').includes('makes you compliant'))
    assert.ok(findForbiddenClaims('instant revocation included').includes('instant revocation'))
    assert.ok(findForbiddenClaims('integrity is guaranteed').includes('guaranteed'))
    assert.ok(findForbiddenClaims('a \u2014 b').includes('em-dash'))
  })

  it('lists frameworks for discovery', () => {
    const fw = listControlFrameworks()
    assert.ok(fw.includes('EU AI Act'))
    assert.ok(fw.includes('GDPR'))
    assert.ok(fw.includes('SOC 2'))
  })
})

// ── bundle types ─────────────────────────────────────────────────────

describe('bundle types', () => {
  it('per-action bundle narrows to one receipt', () => {
    // Use a receipt already seeded in before(), do not re-seed (PK collision).
    const row = getDB()
      .prepare(`SELECT id FROM evaluation_receipts WHERE tenant_id = ? ORDER BY id LIMIT 1`)
      .get(TENANT) as { id: number }
    const receiptId = row.id
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-action', receiptId })
    assert.equal(signed.manifest.bundleType, 'per-action')
    assert.equal(signed.manifest.subject.receiptId, receiptId)
    assert.equal(signed.manifest.records.length, 1, 'per-action narrows to a single record')
  })

  it('per-policy bundle narrows to one policy hash', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-policy', policyHash: POLICY_HASH })
    assert.equal(signed.manifest.bundleType, 'per-policy')
    for (const v of signed.manifest.policyVersions) {
      // Only the requested policy hash should remain in scope.
      assert.equal(v, POLICY_HASH)
    }
  })

  it('per-compliance-control bundle carries a focused control mapping', () => {
    const signed = assembleBundle({
      tenantId: TENANT,
      bundleType: 'per-compliance-control',
      framework: 'GDPR',
    })
    assert.ok(signed.manifest.controlMapping.length > 0)
    for (const e of signed.manifest.controlMapping) {
      assert.equal(e.framework, 'GDPR')
    }
  })

  it('per-incident bundle uses the window and includes a summary', () => {
    const signed = assembleBundle({
      tenantId: TENANT,
      bundleType: 'per-incident',
      incidentId: 'INC-1',
      from: '2026-04-01T00:00:00Z',
      to: '2026-04-02T00:00:00Z',
    })
    assert.equal(signed.manifest.subject.incidentId, 'INC-1')
    assert.ok(signed.manifest.summary.narrative.length > 0)
  })
})

// ── revocation checks + evidence assurance + W2 stub markers ─────────

describe('revocation checks and verifier-derived assurance', () => {
  it('revocation checks reflect active agents as not revoked', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const agentCheck = signed.manifest.revocationChecks.find((c: any) => c.target_type === 'agent')
    assert.ok(agentCheck, 'agent revocation check present')
    assert.equal((agentCheck as any).revoked, false)
  })

  it('revocation check reflects a revoked agent', () => {
    const db = getDB()
    const revAgent = 'agent-d2-revoked'
    db.prepare(
      `INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, 'pk', 'revoked')`,
    ).run(randomUUID(), TENANT, revAgent)
    const evalId = randomUUID()
    db.prepare(
      `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, created_at)
       VALUES (?, ?, ?, 'tool_call', 'fs', 'read:x', 'permit', '2026-04-03T10:00:00Z')`,
    ).run(evalId, TENANT, revAgent)
    db.prepare(
      `INSERT INTO evaluation_receipts (tenant_id, agent_id, evaluation_id, event_type, verdict, policy_hash, receipt_hash, gateway_signature, created_at)
       VALUES (?, ?, ?, 'authorization_permit', 'permit', 'ph', 'rh', 'sig', '2026-04-03T10:00:00Z')`,
    ).run(TENANT, revAgent, evalId)
    db.prepare(
      `INSERT INTO revocations (id, tenant_id, target_type, target_id, revoked_by) VALUES (?, ?, 'agent', ?, 'owner')`,
    ).run(randomUUID(), TENANT, revAgent)

    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: revAgent })
    const check = signed.manifest.revocationChecks.find((c: any) => c.target_id === revAgent) as any
    assert.ok(check)
    assert.equal(check.revoked, true)
    assert.equal(check.explicit_revocation, true)
  })

  it('evidence assurance is verifier-derived and provisional (W2 stub)', () => {
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    assert.ok(signed.manifest.evidenceAssurance.length > 0)
    for (const d of signed.manifest.evidenceAssurance) {
      assert.equal(d.derivation, 'verifier_derived', 'assurance must be verifier-derived, never issuer-set')
      assert.equal(d.authoritative, false, 'provisional until SDK Wave 2 descriptor lands')
    }
    assert.equal(evidenceAssuranceAuthoritative(), false)
  })

  it('deriveEvidenceAssurance maps a signed receipt to infrastructure level', () => {
    const d = deriveEvidenceAssurance({
      evidenceRef: 'e1',
      evidenceType: 'receipt',
      method: 'did:key',
      hasIssuerSignature: true,
      hasPrincipalBinding: true,
      validAt: new Date().toISOString(),
    })
    assert.equal(d.level, 'principal_bound')
    assert.equal(d.fresh, true)
  })

  it('the G-A1 batch backbone is not available off-base; SDK leaf Merkle is used', () => {
    assert.equal(gemBatchBackboneAvailable(), false)
    const signed = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    assert.ok(['sdk_leaf_merkle', 'receipt_window_seal'].includes(signed.manifest.hashManifest.rootSource))
  })
})

// ── SDK Merkle backbone is reused, not reinvented ────────────────────

describe('SDK Merkle backbone', () => {
  it('SDK leaf Merkle produces verifiable inclusion proofs', () => {
    const leaves = [
      { kind: 'audit_record' as const, sourceRef: 'a', leafHash: 'aa'.repeat(32) },
      { kind: 'audit_record' as const, sourceRef: 'b', leafHash: 'bb'.repeat(32) },
      { kind: 'audit_record' as const, sourceRef: 'c', leafHash: 'cc'.repeat(32) },
    ]
    const { merkleRoot, inclusionProofs } = sdkLeafMerkle(leaves)
    assert.ok(merkleRoot)
    const proof = inclusionProofs['aa'.repeat(32)]
    assert.ok(proof, 'inclusion proof exists for the leaf')
    assert.equal(verifyLeafInclusion(proof), true, 'SDK verifier confirms the proof')
  })

  it('signManifest is stable: same manifest produces the same hash', () => {
    const signed1 = assembleBundle({ tenantId: TENANT, bundleType: 'per-agent', agentId: AGENT })
    const reSigned = signManifest(signed1.manifest)
    assert.equal(reSigned.manifestHash, signed1.manifestHash, 'canonical hash is deterministic')
  })
})
