// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-D4 - air-gapped offline export bundle. Confirms:
//   - the bundle builds and verifies entirely OFFLINE (no network);
//   - records carry receipt HASHES only, never PHI / raw payloads;
//   - the bundle carries the JWKS so a bring-your-own-root / offline verifier
//     can check the gateway signature without contacting AEOESS;
//   - tampering with a record is detected by the digest seal.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import {
  buildAirGapBundle,
  verifyAirGapBundleOffline,
  bundleRecordsToJsonLines,
} from '../../src/gateway/tenant-isolation/index.js'

const TENANT = 'airgap-tenant'

function seedEvaluation(phiLikeTarget: string) {
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`)
    .run(TENANT, 'Air Gap Tenant', 'airgap@example.com')
  db.prepare(
    `INSERT OR IGNORE INTO agents (id, tenant_id, agent_id, public_key, status)
     VALUES (?, ?, ?, ?, 'active')`,
  ).run('uuid-airgap', TENANT, 'airgap-agent', 'a'.repeat(64))
  // The evaluation row stores an action_target that, in a real PHI workflow,
  // would be a pointer/identifier, never the payload. We seed a value here and
  // assert it never crosses into the bundle's exported record set.
  db.prepare(
    `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, duration_ms, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 'permit', 12, '2026-05-15T10:00:00Z')`,
  ).run('eval-airgap-1', TENANT, 'airgap-agent', 'fhir:read', phiLikeTarget, 'fhir:read')
}

before(() => {
  initDB(':memory:')
  initGatewayIdentity()
})

describe('air-gapped bundle - builds and verifies offline', () => {
  beforeEach(() => {
    getDB().prepare(`DELETE FROM policy_evaluations`).run()
    getDB().prepare(`DELETE FROM agents`).run()
    getDB().prepare(`DELETE FROM tenants`).run()
  })

  it('builds a bundle and verifies it offline (no network)', () => {
    seedEvaluation('patient-MRN-0001-RAW-PHI')
    const bundle = buildAirGapBundle({
      tenantId: TENANT,
      from: '2026-05-01T00:00:00Z',
      to: '2026-06-01T00:00:00Z',
    })
    assert.equal(bundle.tenant_id, TENANT)
    assert.equal(bundle.offline_verifiable, true)
    assert.equal(bundle.record_count, 1)
    const v = verifyAirGapBundleOffline(bundle)
    assert.equal(v.consistent, true)
  })

  it('records carry receipt HASHES, never the raw PHI-like action target', () => {
    seedEvaluation('patient-MRN-0001-RAW-PHI')
    const bundle = buildAirGapBundle({
      tenantId: TENANT,
      from: '2026-05-01T00:00:00Z',
      to: '2026-06-01T00:00:00Z',
    })
    const serialized = JSON.stringify(bundle.records)
    // The audit record exposes a receipt_hash, scope, decision - never the
    // raw action_target value we seeded.
    assert.ok(!serialized.includes('patient-MRN-0001-RAW-PHI'))
    assert.match(bundle.records[0].receipt_hash, /^[0-9a-f]{64}$/)
    assert.equal(bundle.records[0].decision, 'allow')
  })

  it('carries the JWKS so a bring-your-own-root / offline verifier can check signatures', () => {
    seedEvaluation('x')
    const bundle = buildAirGapBundle({
      tenantId: TENANT,
      from: '2026-05-01T00:00:00Z',
      to: '2026-06-01T00:00:00Z',
    })
    assert.ok(bundle.jwks)
    assert.ok(Array.isArray(bundle.jwks.keys))
    assert.ok(bundle.jwks.keys.length >= 1)
    assert.equal(bundle.jwks.keys[0].kid, 'gateway-v1')
    assert.equal(bundle.jwks.keys[0].alg, 'EdDSA')
  })

  it('detects tampering with a record via the digest seal', () => {
    seedEvaluation('x')
    const bundle = buildAirGapBundle({
      tenantId: TENANT,
      from: '2026-05-01T00:00:00Z',
      to: '2026-06-01T00:00:00Z',
    })
    // Tamper: flip the decision after sealing.
    bundle.records[0].decision = 'deny'
    const v = verifyAirGapBundleOffline(bundle)
    assert.equal(v.consistent, false)
    assert.match(v.reason, /digest mismatch/)
  })

  it('exposes records as JSON Lines via the reused audit-export formatter', () => {
    seedEvaluation('x')
    const bundle = buildAirGapBundle({
      tenantId: TENANT,
      from: '2026-05-01T00:00:00Z',
      to: '2026-06-01T00:00:00Z',
    })
    const jsonl = bundleRecordsToJsonLines(bundle)
    assert.ok(jsonl.includes('"decision":"allow"'))
  })
})
