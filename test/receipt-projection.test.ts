// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Security triage 2026-04-11 fix 2: the public receipt endpoint must
// project signed payload bodies to a whitelist of safe fields.
// Reference: CODE-AUDIT-2026-04-11.md §2.9.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  projectPublicBody,
  payloadFingerprint,
  PUBLIC_BODY_WHITELISTS,
} from '../src/gateway/receipt-projection.js'

// A realistic policy_receipt payload that contains BOTH safe fields and
// the exact unsafe fields the audit flagged (tenant_id, spend, delegation
// chain, principal IDs). Used to exercise the projection from both
// angles: the safe fields must appear in the output, the unsafe fields
// must not.
const POLICY_PAYLOAD = {
  schema_version: '1.2',
  verdict: 'permit',
  receipt_hash: 'sha256:abc123',
  action_type: 'cloud:provision',
  action_hash: 'sha256:def456',
  scope_hash: 'sha256:789abc',
  evaluation_id: 'eval_01',
  timestamp: '2026-04-11T12:00:00Z',
  duration_ms: 42,
  task_class: 'standard',
  // Fields that MUST NOT leak:
  tenant_id: 'tenant_super_secret',
  tenant_email: 'ops@acme-corp.example',
  agent_id: 'agent_alpha',
  principal_id: 'principal_bob',
  spend_amount: 42000,
  spend_currency: 'USD',
  delegation_chain: [
    { from: 'root', to: 'manager', scope: ['cloud:*'] },
    { from: 'manager', to: 'agent_alpha', scope: ['cloud:provision'] },
  ],
  internal_metadata: { notes: 'internal notes here, do not show publicly' },
}

const POLICY_ROW = {
  id: 'rcp_01',
  action_type: 'cloud:provision',
  verdict: 'permit',
  created_at: '2026-04-11T12:00:00Z',
  schema_version: '1.2',
  receipt_hash: 'sha256:abc123',
  // DB columns that should never leak:
  tenant_id: 'tenant_super_secret',
}

describe('projectPublicBody — policy_receipt (the audit case)', () => {
  it('keeps all whitelisted safe fields', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.verdict, 'permit')
    assert.equal(out.schema_version, '1.2')
    assert.equal(out.receipt_hash, 'sha256:abc123')
    assert.equal(out.action_type, 'cloud:provision')
    assert.equal(out.action_hash, 'sha256:def456')
    assert.equal(out.scope_hash, 'sha256:789abc')
    assert.equal(out.evaluation_id, 'eval_01')
    assert.equal(out.timestamp, '2026-04-11T12:00:00Z')
    assert.equal(out.duration_ms, 42)
    assert.equal(out.task_class, 'standard')
  })

  it('drops tenant_id from both the parsed payload and the row', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.tenant_id, undefined, 'tenant_id must not appear in the projection')
    // Also verify no case-variant slips through
    assert.equal((out as any).tenantId, undefined)
  })

  it('drops tenant_email (PII leak surface)', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.tenant_email, undefined)
  })

  it('drops raw agent_id and principal_id', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.agent_id, undefined)
    assert.equal(out.principal_id, undefined)
  })

  it('drops spend_amount and spend_currency', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.spend_amount, undefined)
    assert.equal(out.spend_currency, undefined)
  })

  it('drops delegation_chain (delegation internals)', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.delegation_chain, undefined)
  })

  it('drops free-form internal_metadata', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    assert.equal(out.internal_metadata, undefined)
  })

  it('regression guard: no key in the projection is outside the whitelist + row fallback', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, POLICY_PAYLOAD)
    const rowFallbackKeys = new Set([
      'id', 'event_type', 'verdict', 'created_at', 'schema_version', 'receipt_hash',
    ])
    const whitelistKeys = new Set(PUBLIC_BODY_WHITELISTS.policy_receipt)
    for (const key of Object.keys(out)) {
      assert.ok(
        rowFallbackKeys.has(key) || whitelistKeys.has(key),
        `key "${key}" leaked into the projection (not in row fallback or policy_receipt whitelist)`,
      )
    }
  })
})

describe('projectPublicBody — unknown type falls back to row only', () => {
  it('returns only the row fallback fields for an unknown proof type', () => {
    const out = projectPublicBody('unknown_type', POLICY_ROW, POLICY_PAYLOAD)
    // None of the payload fields should appear because the whitelist is empty.
    assert.equal(out.tenant_id, undefined)
    assert.equal(out.action_hash, undefined)
    assert.equal(out.spend_amount, undefined)
    assert.equal(out.delegation_chain, undefined)
    // Row fallback should be present.
    assert.equal(out.id, 'rcp_01')
    assert.equal(out.verdict, 'permit')
  })
})

describe('projectPublicBody — null/array/missing payload', () => {
  it('handles null parsedPayload (row-only)', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, null)
    assert.equal(out.id, 'rcp_01')
    assert.equal(out.verdict, 'permit')
    assert.equal(out.tenant_id, undefined)
  })

  it('rejects array payloads (returns row-only, no leak)', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, [{ tenant_id: 'x' }])
    assert.equal(out.tenant_id, undefined)
  })

  it('handles primitive payload (returns row-only)', () => {
    const out = projectPublicBody('policy_receipt', POLICY_ROW, 'a string')
    assert.equal(out.tenant_id, undefined)
  })
})

describe('projectPublicBody — per-type whitelists', () => {
  const accessPayload = {
    schema_version: '1.0',
    receipt_hash: 'sha256:aaaa',
    timestamp: '2026-04-11T12:00:00Z',
    purpose_hash: 'sha256:bbbb',
    source_hash: 'sha256:cccc',
    // Unsafe:
    tenant_id: 'leaky',
    data_source_payload: 'secret',
    contributor_id: 'contrib_01',
  }
  const accessRow = { id: 'acc_01', created_at: '2026-04-11T12:00:00Z' }

  it('access_receipt keeps purpose_hash and source_hash', () => {
    const out = projectPublicBody('access_receipt', accessRow, accessPayload)
    assert.equal(out.purpose_hash, 'sha256:bbbb')
    assert.equal(out.source_hash, 'sha256:cccc')
    assert.equal(out.tenant_id, undefined)
    assert.equal(out.data_source_payload, undefined)
    assert.equal(out.contributor_id, undefined)
  })

  const derivPayload = {
    schema_version: '1.0',
    receipt_id: 'drv_abc',
    derivative_type: 'model_weights_delta',
    transform_class: 'gradient_descent',
    lineage_confidence: 'complete',
    timestamp: '2026-04-11T12:00:00Z',
    external_boundary_break: false,
    is_synthetic_derivative: false,
    // Unsafe:
    parent_artifacts: [{ artifact_id: 'art_01', tenant_id: 'leaky' }],
    agent_id: 'agent_xyz',
    delegation_id: 'del_xyz',
  }
  const derivRow = { id: 'drv_abc', created_at: '2026-04-11T12:00:00Z' }

  it('derivation_receipt keeps derivative_type and lineage_confidence but drops parent_artifacts', () => {
    const out = projectPublicBody('derivation_receipt', derivRow, derivPayload)
    assert.equal(out.derivative_type, 'model_weights_delta')
    assert.equal(out.transform_class, 'gradient_descent')
    assert.equal(out.lineage_confidence, 'complete')
    assert.equal(out.parent_artifacts, undefined)
    assert.equal(out.agent_id, undefined)
    assert.equal(out.delegation_id, undefined)
  })
})

describe('payloadFingerprint', () => {
  it('produces a stable SHA-256 hex string', () => {
    const hex = payloadFingerprint('hello world')
    assert.match(hex, /^[0-9a-f]{64}$/)
    // Known SHA-256 of 'hello world'
    assert.equal(hex, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9')
  })

  it('produces different hashes for different inputs', () => {
    const a = payloadFingerprint('{"tenant_id":"a"}')
    const b = payloadFingerprint('{"tenant_id":"b"}')
    assert.notEqual(a, b)
  })

  it('is stable across calls with the same input', () => {
    const a = payloadFingerprint('test')
    const b = payloadFingerprint('test')
    assert.equal(a, b)
  })
})
