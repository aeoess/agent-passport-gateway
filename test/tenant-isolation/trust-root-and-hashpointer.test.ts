// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-D4 - customer bring-your-own trust root (W2-B1 seam) and hash-and-pointer
// (W2-B6 seam). Confirms:
//   - a customer HSM/KMS anchor binds and records a fingerprint + reference,
//     NEVER private key material;
//   - raw private key material is refused;
//   - hash-and-pointer envelopes carry a hash + pointer, never payload bytes;
//   - the raw-payload tripwire catches a PHI-shaped field.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  validateCustomerTrustAnchor,
  bindTrustRoot,
  anchorFingerprint,
  toHashPointer,
  assertNoRawPayload,
  isHashOnly,
} from '../../src/gateway/tenant-isolation/index.js'

describe('trust-root seam (W2-B1) - customer bring-your-own root', () => {
  it('validates an HSM anchor by shape and labels assurance as a stub', () => {
    const v = validateCustomerTrustAnchor({
      source: 'hsm',
      keyRef: 'pkcs11:slot=0;object=tenant-signer',
      anchorMaterial: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
    })
    assert.equal(v.valid, true)
    // Assurance is verifier-derived in production; the stub is honest about it.
    assert.equal(v.assuranceSource, 'shape-check-stub')
  })

  it('a gateway-source anchor needs no customer material', () => {
    const v = validateCustomerTrustAnchor({ source: 'gateway', keyRef: '' })
    assert.equal(v.valid, true)
  })

  it('rejects a non-gateway anchor missing the keyRef', () => {
    const v = validateCustomerTrustAnchor({ source: 'kms', keyRef: '' })
    assert.equal(v.valid, false)
    assert.match(v.reason, /keyRef/)
  })

  it('REFUSES raw private key material in the keyRef (key must be a reference)', () => {
    const v = validateCustomerTrustAnchor({
      source: 'hsm',
      keyRef: '-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----',
      anchorMaterial: 'anchor',
    })
    assert.equal(v.valid, false)
    assert.match(v.reason, /private key material/)
  })

  it('bindTrustRoot records a fingerprint + reference, NEVER key material', () => {
    const anchor = {
      source: 'kms' as const,
      keyRef: 'arn:aws:kms:us-east-1:111122223333:key/abcd-1234',
      anchorMaterial: 'customer-anchor-public-material',
      label: 'acme-root',
    }
    const binding = bindTrustRoot(anchor)
    assert.equal(binding.source, 'kms')
    assert.equal(binding.keyRef, anchor.keyRef) // a reference, not a key
    assert.equal(binding.anchorFingerprint, anchorFingerprint(anchor.anchorMaterial))
    assert.match(binding.anchorFingerprint, /^[0-9a-f]{64}$/)
    // The binding object must not carry the anchor material itself.
    assert.ok(!('anchorMaterial' in binding))
  })

  it('bindTrustRoot throws on an invalid anchor', () => {
    assert.throws(() => bindTrustRoot({ source: 'hsm', keyRef: '' }), /binding refused/)
  })
})

describe('hash-and-pointer seam (W2-B6) - gateway stores hash + pointer only', () => {
  it('builds an envelope carrying a hash and a pointer, never the payload', () => {
    const env = toHashPointer('{"patient":"sensitive PHI"}', 'tenant://store/object-123', 'application/fhir+json')
    assert.match(env.contentHash, /^[0-9a-f]{64}$/)
    assert.equal(env.pointer, 'tenant://store/object-123')
    assert.equal(env.alg, 'sha256')
    // The payload bytes must NOT appear anywhere in the envelope.
    const serialized = JSON.stringify(env)
    assert.ok(!serialized.includes('sensitive PHI'))
    assert.ok(!serialized.includes('patient'))
  })

  it('isHashOnly confirms an envelope has no payload bytes', () => {
    const env = toHashPointer('payload', 'ptr')
    assert.equal(isHashOnly(env), true)
  })

  it('requires a customer-resolvable pointer', () => {
    assert.throws(() => toHashPointer('x', ''), /pointer/)
  })

  it('assertNoRawPayload tripwire catches a PHI-shaped field', () => {
    assert.throws(() => assertNoRawPayload({ phi: 'leak' }), /raw sensitive payload/)
    assert.throws(() => assertNoRawPayload({ raw_payload: 'leak' }), /raw sensitive payload/)
    assert.throws(() => assertNoRawPayload({ patient_record: 'leak' }), /raw sensitive payload/)
  })

  it('assertNoRawPayload passes a clean hash+pointer record', () => {
    assert.doesNotThrow(() =>
      assertNoRawPayload({ content_hash: 'abc', pointer: 'tenant://x', source: 'hsm' }),
    )
  })
})
