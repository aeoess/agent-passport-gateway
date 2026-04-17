// DID resolution cache tests — migrated from SDK after the TTL cache
// primitives moved to the gateway. SDK keeps verifyEntityChain as a
// pure live-resolution primitive.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDID, clearStores,
} from 'agent-passport-system'
import type { PublicProofSurface } from 'agent-passport-system'
import { DIDCache, verifyEntityChainCached } from '../../../src/sdk-migrated/core/did-cache.js'

const keys = generateKeyPair()

async function mockLookup(entityId: string): Promise<PublicProofSurface | null> {
  if (entityId === 'active-entity') {
    return {
      entity_id: 'active-entity', name: 'AEOESS DAO LLC',
      status: 'active', entity_type: 'wyoming_dao_llc',
      authority_ceiling: ['hold_assets'],
      verified_at: '2026-03-24T00:00:00Z',
    }
  }
  return null
}

describe('DIDCache — basic put/get', () => {
  it('caches a DID resolution', () => {
    const cache = new DIDCache()
    const did = createDID(keys.publicKey)
    const entry = cache.put(did, keys.publicKey, 3600_000)
    assert.equal(entry.did, did)
    assert.equal(entry.publicKey, keys.publicKey)
    assert.equal(entry.status, 'live')
    assert.ok(entry.resolvedAt)
    assert.ok(entry.expiresAt)
  })

  it('retrieves cached resolution with status=cached', () => {
    const cache = new DIDCache()
    const did = createDID(keys.publicKey)
    cache.put(did, keys.publicKey, 3600_000)
    const cached = cache.get(did)
    assert.ok(cached)
    assert.equal(cached!.publicKey, keys.publicKey)
    assert.equal(cached!.status, 'cached')
  })

  it('returns null for expired cache entry', () => {
    const cache = new DIDCache()
    const did = createDID(keys.publicKey)
    cache.put(did, keys.publicKey, 1) // 1ms TTL
    const start = Date.now()
    while (Date.now() - start < 5) { /* busy wait */ }
    const cached = cache.get(did)
    assert.equal(cached, null)
  })

  it('returns null for uncached DID', () => {
    const cache = new DIDCache()
    const cached = cache.get('did:aps:zNotCached')
    assert.equal(cached, null)
  })

  it('clear empties the cache', () => {
    const cache = new DIDCache()
    cache.put('did:a', 'pk_a')
    cache.put('did:b', 'pk_b')
    assert.equal(cache.size(), 2)
    cache.clear()
    assert.equal(cache.size(), 0)
  })
})

describe('verifyEntityChainCached — wraps SDK with cache fallback', () => {
  it('successful live resolve populates cache', async () => {
    clearStores()
    const cache = new DIDCache()
    const did = createDID(keys.publicKey)
    const result = await verifyEntityChainCached(did, mockLookup, { entityId: 'active-entity', cache })
    assert.equal(result.verified, true)
    assert.equal(result.didResolutionStatus, 'live')
    assert.equal(cache.size(), 1)
    const cached = cache.get(did)
    assert.equal(cached!.publicKey, keys.publicKey)
  })

  it('failed live resolve falls back to cached entry when allowed', async () => {
    const cache = new DIDCache()
    const did = 'did:aps:zUnresolvable123' // valid format but not in stores
    cache.put(did, keys.publicKey)
    const result = await verifyEntityChainCached(did, mockLookup, {
      entityId: 'active-entity',
      cache,
      allowCachedFallback: true,
    })
    assert.equal(result.didResolutionStatus, 'cached')
    assert.equal(result.resolvedPublicKey, keys.publicKey)
    assert.equal(result.verified, true)
  })

  it('failed live resolve fails closed when fallback disabled', async () => {
    const cache = new DIDCache()
    const did = 'did:aps:zUnresolvable999'
    cache.put(did, keys.publicKey)
    const result = await verifyEntityChainCached(did, mockLookup, {
      entityId: 'active-entity',
      cache,
      allowCachedFallback: false,
    })
    assert.equal(result.verified, false)
    assert.equal(result.didResolutionStatus, 'failed')
  })
})
