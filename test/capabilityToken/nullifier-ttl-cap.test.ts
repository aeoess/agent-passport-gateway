// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R4-2 (round-3 Consilium): the nullifier store REJECTS (does not clamp) a token
// whose expires_at exceeds now + MAX_CAPABILITY_TTL. sweepExpired can never evict a
// far-future expiry (disk DoS), and silent clamping (R3-3) under-protects quietly
// and can turn the sweep into a replay-enabler if accept-time MAX is missing. Loud
// beats silent: refuse a token the store cannot protect for its full lifetime, and
// store nothing. Supersedes the R3-3 clamp tests.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { SqliteNullifierStore, CapabilityTtlExceededError } from '../../src/capabilityToken/nullifier-store.js'

const iso = (msFromNow: number) => new Date(Date.now() + msFromNow).toISOString()
const H = 60 * 60 * 1000

describe('R4-2 nullifier TTL: reject, do not clamp', () => {
  it('[DoS] a far-future expires_at THROWS and stores nothing', () => {
    const store = new SqliteNullifierStore(new Database(':memory:')) // default 24h
    assert.throws(() => store.consume('dos', '9999-01-01T00:00:00.000Z'), CapabilityTtlExceededError)
    assert.equal(store.isConsumed('dos'), false, 'nothing is stored for a refused token')
    assert.equal(store.size(), 0)
  })

  it('a refusal does not poison the store: a DIFFERENT legitimate consume still works', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    assert.throws(() => store.consume('too-long', '9999-01-01T00:00:00.000Z'), CapabilityTtlExceededError)
    assert.doesNotThrow(() => store.consume('ok', iso(1 * H)))
    assert.equal(store.isConsumed('ok'), true)
  })

  it('a within-horizon expiry is stored unchanged and swept only after it passes', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('soon', iso(1 * H)) // within 24h
    assert.equal(store.sweepExpired(iso(30 * 60 * 1000)), 0, 'not swept before its expiry')
    assert.equal(store.sweepExpired(iso(2 * H)), 1, 'swept after its expiry')
  })

  it('replay detection is unaffected for a within-horizon token', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('rp', iso(2 * H))
    assert.throws(() => store.consume('rp', iso(2 * H)), /replay|already consumed/i)
  })

  it('the horizon is a constructor option (MAX_CAPABILITY_TTL); an exp beyond it is refused', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'), { maxCapabilityTtlMs: 1000 }) // 1s
    assert.throws(() => store.consume('tiny', iso(60 * 1000)), CapabilityTtlExceededError) // 60s > 1s horizon
    assert.doesNotThrow(() => store.consume('within', iso(500))) // 0.5s < 1s horizon
  })

  it('an unparseable expiry is left as-is (kept, never swept), not rejected', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    assert.doesNotThrow(() => store.consume('weird', 'not-a-timestamp'))
    assert.equal(store.sweepExpired(iso(48 * H)), 0, 'kept, never swept')
    assert.equal(store.isConsumed('weird'), true)
  })

  it('a null expiry (no declared TTL) is unchanged', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    assert.doesNotThrow(() => store.consume('noexp'))
    assert.equal(store.isConsumed('noexp'), true)
  })
})
