// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R3-3 (round-2 Consilium): insert-time TTL cap. sweepExpired can never evict a
// nullifier whose expires_at is far in the future, so an attacker who mints tokens
// with expires_at=9999 grows capability_nullifiers unbounded once the store is
// wired (disk DoS). Fix in consume(): clamp the STORED expires_at to
// min(claimed, now + MAX_CAPABILITY_TTL). This is the fail-closed-for-replay
// choice: MAX is the maximum capability-token lifetime, so a token cannot be
// validly presented after now+MAX; clamping the nullifier to now+MAX never drops
// replay protection while the token is still honorable, and it bounds table growth
// (a far-future or absent expiry can no longer make a row un-sweepable). Rejecting
// was considered but it refuses an over-horizon token outright and still leaves the
// caller to bound growth elsewhere; clamping bounds it at the store itself.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { SqliteNullifierStore } from '../../src/capabilityToken/nullifier-store.js'

const iso = (msFromNow: number) => new Date(Date.now() + msFromNow).toISOString()
const H = 60 * 60 * 1000

describe('R3-3 nullifier insert-time TTL cap', () => {
  it('[DoS] a far-future expires_at is clamped so the nullifier becomes sweepable', () => {
    const store = new SqliteNullifierStore(new Database(':memory:')) // default 24h horizon
    store.consume('dos', '9999-01-01T00:00:00.000Z')
    // The claimed expiry is centuries out; under the cap it is clamped to ~now+24h, so a sweep
    // beyond the horizon evicts it. Without the cap it could never be swept (unbounded growth).
    assert.equal(store.sweepExpired(iso(48 * H)), 1, 'clamped far-future nullifier IS evictable')
    assert.equal(store.isConsumed('dos'), false)
  })

  it('a within-horizon expiry is unchanged (not clamped, evicts only after it passes)', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('soon', iso(1 * H)) // expires in 1h, well within 24h
    assert.equal(store.sweepExpired(iso(30 * 60 * 1000)), 0, 'not swept before its real 1h expiry')
    assert.equal(store.isConsumed('soon'), true)
    assert.equal(store.sweepExpired(iso(2 * H)), 1, 'swept after its real expiry')
  })

  it('replay protection is intact within the clamped window', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('rp', '9999-01-01T00:00:00.000Z')
    assert.throws(() => store.consume('rp', '9999-01-01T00:00:00.000Z'), /replay|already consumed/i)
    // still blocked well within the clamp horizon
    assert.equal(store.sweepExpired(iso(1 * H)), 0, 'clamped nullifier survives a within-horizon sweep')
    assert.equal(store.isConsumed('rp'), true)
  })

  it('the horizon is a constructor option (MAX_CAPABILITY_TTL)', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'), { maxCapabilityTtlMs: 1000 }) // 1s
    store.consume('tiny', '9999-01-01T00:00:00.000Z') // clamps to now+1s
    assert.equal(store.sweepExpired(iso(5000)), 1, 'clamped to the 1s horizon, evicted after 5s')
  })

  it('an unparseable expiry is left as-is (sweep keeps it fail-safe), not clamped or rejected', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    assert.doesNotThrow(() => store.consume('weird', 'not-a-timestamp'))
    assert.equal(store.sweepExpired(iso(48 * H)), 0, 'kept, never swept')
    assert.equal(store.isConsumed('weird'), true)
  })
})
