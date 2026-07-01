// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Consilium hostile panel B4 Finding 1 (HIGH, replay) + Finding 2 (LOW, bloat):
// sweepExpired compared expires_at as an OPAQUE STRING (`expires_at < now`). A
// valid ISO-8601 expiry rendered with a timezone offset ('...-05:00') instead of
// 'Z' sorts before a 'Z'/'.'-suffixed now, so a STILL-VALID nullifier gets swept
// hours before its real expiry -> the token can be replayed. And an expired no-ms
// nullifier ('...05Z') sorts after a '...05.500Z' now, so it is NOT swept (bloat).
// Fix: compare epochs (strftime('%s', ...) normalizes the TZ), not raw strings.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { SqliteNullifierStore } from '../../src/capabilityToken/nullifier-store.js'

describe('B4 panel F1/F2: sweepExpired is timezone-correct (epoch, not lexicographic)', () => {
  it('[ATTACK F1] a still-valid token expressed with a -05:00 offset is NOT swept early (no replay)', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    // Token truly expires at 2026-07-01T05:00:00Z, expressed with a -05:00 offset (a tz-aware emitter).
    store.consume('capTok', '2026-07-01T00:00:00-05:00')
    // A routine sweep at 00:00:00Z runs 5 HOURS before the token actually expires.
    const swept = store.sweepExpired('2026-07-01T00:00:00.000Z')
    assert.equal(swept, 0, 'a still-valid nullifier must not be swept')
    assert.equal(store.isConsumed('capTok'), true, 'the nullifier is still present')
    assert.throws(() => store.consume('capTok', '2026-07-01T00:00:00-05:00'), /replay|already consumed/i, 'replay stays rejected')
  })

  it('[F2] an EXPIRED no-milliseconds nullifier IS swept (no unbounded bloat)', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('e', '2026-07-01T00:00:05Z') // expires at :05, no milliseconds
    const swept = store.sweepExpired('2026-07-01T00:00:05.500Z') // 0.5s after expiry
    assert.equal(swept, 1, 'an expired nullifier must be swept regardless of ms/Z form')
    assert.equal(store.isConsumed('e'), false)
  })

  it('a normal Z-form expiry sweeps only after it passes (control)', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('live', '2030-01-01T00:00:00.000Z')
    store.consume('dead', '2020-01-01T00:00:00.000Z')
    assert.equal(store.sweepExpired('2026-06-01T00:00:00.000Z'), 1, 'only the past-expiry one is swept')
    assert.equal(store.isConsumed('live'), true)
    assert.equal(store.isConsumed('dead'), false)
  })

  it('an unparseable stored expiry is never swept (fail-safe: keep, do not reopen replay)', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('weird', 'not-a-timestamp')
    assert.equal(store.sweepExpired('2030-01-01T00:00:00.000Z'), 0, 'a value SQLite cannot parse is kept, never swept')
    assert.equal(store.isConsumed('weird'), true)
  })
})
