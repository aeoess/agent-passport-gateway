// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B4 (Consilium): prove the nullifier store's replay guarantees at the level the
// live wire will depend on - not just "consume twice throws", but:
//   * UNIQUE(nullifier) is enforced by the DATABASE (a raw duplicate INSERT with
//     no ON CONFLICT clause raises a constraint error), so replay protection does
//     not rely on app-level bookkeeping.
//   * consume() detects a replay by reading changes() from the atomic INSERT, so
//     it rejects a nullifier ALREADY present in the table even if this store
//     instance never saw it (no stale in-memory set).
//   * two live store instances over the same DB: exactly one consume of a given
//     preimage wins; the other is rejected (cross-instance atomicity).
//   * the expires_at TTL is a REPLAY-SAFETY boundary: a nullifier swept before the
//     token's true expiry re-opens the replay window. This is the concrete reason
//     the caller MUST bind expires_at to the VERIFIED token exp, never a shorter
//     value. (The binding itself happens at the redemption call site, which lives
//     in agent-passport-mcp - see REMEDIATION-MEMO.md, B4 OPEN wiring obligation.)
//
// The store here is already correct (UNIQUE PK + changes()-based detection pre-date
// this remediation); this file locks those properties down and documents the exp
// obligation. The missing piece is the LIVE WIRE (MCP injection), tracked OPEN.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { SqliteNullifierStore } from '../../src/capabilityToken/nullifier-store.js'

const nowIso = () => new Date().toISOString()

describe('B4 nullifier replay guarantees (store contract for the live wire)', () => {
  it('UNIQUE(nullifier) is enforced by the DB, not just app logic', () => {
    const db = new Database(':memory:')
    new SqliteNullifierStore(db) // creates the table
    db.prepare(`INSERT INTO capability_nullifiers (nullifier, expires_at, created_at) VALUES ('n', NULL, ?)`).run(nowIso())
    // A second RAW insert with NO ON CONFLICT clause must hit the primary-key unique index.
    assert.throws(
      () => db.prepare(`INSERT INTO capability_nullifiers (nullifier, expires_at, created_at) VALUES ('n', NULL, ?)`).run(nowIso()),
      /UNIQUE constraint failed|PRIMARY KEY/i,
      'the nullifier column must be a DB-enforced unique key',
    )
  })

  it('consume() reads changes() and rejects a nullifier ALREADY in the table (no stale in-memory set)', () => {
    const db = new Database(':memory:')
    const store = new SqliteNullifierStore(db)
    // A different actor (or a prior process) inserted the nullifier directly.
    db.prepare(`INSERT INTO capability_nullifiers (nullifier, expires_at, created_at) VALUES ('preexisting', NULL, ?)`).run(nowIso())
    // This store instance never called consume for it, yet must reject the replay via changes()===0.
    assert.throws(() => store.consume('preexisting'), /replay|already consumed/i)
  })

  it('two live store instances over one DB: exactly one consume of a preimage wins', () => {
    const db = new Database(':memory:')
    const a = new SqliteNullifierStore(db)
    const b = new SqliteNullifierStore(db)
    a.consume('shared-preimage')
    assert.throws(() => b.consume('shared-preimage'), /replay|already consumed/i, 'the second instance must lose the race')
    assert.equal(a.size(), 1)
  })

  it('[HAZARD] an expires_at SHORTER than the token exp re-opens replay after a sweep', () => {
    // Model a token whose VERIFIED exp is 2030, consumed with a WRONG (too-short) exp of 2026.
    // Large horizon: this test uses a fixed 2030 "verified exp"; the R4-2 TTL reject is covered in
    // nullifier-ttl-cap.test.ts, not here.
    const db = new Database(':memory:')
    const FAR = { maxCapabilityTtlMs: 100 * 365 * 24 * 60 * 60 * 1000 }
    const store = new SqliteNullifierStore(db, FAR)
    const tokenVerifiedExp = '2030-01-01T00:00:00.000Z'
    const wrongShortExp = '2026-02-01T00:00:00.000Z'
    store.consume('replayable', wrongShortExp)
    // A routine TTL sweep at a time AFTER the wrong exp but BEFORE the real token exp...
    const swept = store.sweepExpired('2026-06-01T00:00:00.000Z')
    assert.equal(swept, 1, 'the too-short exp caused a premature sweep')
    // ...frees the slot, so the STILL-VALID token can now be replayed. This is the vulnerability
    // that binding expires_at to the verified token exp prevents.
    assert.doesNotThrow(() => store.consume('replayable', tokenVerifiedExp), 'replay re-opened by the premature sweep')

    // Control: bound correctly to the verified exp, the same sweep does NOT remove it, so replay stays shut.
    const store2 = new SqliteNullifierStore(new Database(':memory:'), FAR)
    store2.consume('safe', tokenVerifiedExp)
    assert.equal(store2.sweepExpired('2026-06-01T00:00:00.000Z'), 0, 'correctly-bound exp survives the sweep')
    assert.throws(() => store2.consume('safe', tokenVerifiedExp), /replay|already consumed/i, 'replay stays rejected')
  })
})
