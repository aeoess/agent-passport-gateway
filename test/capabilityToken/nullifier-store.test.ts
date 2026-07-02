// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Audit item 5 (HIGH replay): the capability-token nullifier must persist across
// restarts and processes, not live in a per-process in-memory Set. A consumed
// token preimage recorded by one instance must be seen as spent by a fresh one.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SqliteNullifierStore, InMemoryNullifierStore } from '../../src/capabilityToken/nullifier-store.js'

let dir: string
let dbPath: string

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'nullifier-'))
  dbPath = join(dir, 'gw.db')
})
after(() => { try { rmSync(dir, { recursive: true, force: true }) } catch {} })

describe('SqliteNullifierStore persistence (audit item 5)', () => {
  it('a nullifier consumed in one instance is seen as spent by a FRESH instance (persistence)', () => {
    const db1 = new Database(dbPath)
    const store1 = new SqliteNullifierStore(db1)
    store1.consume('preimage-alpha')
    assert.equal(store1.isConsumed('preimage-alpha'), true)
    db1.close()

    // Simulated restart / separate process: a brand-new connection + store on the same DB file.
    const db2 = new Database(dbPath)
    const store2 = new SqliteNullifierStore(db2)
    assert.equal(store2.isConsumed('preimage-alpha'), true, 'consumed nullifier survived the restart')
    db2.close()
  })

  it('a replay across a simulated restart is REJECTED', () => {
    const p = join(dir, 'replay.db')
    const db1 = new Database(p)
    new SqliteNullifierStore(db1).consume('preimage-beta')
    db1.close()

    const db2 = new Database(p)
    const store2 = new SqliteNullifierStore(db2)
    assert.throws(() => store2.consume('preimage-beta'), /replay/, 'restarted instance must reject the replay')
    db2.close()
  })

  it('check-and-consume is atomic: first consume ok, immediate replay throws', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('once')
    assert.throws(() => store.consume('once'), /already consumed/)
    assert.equal(store.size(), 1)
  })

  it('a fresh nullifier is not consumed; a distinct one is independent', () => {
    const store = new SqliteNullifierStore(new Database(':memory:'))
    store.consume('a')
    assert.equal(store.isConsumed('a'), true)
    assert.equal(store.isConsumed('b'), false)
    store.consume('b')
    assert.equal(store.size(), 2)
  })

  it('sweepExpired removes past-TTL nullifiers so they can be re-issued; keeps live ones', () => {
    // Large horizon: this test uses fixed far-future exps to mean "live"; the R4-2 TTL reject is
    // covered by nullifier-ttl-cap.test.ts, not here.
    const store = new SqliteNullifierStore(new Database(':memory:'), { maxCapabilityTtlMs: 100 * 365 * 24 * 60 * 60 * 1000 })
    store.consume('expired-token', '2020-01-01T00:00:00.000Z')
    store.consume('live-token', '2099-01-01T00:00:00.000Z')
    const swept = store.sweepExpired('2026-06-30T00:00:00.000Z')
    assert.equal(swept, 1)
    assert.equal(store.isConsumed('expired-token'), false)
    assert.equal(store.isConsumed('live-token'), true)
    // an expired-then-swept preimage can be consumed again (its window has passed)
    store.consume('expired-token', '2099-01-01T00:00:00.000Z')
    assert.equal(store.isConsumed('expired-token'), true)
  })
})

describe('InMemoryNullifierStore (reference / test path)', () => {
  it('consumes, detects replay, reports size, clears', () => {
    const s = new InMemoryNullifierStore()
    s.consume('x')
    assert.equal(s.isConsumed('x'), true)
    assert.throws(() => s.consume('x'), /replay/)
    assert.equal(s.size(), 1)
    s.clear()
    assert.equal(s.isConsumed('x'), false)
    assert.equal(s.size(), 0)
  })
})
