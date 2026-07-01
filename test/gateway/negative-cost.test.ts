// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B6 (Consilium): the two negative-cost CRITICALs (fix commit e3672c0).
//   A negative estimated_cost slipped past `cost > remaining` (a negative is
//   never greater than the remaining budget) AND, on permit, was ADDED to
//   spend_used, REFUNDING the budget -> unlimited spend. The fix rejects any
//   non-non-negative-finite cost before the budget math and only ever adds a
//   POSITIVE amount to spend_used.
//
// This file proves the property at two layers:
//   1. app guard  -- isNonNegativeFiniteCost rejects the full hostile domain.
//   2. DB invariant -- delegation rows cannot hold a negative / over-limit spend.
// The end-to-end "no refund on the wire" proof (portable across the pre-fix
// commit) lives in negative-cost-refund-e2e.test.ts.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { isNonNegativeFiniteCost } from '../../src/gateway/enforce.js'
import { initDB, getDB } from '../../src/db/schema.js'

describe('B6 unit: isNonNegativeFiniteCost rejects every hostile cost', () => {
  // The exact adversarial domain called out by the Consilium: a value that is
  // negative, non-finite, a signed zero edge, unsafe, or a coercing non-number
  // must NOT be accepted as a spendable cost.
  const rejected: Array<[string, unknown]> = [
    ['negative', -1],
    ['large negative', -1e9],
    ['NaN', Number.NaN],
    ['+Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
    ['coercing string "5"', '5'],
    ['coercing string "-5"', '-5'],
    ['empty string', ''],
    ['boolean true', true],
    ['boolean false', false],
    ['null', null],
    ['undefined', undefined],
    ['object', {}],
    ['array [1]', [1]],
    ['bigint', BigInt(5) as unknown],
  ]
  for (const [label, value] of rejected) {
    it(`rejects ${label}`, () => {
      assert.equal(isNonNegativeFiniteCost(value), false, `${label} must be rejected`)
    })
  }

  const accepted: Array<[string, number]> = [
    ['zero', 0],
    ['negative zero (-0 is >= 0)', -0],
    ['a normal positive', 12.5],
    ['a large but finite/unsafe integer', Number.MAX_SAFE_INTEGER + 1],
  ]
  for (const [label, value] of accepted) {
    it(`accepts ${label}`, () => {
      assert.equal(isNonNegativeFiniteCost(value), true, `${label} must be accepted as finite >= 0`)
    })
  }
})

describe('B6 DB invariant: delegation money columns are CHECK-constrained', () => {
  // Defense in depth behind the app guard: even a code path that bypassed the
  // guard cannot persist a negative or refunded spend. New databases (tests and
  // fresh deployments) carry these constraints; the existing-table rebuild is a
  // sign-off-gated money-path migration (see REMEDIATION-MEMO.md).
  function freshDB() {
    initDB(':memory:')
    const db = getDB()
    db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES ('t','T','t@test.local')`).run()
    return db
  }
  const insert = (db: Database.Database, spendLimit: number | null, spendUsed: number) =>
    db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, spend_limit, spend_used, status) VALUES (?, 't', 'p', 'c', 'commerce:checkout', ?, ?, 'active')`)
      .run(`d-${spendLimit}-${spendUsed}`, spendLimit, spendUsed)

  it('rejects a negative spend_used (a refund below zero)', () => {
    const db = freshDB()
    assert.throws(() => insert(db, 100, -5), /CHECK constraint failed/)
  })
  it('rejects a negative spend_limit', () => {
    const db = freshDB()
    assert.throws(() => insert(db, -1, 0), /CHECK constraint failed/)
  })
  it('rejects spend_used greater than spend_limit (over-refund past the ceiling)', () => {
    const db = freshDB()
    assert.throws(() => insert(db, 10, 20), /CHECK constraint failed/)
  })
  it('permits a valid within-budget row (control)', () => {
    const db = freshDB()
    assert.doesNotThrow(() => insert(db, 100, 50))
  })
  it('permits a null spend_limit (unlimited grant) with a non-negative spend', () => {
    const db = freshDB()
    assert.doesNotThrow(() => insert(db, null, 0))
  })
})
