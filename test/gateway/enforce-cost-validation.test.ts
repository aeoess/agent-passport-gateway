// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Regression: gateway estimated_cost validation (negative-cost money bug)
// ══════════════════════════════════════════════════════════════════
// A negative estimated_cost slipped past the budget check (`cost > remaining`
// is false for a negative) AND, on permit, was ADDED to spend_used, refunding
// the budget. The evaluate path now rejects any estimated_cost that is not a
// non-negative finite number via isNonNegativeFiniteCost, denying the request
// and never updating spend_used. This unit-tests the validation predicate that
// the route uses. It fails before the fix (the function did not exist).
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { isNonNegativeFiniteCost } from '../../src/gateway/enforce.js'

describe('gateway estimated_cost validation', () => {
  it('accepts non-negative finite numbers (including zero)', () => {
    for (const ok of [0, 0.01, 1, 100, 999999.99]) {
      assert.equal(isNonNegativeFiniteCost(ok), true, `${ok} should be valid`)
    }
  })

  it('rejects negative, non-finite, and non-number costs (the bypass + refund vector)', () => {
    for (const bad of [-1, -0.01, -1000, NaN, Infinity, -Infinity, '5', null, undefined, {}, [], true]) {
      assert.equal(isNonNegativeFiniteCost(bad as unknown), false, `${String(bad)} should be invalid`)
    }
  })
})
