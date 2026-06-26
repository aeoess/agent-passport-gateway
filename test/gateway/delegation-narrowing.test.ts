// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Regression: gateway delegation creation must enforce monotonic narrowing
// ══════════════════════════════════════════════════════════════════
// POST /delegations checked only that the child agent exists; it never verified
// the new delegation narrowed the parent's grant, so a delegatee could mint a
// child with broader scope, higher spend, or a deeper ceiling (escalation).
// This unit-tests the predicate the route now gates on.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { checkDelegationNarrowing, scopeCovers } from '../../src/gateway/enforce.js'

describe('scopeCovers', () => {
  it('covers exact, global, hierarchical prefix, and wildcard suffix', () => {
    assert.equal(scopeCovers('*', 'anything:here'), true)
    assert.equal(scopeCovers('commerce:checkout', 'commerce:checkout'), true)
    assert.equal(scopeCovers('commerce', 'commerce:checkout'), true)
    assert.equal(scopeCovers('commerce:*', 'commerce:checkout'), true)
  })
  it('does not cover unrelated or broader scopes', () => {
    assert.equal(scopeCovers('commerce:browse', 'commerce:checkout'), false)
    assert.equal(scopeCovers('commerce:checkout', 'commerce'), false)
    assert.equal(scopeCovers('data:read', 'admin:write'), false)
  })
})

describe('checkDelegationNarrowing', () => {
  const parent = { scope: 'commerce:checkout,data:read', spend_limit: 100, spend_used: 30, max_depth: 3 }

  it('allows a root grant (no parent delegation)', () => {
    assert.equal(checkDelegationNarrowing(null, { scope: ['anything'], spend_limit: 9999, max_depth: 9 }).ok, true)
  })

  it('allows a legitimate narrowing', () => {
    const r = checkDelegationNarrowing(parent, { scope: ['commerce:checkout'], spend_limit: 50, max_depth: 2 })
    assert.equal(r.ok, true, r.violations.join('; '))
  })

  it('rejects scope escalation', () => {
    const r = checkDelegationNarrowing(parent, { scope: ['admin:write'], spend_limit: 10, max_depth: 1 })
    assert.equal(r.ok, false)
    assert.match(r.violations.join(' '), /not within the parent/)
  })

  it('rejects spend above the parent REMAINING budget (not just the nominal limit)', () => {
    // remaining = 100 - 30 = 70; a child limit of 80 is under the nominal 100 but over remaining.
    const r = checkDelegationNarrowing(parent, { scope: ['commerce:checkout'], spend_limit: 80, max_depth: 1 })
    assert.equal(r.ok, false)
    assert.match(r.violations.join(' '), /exceeds parent remaining/)
  })

  it('rejects a deeper depth ceiling', () => {
    const r = checkDelegationNarrowing(parent, { scope: ['data:read'], spend_limit: 10, max_depth: 5 })
    assert.equal(r.ok, false)
    assert.match(r.violations.join(' '), /max_depth 5 exceeds/)
  })
})
