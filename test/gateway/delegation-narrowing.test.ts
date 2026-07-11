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

  it('rejects a child whose running chain depth would exceed max_depth (the real depth bound)', () => {
    // parent sits at current_depth 3 with a ceiling of 3; the child would be depth 4 -> reject.
    const deep = { scope: 'commerce:checkout', spend_limit: 100, spend_used: 0, max_depth: 3, current_depth: 3 }
    const r = checkDelegationNarrowing(deep, { scope: ['commerce:checkout'], spend_limit: 10, max_depth: 3 })
    assert.equal(r.ok, false)
    assert.match(r.violations.join(' '), /chain depth 4 exceeds max_depth 3/)
  })

  it('allows a child within the running depth bound', () => {
    const shallow = { scope: 'commerce:checkout', spend_limit: 100, spend_used: 0, max_depth: 3, current_depth: 1 }
    // child depth 2 <= 3
    assert.equal(checkDelegationNarrowing(shallow, { scope: ['commerce:checkout'], spend_limit: 10, max_depth: 3 }).ok, true)
  })

  it('rejects an absent (null) child spend_limit under a spend-bounded parent (P1 widening)', () => {
    // Money-path narrowing violation: the parent carries a bounded spend budget, but the child
    // omits spend_limit (null). At enforcement time a null spend_limit is treated as unlimited, so
    // a null child would WIDEN a bounded ancestor to unbounded spend. Monotonic narrowing forbids
    // this: authority can only decrease. The child must carry an explicit bound.
    const r = checkDelegationNarrowing(parent, { scope: ['commerce:checkout'], spend_limit: null, max_depth: 1 })
    assert.equal(r.ok, false, 'a null child spend_limit under a bounded parent must not widen the bound')
    assert.match(r.violations.join(' '), /unbounded|absent|widen/i)
  })

  it('still allows an absent (null) child spend_limit when NO ancestor carries a bound', () => {
    // If the parent itself has no spend bound, introducing a bound is narrowing (allowed) and
    // leaving the child unbounded introduces no widening (there was no bound to widen). Preserve it.
    const unbounded = { scope: 'commerce:checkout', spend_limit: null, spend_used: 0, max_depth: 3, current_depth: 1 }
    assert.equal(checkDelegationNarrowing(unbounded, { scope: ['commerce:checkout'], spend_limit: null, max_depth: 3 }).ok, true)
  })
})
