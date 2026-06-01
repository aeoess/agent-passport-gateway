// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-B3 freshness gate - integration with the REAL SDK freshness primitives.
 *
 * The tier-engine test injects deterministic stubs; this test runs the gate
 * end-to-end through the actual `isEvidenceFresh` / `computeEvidenceAge` from
 * agent-passport-system 2.6.0-alpha.3, plus the descriptor parser, the
 * revocation-mode selection, and the Wave 2 recording stub (M4) which returns
 * null today (recordedViaSdk === false).
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  runFreshnessGate,
  parseFreshnessDescriptor,
  selectRevocationMode,
} from '../src/gateway/freshness/gate.js'

function isoAgo(seconds: number): string {
  return new Date(Date.now() - seconds * 1000).toISOString()
}

describe('parseFreshnessDescriptor - accepts well-formed, rejects malformed', () => {
  it('accepts a full rotating descriptor', () => {
    const d = parseFreshnessDescriptor({ type: 'rotating', validAt: isoAgo(10), ttl: 600 })
    assert.ok(d)
    assert.equal(d!.type, 'rotating')
    assert.equal(d!.ttl, 600)
  })
  it('accepts snake_case fields (valid_at, max_age)', () => {
    const d = parseFreshnessDescriptor({ type: 'snapshot', valid_at: isoAgo(5), max_age: 30 })
    assert.ok(d)
    assert.equal(d!.maxAge, 30)
  })
  it('rejects an unknown type', () => {
    assert.equal(parseFreshnessDescriptor({ type: 'weekly', validAt: isoAgo(1) }), null)
  })
  it('rejects a missing/empty validAt', () => {
    assert.equal(parseFreshnessDescriptor({ type: 'static' }), null)
    assert.equal(parseFreshnessDescriptor({ type: 'static', validAt: '' }), null)
  })
  it('rejects an unparseable validAt', () => {
    assert.equal(parseFreshnessDescriptor({ type: 'static', validAt: 'not-a-date' }), null)
  })
  it('rejects non-object input', () => {
    assert.equal(parseFreshnessDescriptor(null), null)
    assert.equal(parseFreshnessDescriptor('rotating'), null)
    assert.equal(parseFreshnessDescriptor(42), null)
  })
  it('drops a negative ttl/maxAge rather than carrying it', () => {
    const d = parseFreshnessDescriptor({ type: 'rotating', validAt: isoAgo(1), ttl: -5 })
    assert.ok(d)
    assert.equal(d!.ttl, undefined)
  })
})

describe('selectRevocationMode - tier maps to credential-check mode (W2-B3 wiring)', () => {
  it('tier 3 and 2 demand the strictest live check', () => {
    assert.equal(selectRevocationMode(3), 'both')
    assert.equal(selectRevocationMode(2), 'both')
  })
  it('tier 1 is on-process', () => {
    assert.equal(selectRevocationMode(1), 'on-process')
  })
  it('tier 0 is on-accept', () => {
    assert.equal(selectRevocationMode(0), 'on-accept')
  })
})

describe('runFreshnessGate - real SDK: tier 0 read-only fails open with recorded stale check', () => {
  it('allows a clearly stale rotating credential and records its age', async () => {
    const r = await runFreshnessGate({
      taskClass: 'read',
      // rotating, ttl 60s, produced 1 hour ago => stale per SDK semantics
      freshnessInput: { type: 'rotating', validAt: isoAgo(3600), ttl: 60 },
    })
    assert.equal(r.tier, 0)
    assert.equal(r.blocks, false)
    assert.equal(r.outcome, 'allow')
    assert.equal(r.fresh, false, 'SDK should report the credential as not fresh')
    assert.ok((r.ageSeconds ?? 0) >= 3000, `expected recorded age ~3600s, got ${r.ageSeconds}`)
  })
})

describe('runFreshnessGate - real SDK: tier 3 fails closed regardless of freshness', () => {
  it('denies even with a perfectly fresh credential', async () => {
    const r = await runFreshnessGate({
      taskClass: 'commerce',
      freshnessInput: { type: 'rotating', validAt: isoAgo(1), ttl: 3600 },
    })
    assert.equal(r.tier, 3)
    assert.equal(r.blocks, true)
    assert.equal(r.outcome, 'fail_closed')
    assert.equal(r.revocationMode, 'both')
  })
})

describe('runFreshnessGate - real SDK: tier 2 denies stale, allows fresh', () => {
  it('denies a stale snapshot for an external action', async () => {
    const r = await runFreshnessGate({
      taskClass: 'email',
      freshnessInput: { type: 'snapshot', validAt: isoAgo(600), maxAge: 60 },
    })
    assert.equal(r.tier, 2)
    assert.equal(r.blocks, true)
    assert.equal(r.outcome, 'deny')
  })
  it('allows a fresh rotating credential for an external action', async () => {
    const r = await runFreshnessGate({
      taskClass: 'email',
      freshnessInput: { type: 'rotating', validAt: isoAgo(5), ttl: 600 },
    })
    assert.equal(r.tier, 2)
    assert.equal(r.blocks, false)
    assert.equal(r.outcome, 'allow')
    assert.equal(r.fresh, true)
  })
})

describe('runFreshnessGate - request tier raises but cannot lower the class floor (B3 clamp)', () => {
  it('a read action forced to tier 3 fails closed', async () => {
    const r = await runFreshnessGate({
      taskClass: 'read',
      requestTier: 3,
      freshnessInput: { type: 'rotating', validAt: isoAgo(1), ttl: 3600 },
    })
    assert.equal(r.tier, 3)
    assert.equal(r.outcome, 'fail_closed')
  })
  it('a commerce action cannot be downgraded below tier 3 by a request field', async () => {
    // The action-class default is a floor. A money action stays tier 3 even when
    // the caller passes risk_tier 0, so the tier-3 fail-closed cannot be bypassed.
    // The request tier may only raise the resolved tier, never lower it.
    const r = await runFreshnessGate({
      taskClass: 'commerce',
      requestTier: 0,
      freshnessInput: { type: 'rotating', validAt: isoAgo(3600), ttl: 60 },
    })
    assert.equal(r.tier, 3)
    assert.equal(r.outcome, 'fail_closed')
  })
})

describe('runFreshnessGate - no freshness evidence supplied', () => {
  it('tier 0 allows, tier 2 denies, tier 3 fails closed', async () => {
    const t0 = await runFreshnessGate({ taskClass: 'read' })
    const t2 = await runFreshnessGate({ taskClass: 'email' })
    const t3 = await runFreshnessGate({ taskClass: 'commerce' })
    assert.equal(t0.blocks, false)
    assert.equal(t2.blocks, true)
    assert.equal(t3.blocks, true)
    assert.equal(t0.fresh, null)
  })
})

describe('runFreshnessGate - Wave 2 M4 recording stub', () => {
  it('recordedViaSdk is false until the M4 recording primitive lands', async () => {
    const r = await runFreshnessGate({
      taskClass: 'read',
      freshnessInput: { type: 'static', validAt: isoAgo(10) },
    })
    assert.equal(r.recordedViaSdk, false, 'M4 recording is stubbed; must be false on alpha.3')
  })
})
