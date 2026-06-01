// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-B3 risk-tiered freshness contracts - tier engine unit tests.
 *
 * Covers: tier-resolution precedence and boundaries; per-tier stale handling;
 * tier 3 fails closed always; tier 0 fails open with a recorded stale check;
 * no-evidence handling per tier; and the negative cases (malformed tiers).
 *
 * The freshness math is the SDK's; these tests inject deterministic
 * isFresh/computeAge stubs to exercise the tier behavior in isolation. The
 * gate test (freshness-gate.test.ts) exercises the REAL SDK functions.
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  resolveRiskTier,
  evaluateFreshnessTier,
  coerceRiskTier,
  type RiskTier,
  type AttestationFreshnessLike,
} from '../src/gateway/freshness/tier-engine.js'

// A minimal freshness descriptor; the injected stubs decide fresh/age.
const DESC = { type: 'rotating' as const, validAt: '2026-05-31T00:00:00.000Z', ttl: 60 }

function fixedFresh(fresh: boolean, age = 10) {
  return {
    isFresh: () => fresh,
    computeAge: () => age,
  }
}

describe('coerceRiskTier - boundaries and negatives', () => {
  it('accepts the valid tiers 0..3 as numbers', () => {
    for (const t of [0, 1, 2, 3]) assert.equal(coerceRiskTier(t), t)
  })
  it('accepts the valid tiers 0..3 as strings', () => {
    assert.equal(coerceRiskTier('0'), 0)
    assert.equal(coerceRiskTier(' 3 '), 3)
  })
  it('rejects out-of-range tiers', () => {
    assert.equal(coerceRiskTier(-1), null)
    assert.equal(coerceRiskTier(4), null)
    assert.equal(coerceRiskTier(99), null)
  })
  it('rejects non-tier inputs', () => {
    assert.equal(coerceRiskTier('high'), null)
    assert.equal(coerceRiskTier(null), null)
    assert.equal(coerceRiskTier(undefined), null)
    assert.equal(coerceRiskTier({}), null)
    assert.equal(coerceRiskTier(2.5), null)
  })
})

describe('resolveRiskTier - precedence and class mapping', () => {
  it('explicit per-action tier wins over everything', () => {
    assert.equal(resolveRiskTier({ taskClass: 'read', explicitTier: 3, delegationTier: 1 }), 3)
  })
  it('per-delegation tier wins when no explicit tier', () => {
    assert.equal(resolveRiskTier({ taskClass: 'read', delegationTier: 1 }), 1)
  })
  it('falls to task-class mapping when no explicit/delegation tier', () => {
    assert.equal(resolveRiskTier({ taskClass: 'read' }), 0)
    assert.equal(resolveRiskTier({ taskClass: 'write' }), 1)
    assert.equal(resolveRiskTier({ taskClass: 'email' }), 2)
    assert.equal(resolveRiskTier({ taskClass: 'commerce' }), 3)
    assert.equal(resolveRiskTier({ taskClass: 'deploy' }), 3)
    assert.equal(resolveRiskTier({ taskClass: 'secret' }), 3)
  })
  it('is case-insensitive on the task class', () => {
    assert.equal(resolveRiskTier({ taskClass: 'READ' }), 0)
    assert.equal(resolveRiskTier({ taskClass: 'Commerce' }), 3)
  })
  it('unknown task class defaults to tier 2 (cautious, not permissive)', () => {
    assert.equal(resolveRiskTier({ taskClass: 'frobnicate' }), 2)
    assert.equal(resolveRiskTier({ taskClass: '' }), 2)
  })
  it('ignores a malformed explicit tier and falls through', () => {
    assert.equal(resolveRiskTier({ taskClass: 'read', explicitTier: 'banana' }), 0)
    assert.equal(resolveRiskTier({ taskClass: 'read', explicitTier: 7 }), 0)
  })
})

describe('evaluateFreshnessTier - tier 3 fails closed always', () => {
  it('denies with fresh evidence', () => {
    const r = evaluateFreshnessTier({ tier: 3, freshness: DESC, ...fixedFresh(true) })
    assert.equal(r.outcome, 'fail_closed')
    assert.equal(r.blocks, true)
    assert.equal(r.reasonCode, 'freshness_tier3_fail_closed')
  })
  it('denies with stale evidence', () => {
    const r = evaluateFreshnessTier({ tier: 3, freshness: DESC, ...fixedFresh(false) })
    assert.equal(r.outcome, 'fail_closed')
    assert.equal(r.blocks, true)
  })
  it('denies with no evidence at all', () => {
    const r = evaluateFreshnessTier({ tier: 3, freshness: null, ...fixedFresh(true) })
    assert.equal(r.outcome, 'fail_closed')
    assert.equal(r.blocks, true)
    assert.equal(r.fresh, null)
  })
  it('still records the observed staleness for the trail', () => {
    const r = evaluateFreshnessTier({ tier: 3, freshness: DESC, ...fixedFresh(false, 7200) })
    assert.equal(r.ageSeconds, 7200)
    assert.equal(r.fresh, false)
  })
})

describe('evaluateFreshnessTier - tier 0 fails open with a recorded stale check', () => {
  it('allows fresh evidence', () => {
    const r = evaluateFreshnessTier({ tier: 0, freshness: DESC, ...fixedFresh(true, 5) })
    assert.equal(r.outcome, 'allow')
    assert.equal(r.blocks, false)
    assert.equal(r.fresh, true)
  })
  it('allows STALE evidence but records the staleness', () => {
    const r = evaluateFreshnessTier({ tier: 0, freshness: DESC, ...fixedFresh(false, 9000) })
    assert.equal(r.outcome, 'allow')
    assert.equal(r.blocks, false)
    assert.equal(r.fresh, false)
    assert.equal(r.ageSeconds, 9000, 'staleness must be recorded even though allowed')
    assert.equal(r.reasonCode, 'freshness_tier0_stale_allowed')
  })
  it('allows when no evidence supplied (records that no check was possible)', () => {
    const r = evaluateFreshnessTier({ tier: 0, freshness: null, ...fixedFresh(true) })
    assert.equal(r.outcome, 'allow')
    assert.equal(r.blocks, false)
    assert.equal(r.fresh, null)
    assert.equal(r.reasonCode, 'freshness_tier0_no_evidence')
  })
})

describe('evaluateFreshnessTier - tier 1 internal write: warn, or require approval if stale', () => {
  it('allows fresh evidence', () => {
    const r = evaluateFreshnessTier({ tier: 1, freshness: DESC, ...fixedFresh(true) })
    assert.equal(r.outcome, 'allow')
    assert.equal(r.blocks, false)
  })
  it('requires approval when stale (blocks)', () => {
    const r = evaluateFreshnessTier({ tier: 1, freshness: DESC, ...fixedFresh(false, 3600) })
    assert.equal(r.outcome, 'require_approval')
    assert.equal(r.blocks, true)
    assert.equal(r.reasonCode, 'freshness_tier1_stale_requires_approval')
  })
  it('warns (does not block) when no evidence supplied', () => {
    const r = evaluateFreshnessTier({ tier: 1, freshness: null, ...fixedFresh(true) })
    assert.equal(r.outcome, 'warn')
    assert.equal(r.blocks, false)
  })
})

describe('evaluateFreshnessTier - tier 2 external/sensitive: deny if stale', () => {
  it('allows fresh evidence', () => {
    const r = evaluateFreshnessTier({ tier: 2, freshness: DESC, ...fixedFresh(true) })
    assert.equal(r.outcome, 'allow')
    assert.equal(r.blocks, false)
  })
  it('denies when stale', () => {
    const r = evaluateFreshnessTier({ tier: 2, freshness: DESC, ...fixedFresh(false, 120) })
    assert.equal(r.outcome, 'deny')
    assert.equal(r.blocks, true)
    assert.equal(r.reasonCode, 'freshness_tier2_stale_denied')
  })
  it('denies when no evidence supplied (freshness could not be confirmed)', () => {
    const r = evaluateFreshnessTier({ tier: 2, freshness: null, ...fixedFresh(true) })
    assert.equal(r.outcome, 'deny')
    assert.equal(r.blocks, true)
    assert.equal(r.reasonCode, 'freshness_tier2_no_evidence')
  })
})

describe('evaluateFreshnessTier - stale handling differs per tier (same stale evidence)', () => {
  // The SAME stale descriptor produces a DIFFERENT outcome at each tier.
  const stale = fixedFresh(false, 5000)
  it('tier 0 allows, tier 1 requires approval, tier 2 denies, tier 3 fails closed', () => {
    const t0 = evaluateFreshnessTier({ tier: 0, freshness: DESC, ...stale })
    const t1 = evaluateFreshnessTier({ tier: 1, freshness: DESC, ...stale })
    const t2 = evaluateFreshnessTier({ tier: 2, freshness: DESC, ...stale })
    const t3 = evaluateFreshnessTier({ tier: 3, freshness: DESC, ...stale })

    assert.equal(t0.blocks, false)
    assert.equal(t1.blocks, true)
    assert.equal(t2.blocks, true)
    assert.equal(t3.blocks, true)

    assert.equal(t0.outcome, 'allow')
    assert.equal(t1.outcome, 'require_approval')
    assert.equal(t2.outcome, 'deny')
    assert.equal(t3.outcome, 'fail_closed')

    // All tiers record the same observed staleness.
    for (const r of [t0, t1, t2, t3]) assert.equal(r.ageSeconds, 5000)
  })
})

describe('evaluateFreshnessTier - SDK failure is treated conservatively', () => {
  it('treats a throwing isFresh as not-confirmed-fresh (tier 2 denies)', () => {
    const throwing = {
      isFresh: () => { throw new Error('sdk down') },
      computeAge: () => { throw new Error('sdk down') },
    }
    const r = evaluateFreshnessTier({ tier: 2, freshness: DESC, ...throwing })
    assert.equal(r.fresh, null)
    assert.equal(r.blocks, true)
    assert.equal(r.outcome, 'deny')
  })
  it('tier 0 still allows even when the SDK math throws', () => {
    const throwing = {
      isFresh: () => { throw new Error('sdk down') },
      computeAge: () => { throw new Error('sdk down') },
    }
    const r = evaluateFreshnessTier({ tier: 0, freshness: DESC, ...throwing })
    assert.equal(r.blocks, false)
    assert.equal(r.outcome, 'allow')
  })
})

// Compile-time sanity: RiskTier and AttestationFreshnessLike are exported.
const _tierCheck: RiskTier = 2
const _descCheck: AttestationFreshnessLike = DESC
void _tierCheck
void _descCheck
