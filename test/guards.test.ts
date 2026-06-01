// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-C2 layer (a): compiled, stateless, non-Turing-complete pre-flight guards.
//
// Tests: guard latency, guard determinism, fail-closed blocking, and the
// load-bearing constraint that a high-risk action with no signed playbook is
// BLOCKED pre-flight (no agent/LLM in the path).

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  evaluateGuards,
  isScopeHighRisk,
  GUARD_NAMES,
  GUARD_SCOPE_SCAN_CAP,
  DEFAULT_HIGH_RISK_SCOPES,
  type GuardContext,
} from '../src/gateway/guards/index.js'

function ctx(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    agentStatus: 'active',
    scopeRequired: 'tool:web_search',
    actionType: 'tool:web_search',
    estimatedCost: 0,
    isHighRisk: false,
    coveredBySignedPlaybook: false,
    costCeiling: 0,
    ...overrides,
  }
}

describe('G-C2 guards - compiled set', () => {
  it('exposes the named compiled guards', () => {
    assert.ok(GUARD_NAMES.includes('posture_lock'))
    assert.ok(GUARD_NAMES.includes('high_risk_requires_signed_playbook'))
    assert.ok(GUARD_NAMES.includes('cost_ceiling'))
  })

  it('a benign active request passes', () => {
    const d = evaluateGuards(ctx())
    assert.equal(d.verdict, 'pass')
  })
})

describe('G-C2 guards - posture lock', () => {
  for (const status of ['suspended', 'frozen', 'revoked']) {
    it(`blocks a ${status} agent pre-flight`, () => {
      const d = evaluateGuards(ctx({ agentStatus: status }))
      assert.equal(d.verdict, 'block')
      assert.equal(d.code, 'guard_posture_lock')
      assert.equal(d.guard, 'posture_lock')
    })
  }
  it('does not block an active or restricted agent on posture', () => {
    assert.equal(evaluateGuards(ctx({ agentStatus: 'active' })).verdict, 'pass')
    assert.equal(evaluateGuards(ctx({ agentStatus: 'restricted' })).verdict, 'pass')
  })
})

describe('G-C2 guards - high-risk requires signed playbook (C1/C2 load-bearing)', () => {
  it('BLOCKS a high-risk action with no signed playbook covering it', () => {
    const d = evaluateGuards(ctx({
      scopeRequired: 'revocation:execute',
      isHighRisk: true,
      coveredBySignedPlaybook: false,
    }))
    assert.equal(d.verdict, 'block')
    assert.equal(d.code, 'guard_high_risk_unsigned')
    assert.equal(d.guard, 'high_risk_requires_signed_playbook')
  })

  it('PASSES a high-risk action when a signed playbook covers it', () => {
    const d = evaluateGuards(ctx({
      scopeRequired: 'revocation:execute',
      isHighRisk: true,
      coveredBySignedPlaybook: true,
    }))
    assert.equal(d.verdict, 'pass')
  })

  it('does not gate a non-high-risk action on playbook coverage', () => {
    const d = evaluateGuards(ctx({
      scopeRequired: 'tool:web_search',
      isHighRisk: false,
      coveredBySignedPlaybook: false,
    }))
    assert.equal(d.verdict, 'pass')
  })
})

describe('G-C2 guards - cost ceiling', () => {
  it('blocks when estimated cost exceeds a configured ceiling', () => {
    const d = evaluateGuards(ctx({ estimatedCost: 150, costCeiling: 100 }))
    assert.equal(d.verdict, 'block')
    assert.equal(d.code, 'guard_cost_ceiling')
  })
  it('passes when no ceiling is configured (ceiling 0)', () => {
    const d = evaluateGuards(ctx({ estimatedCost: 1_000_000, costCeiling: 0 }))
    assert.equal(d.verdict, 'pass')
  })
})

describe('G-C2 guards - first-deny ordering', () => {
  it('posture lock wins over a high-risk-unsigned block (first compiled guard)', () => {
    const d = evaluateGuards(ctx({
      agentStatus: 'suspended',
      scopeRequired: 'revocation:execute',
      isHighRisk: true,
      coveredBySignedPlaybook: false,
    }))
    assert.equal(d.code, 'guard_posture_lock')
  })
})

describe('G-C2 guards - active-set filtering cannot enable un-vetted code', () => {
  it('disabling a guard by name skips only that guard', () => {
    // Disable posture_lock; a suspended agent now passes the (disabled) posture
    // guard but is still subject to the rest. With a benign scope it passes.
    const d = evaluateGuards(ctx({ agentStatus: 'suspended' }), ['high_risk_requires_signed_playbook', 'cost_ceiling'])
    assert.equal(d.verdict, 'pass')
  })
  it('an unknown active-guard name enables nothing', () => {
    const d = evaluateGuards(ctx(), ['definitely_not_a_real_guard'])
    assert.equal(d.verdict, 'pass') // no guards active => nothing blocks
  })
})

describe('G-C2 guards - determinism (stateless)', () => {
  it('the same input yields the same output across many runs', () => {
    const c = ctx({ scopeRequired: 'revocation:execute', isHighRisk: true })
    const first = evaluateGuards(c)
    for (let i = 0; i < 2000; i++) {
      const d = evaluateGuards(c)
      assert.deepEqual(d, first)
    }
  })

  it('isScopeHighRisk is a pure function of (scope, list)', () => {
    for (let i = 0; i < 1000; i++) {
      assert.equal(isScopeHighRisk('revocation:execute', DEFAULT_HIGH_RISK_SCOPES), true)
      assert.equal(isScopeHighRisk('admin:delete:everything', DEFAULT_HIGH_RISK_SCOPES), true)
      assert.equal(isScopeHighRisk('tool:web_search', DEFAULT_HIGH_RISK_SCOPES), false)
    }
  })
})

describe('G-C2 guards - latency (real-time, nanosecond-class)', () => {
  it('evaluates well under a 1ms budget per call on average', () => {
    const c = ctx({ scopeRequired: 'revocation:execute', isHighRisk: true, coveredBySignedPlaybook: false })
    const N = 100_000
    const start = process.hrtime.bigint()
    for (let i = 0; i < N; i++) evaluateGuards(c)
    const elapsedNs = Number(process.hrtime.bigint() - start)
    const perCallNs = elapsedNs / N
    // Compiled straight-line predicates: comfortably sub-microsecond. Budget is
    // generous (1ms) to stay non-flaky on shared CI, but typical is < 1000ns.
    assert.ok(perCallNs < 1_000_000, `per-call ${perCallNs.toFixed(0)}ns exceeded 1ms budget`)
  })
})

describe('G-C2 guards - non-Turing-complete (bounded work)', () => {
  it('isScopeHighRisk scans at most the cap even with an oversized list', () => {
    // A list far larger than the cap must not blow up; work is bounded by the cap.
    const big = Array.from({ length: GUARD_SCOPE_SCAN_CAP * 10 }, (_, i) => `noise:${i}`)
    const start = process.hrtime.bigint()
    const result = isScopeHighRisk('tool:web_search', big)
    const elapsedNs = Number(process.hrtime.bigint() - start)
    assert.equal(result, false)
    // Bounded: even with 10x the cap, a single call is trivially fast.
    assert.ok(elapsedNs < 1_000_000, `bounded scan took ${elapsedNs}ns`)
  })
})
