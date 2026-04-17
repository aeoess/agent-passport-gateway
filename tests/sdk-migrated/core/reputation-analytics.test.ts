// Reputation analytics tests (migrated from SDK on 2026-04-17).
// Consolidates three SDK test files:
//   - reputation-authority.test.ts: createPromotionReview + triggerDemotion blocks
//   - reputation-drift.test.ts: sliding-window drift detection
//   - consistency-score.test.ts: predictability scoring
//
// References: Nanook PDR v2.19 §6.5 (over-promiser paradox), §6.6
// (NexusGuard sliding-window drift); gap audit §3 rows 8/21 / §5 ranks 3/6.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  createScopedReputation,
  updateReputationFromResult,
  RECENT_OBSERVATIONS_CAP,
  generateKeyPair,
} from 'agent-passport-system'
import type {
  EvidencePortfolio,
  ScopedReputation,
  ReputationObservation,
  EvidenceClass,
} from 'agent-passport-system'

import {
  createPromotionReview,
  triggerDemotion,
  computeReputationDrift,
  computeConsistencyScore,
  DEFAULT_DRIFT_WARNING_THRESHOLD,
  DEFAULT_DRIFT_CRITICAL_THRESHOLD,
} from '../../../src/sdk-migrated/core/reputation-analytics.js'

// ══════════════════════════════════════
// createPromotionReview (workflow)
// ══════════════════════════════════════

describe('createPromotionReview', () => {
  const goodEvidence: EvidencePortfolio = {
    scope: 'code_execution', totalReceipts: 60,
    classCounts: { trivial: 30, standard: 18, complex: 9, critical: 3 },
    distinctReviewers: 3, distinctTaskTypes: 4,
    failureRate: 0.05, interventionRate: 0.1,
  }

  it('creates a signed promotion review', () => {
    const reviewer = generateKeyPair()
    const review = createPromotionReview({
      agentId: 'agent-target', principalId: 'principal-1',
      scope: 'code_execution', fromTier: 1, toTier: 2,
      reviewerId: 'agent-reviewer', reviewerTier: 3, reviewerOrigin: 'earned',
      evidence: goodEvidence, effectiveScore: 65,
      verdict: 'promoted', reasoning: 'Strong evidence',
      reviewerPrivateKey: reviewer.privateKey,
    })
    assert.ok(review.reviewId.startsWith('promo-'))
    assert.equal(review.verdict, 'promoted')
    assert.ok(review.signature)
    assert.ok(review.probationEndsAt, 'Promoted reviews should have probation')
  })

  it('rejects fiat reviewer', () => {
    const reviewer = generateKeyPair()
    assert.throws(() => {
      createPromotionReview({
        agentId: 'agent-target', principalId: 'p1', scope: 's',
        fromTier: 0, toTier: 1,
        reviewerId: 'reviewer', reviewerTier: 3, reviewerOrigin: 'fiat',
        evidence: goodEvidence, effectiveScore: 40,
        verdict: 'promoted', reasoning: 'test',
        reviewerPrivateKey: reviewer.privateKey,
      })
    }, /only 'earned' agents/)
  })

  it('rejects reviewer at same tier as target', () => {
    const reviewer = generateKeyPair()
    assert.throws(() => {
      createPromotionReview({
        agentId: 'agent-target', principalId: 'p1', scope: 's',
        fromTier: 1, toTier: 2,
        reviewerId: 'reviewer', reviewerTier: 2, reviewerOrigin: 'earned',
        evidence: goodEvidence, effectiveScore: 65,
        verdict: 'promoted', reasoning: 'test',
        reviewerPrivateKey: reviewer.privateKey,
      })
    }, /not above target tier/)
  })

  it('rejects self-promotion', () => {
    const reviewer = generateKeyPair()
    assert.throws(() => {
      createPromotionReview({
        agentId: 'agent-same', principalId: 'p1', scope: 's',
        fromTier: 1, toTier: 2,
        reviewerId: 'agent-same', reviewerTier: 3, reviewerOrigin: 'earned',
        evidence: goodEvidence, effectiveScore: 65,
        verdict: 'promoted', reasoning: 'test',
        reviewerPrivateKey: reviewer.privateKey,
      })
    }, /Self-promotion/)
  })

  it('denied verdict has no probation', () => {
    const reviewer = generateKeyPair()
    const review = createPromotionReview({
      agentId: 'agent-target', principalId: 'p1', scope: 's',
      fromTier: 1, toTier: 2,
      reviewerId: 'reviewer', reviewerTier: 3, reviewerOrigin: 'earned',
      evidence: goodEvidence, effectiveScore: 65,
      verdict: 'denied', reasoning: 'Insufficient evidence',
      reviewerPrivateKey: reviewer.privateKey,
    })
    assert.equal(review.probationEndsAt, undefined)
  })
})

// ══════════════════════════════════════
// triggerDemotion (workflow)
// ══════════════════════════════════════

describe('triggerDemotion', () => {
  it('behavioral demotion affects reputation', () => {
    const event = triggerDemotion({
      agentId: 'a1', principalId: 'p1', scope: 's',
      currentTier: 3, cause: 'behavioral', reason: 'Policy violation',
    })
    assert.equal(event.fromTier, 3)
    assert.equal(event.toTier, 2)
    assert.equal(event.affectsReputation, true)
    assert.equal(event.cause, 'behavioral')
  })

  it('administrative demotion preserves reputation', () => {
    const event = triggerDemotion({
      agentId: 'a1', principalId: 'p1', scope: 's',
      currentTier: 2, cause: 'administrative', reason: 'Policy changed',
    })
    assert.equal(event.affectsReputation, false)
  })

  it('environmental demotion preserves reputation', () => {
    const event = triggerDemotion({
      agentId: 'a1', principalId: 'p1', scope: 's',
      currentTier: 1, cause: 'environmental', reason: 'Upstream revoked',
    })
    assert.equal(event.affectsReputation, false)
  })

  it('does not demote below tier 0', () => {
    const event = triggerDemotion({
      agentId: 'a1', principalId: 'p1', scope: 's',
      currentTier: 0, cause: 'behavioral', reason: 'Failed',
    })
    assert.equal(event.toTier, 0)
  })
})

// ══════════════════════════════════════
// computeReputationDrift (analytics)
// ══════════════════════════════════════

function makeFreshRep(): ScopedReputation {
  return createScopedReputation('p-drift', 'a-drift', 's-drift')
}

function makeRepWithObservations(opts: {
  mu?: number
  sigma?: number
  recentObservations: ReputationObservation[]
}): ScopedReputation {
  const base = makeFreshRep()
  return {
    ...base,
    mu: opts.mu ?? 50,
    sigma: opts.sigma ?? 10,
    receiptCount: opts.recentObservations.length,
    recentObservations: opts.recentObservations,
  }
}

function obs(muDelta: number, success: boolean = true, evidenceClass: EvidenceClass = 'standard'): ReputationObservation {
  return {
    timestamp: '2026-04-10T00:00:00.000Z',
    success,
    evidenceClass,
    muDelta,
    sigmaDelta: 0,
  }
}

describe('computeReputationDrift — no history available', () => {
  it('fresh reputation with no recentObservations: delta=0, severity=none, alert=null', () => {
    const rep = makeFreshRep()
    assert.equal(rep.recentObservations, undefined, 'fresh rep has no ring buffer')

    const result = computeReputationDrift(rep, 5)
    assert.equal(result.delta, 0)
    assert.equal(result.windowedScore, 0)
    assert.equal(result.cumulativeScore, rep.mu)
    assert.equal(result.observationsInWindow, 0)
    assert.equal(result.windowSize, 5)
    assert.equal(result.alert, null)
  })

  it('reputation with empty recentObservations array: same no-history result', () => {
    const rep = makeRepWithObservations({ recentObservations: [] })
    const result = computeReputationDrift(rep, 5)
    assert.equal(result.delta, 0)
    assert.equal(result.observationsInWindow, 0)
    assert.equal(result.alert, null)
  })
})

describe('computeReputationDrift — direction', () => {
  it('all-positive muDeltas: delta > 0, direction improving', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.5), obs(0.5), obs(0.5)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.delta, 1.5)
    assert.equal(result.windowedScore, 1.5)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(result.alert)
    assert.equal(result.alert!.direction, 'improving')
  })

  it('all-negative muDeltas: delta < 0, direction degrading', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(-0.5), obs(-0.5), obs(-0.5)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.delta, -1.5)
    assert.equal(result.windowedScore, -1.5)
    assert.ok(result.alert)
    assert.equal(result.alert!.direction, 'degrading')
  })

  it('mixed deltas summing to within threshold: direction stable, severity none', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.05), obs(-0.03), obs(0.02)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.ok(Math.abs(result.delta - 0.04) < 1e-9)
    assert.equal(result.alert, null)
  })
})

describe('computeReputationDrift — threshold boundaries', () => {
  it('exactly at warning threshold (delta = 0.15): severity warning', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.15)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.equal(result.delta, 0.15)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'warning')
    assert.equal(result.alert!.direction, 'stable', 'delta exactly equals threshold so direction is stable, not improving')
  })

  it('exactly at critical threshold (delta = 0.30): severity critical', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.30)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.equal(result.delta, 0.30)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
  })

  it('just below warning (delta = 0.149): severity none, alert null', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.149)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.equal(result.alert, null)
  })

  it('just above critical (delta = 0.31): severity critical', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.31)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
  })

  it('negative critical (delta = -0.40): severity critical, direction degrading', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(-0.40)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
    assert.equal(result.alert!.direction, 'degrading')
  })
})

describe('computeReputationDrift — severity escalates with |delta|', () => {
  it('|delta| growth from 0.10 → 0.20 → 0.40 walks through none → warning → critical', () => {
    const r1 = makeRepWithObservations({ recentObservations: [obs(0.10)] })
    const r2 = makeRepWithObservations({ recentObservations: [obs(0.20)] })
    const r3 = makeRepWithObservations({ recentObservations: [obs(0.40)] })

    assert.equal(computeReputationDrift(r1, 1).alert, null)
    assert.equal(computeReputationDrift(r2, 1).alert!.severity, 'warning')
    assert.equal(computeReputationDrift(r3, 1).alert!.severity, 'critical')
  })
})

describe('computeReputationDrift — window clamping', () => {
  it('observationsInWindow clamps to recentObservations.length when history is sparse', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.1), obs(0.1)],
    })
    const result = computeReputationDrift(rep, 10)
    assert.equal(result.windowSize, 10)
    assert.equal(result.observationsInWindow, 2, 'only 2 events available')
    assert.equal(result.delta, 0.2)
  })

  it('only the last windowSize events are summed when history is longer than the window', () => {
    const rep = makeRepWithObservations({
      recentObservations: [
        obs(1.0),
        obs(1.0),
        obs(-0.5),
        obs(-0.5),
        obs(-0.5),
      ],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(Math.abs(result.delta - (-1.5)) < 1e-9, `expected -1.5, got ${result.delta}`)
    assert.equal(result.alert!.severity, 'critical')
    assert.equal(result.alert!.direction, 'degrading')
  })

  it('windowSize equal to history length uses every event', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.1), obs(0.2), obs(0.3)],
    })
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(Math.abs(result.delta - 0.6) < 1e-9)
  })
})

describe('computeReputationDrift — custom thresholds', () => {
  it('tighter thresholds (0.05 / 0.10) trip earlier', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.07)],
    })
    const defaultResult = computeReputationDrift(rep, 1)
    assert.equal(defaultResult.alert, null)

    const customResult = computeReputationDrift(rep, 1, {
      warningThreshold: 0.05,
      criticalThreshold: 0.10,
    })
    assert.ok(customResult.alert)
    assert.equal(customResult.alert!.severity, 'warning')
    assert.equal(customResult.alert!.warningThreshold, 0.05)
    assert.equal(customResult.alert!.criticalThreshold, 0.10)
  })

  it('looser thresholds (0.50 / 1.00) suppress alerts that would fire under defaults', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.40)],
    })
    assert.equal(computeReputationDrift(rep, 1).alert!.severity, 'critical')
    assert.equal(
      computeReputationDrift(rep, 1, { warningThreshold: 0.50, criticalThreshold: 1.00 }).alert,
      null,
    )
  })
})

describe('computeReputationDrift — default thresholds (NexusGuard AIP v0.5.48)', () => {
  it('exported constants are 0.15 and 0.30', () => {
    assert.equal(DEFAULT_DRIFT_WARNING_THRESHOLD, 0.15)
    assert.equal(DEFAULT_DRIFT_CRITICAL_THRESHOLD, 0.30)
  })

  it('default thresholds in alert match the exported constants', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.20)],
    })
    const result = computeReputationDrift(rep, 1)
    assert.ok(result.alert)
    assert.equal(result.alert!.warningThreshold, 0.15)
    assert.equal(result.alert!.criticalThreshold, 0.30)
  })
})

describe('computeReputationDrift — invariants', () => {
  it('alert is null iff severity === none', () => {
    const cases = [
      { delta: 0.0, expectedAlert: false },
      { delta: 0.10, expectedAlert: false },
      { delta: 0.149, expectedAlert: false },
      { delta: 0.15, expectedAlert: true },
      { delta: 0.20, expectedAlert: true },
      { delta: 0.30, expectedAlert: true },
      { delta: 0.40, expectedAlert: true },
      { delta: -0.10, expectedAlert: false },
      { delta: -0.15, expectedAlert: true },
      { delta: -0.30, expectedAlert: true },
    ]
    for (const c of cases) {
      const rep = makeRepWithObservations({ recentObservations: [obs(c.delta)] })
      const result = computeReputationDrift(rep, 1)
      const hasAlert = result.alert !== null
      assert.equal(hasAlert, c.expectedAlert, `delta=${c.delta}: expected alert=${c.expectedAlert}, got ${hasAlert}`)
      if (hasAlert) {
        assert.notEqual(result.alert!.severity, 'none', 'when alert is non-null, severity must not be none')
      }
    }
  })

  it('does not mutate input reputation', () => {
    const rep = makeRepWithObservations({
      recentObservations: [obs(0.1), obs(0.2), obs(0.3)],
    })
    const beforeMu = rep.mu
    const beforeSigma = rep.sigma
    const beforeRecentLength = rep.recentObservations!.length
    const beforeRecentRef = rep.recentObservations

    computeReputationDrift(rep, 5)

    assert.equal(rep.mu, beforeMu)
    assert.equal(rep.sigma, beforeSigma)
    assert.equal(rep.recentObservations!.length, beforeRecentLength)
    assert.strictEqual(rep.recentObservations, beforeRecentRef, 'array reference unchanged')
  })
})

describe('updateReputationFromResult ring buffer + computeReputationDrift', () => {
  it('after 40 update calls, recentObservations.length === RECENT_OBSERVATIONS_CAP (FIFO eviction)', () => {
    let rep = makeFreshRep()
    for (let i = 0; i < 40; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', { principalHash: `p${i}` })
    }
    assert.equal(rep.recentObservations!.length, RECENT_OBSERVATIONS_CAP, `expected cap ${RECENT_OBSERVATIONS_CAP}, got ${rep.recentObservations!.length}`)
    assert.equal(RECENT_OBSERVATIONS_CAP, 30, 'sanity: cap default')
  })

  it('after 5 successful updates, drift sum equals (rep.mu - INITIAL_MU) within float tolerance', () => {
    let rep = makeFreshRep()
    const startMu = rep.mu
    for (let i = 0; i < 5; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', { principalHash: `p${i}` })
    }
    const muChange = rep.mu - startMu
    const result = computeReputationDrift(rep, 5)
    assert.equal(result.observationsInWindow, 5)
    assert.ok(
      Math.abs(result.delta - muChange) < 1e-9,
      `delta=${result.delta} should equal mu change=${muChange}`,
    )
    assert.ok(result.alert)
    assert.equal(result.alert!.severity, 'critical')
    assert.equal(result.alert!.direction, 'improving')
  })

  it('after 5 failed updates, drift is negative and direction is degrading', () => {
    let rep = makeFreshRep()
    const startMu = rep.mu
    for (let i = 0; i < 5; i++) {
      rep = updateReputationFromResult(rep, false, 'standard', { principalHash: `p${i}` })
    }
    const muChange = rep.mu - startMu
    const result = computeReputationDrift(rep, 5)
    assert.ok(muChange < 0, 'sanity: 5 failures should reduce mu')
    assert.ok(
      Math.abs(result.delta - muChange) < 1e-9,
      `delta=${result.delta} should equal mu change=${muChange}`,
    )
    assert.ok(result.alert)
    assert.equal(result.alert!.direction, 'degrading')
  })

  it('window of 3 only counts the last 3 events from a longer history', () => {
    let rep = makeFreshRep()
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, false, 'standard', { principalHash: `f${i}` })
    }
    const muAfterFailures = rep.mu
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, true, 'standard', { principalHash: `s${i}` })
    }
    const recentImprovement = rep.mu - muAfterFailures
    const result = computeReputationDrift(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.ok(
      Math.abs(result.delta - recentImprovement) < 1e-9,
      `windowed delta ${result.delta} should equal recent improvement ${recentImprovement}`,
    )
    assert.ok(result.delta > 0, 'window of last 3 should be improving (the successes)')
  })

  it('mu clamping is reflected in stored muDeltas (boundary case)', () => {
    let rep = makeFreshRep()
    for (let i = 0; i < 30; i++) {
      rep = updateReputationFromResult(rep, true, 'critical', { principalHash: `p${i}` })
    }
    assert.equal(rep.mu, 100, 'mu should be clamped at 100 after many critical successes')

    const lastObs = rep.recentObservations![rep.recentObservations!.length - 1]
    assert.equal(lastObs.muDelta, 0, 'effective muDelta at the clamp boundary is zero')

    const result = computeReputationDrift(rep, 5)
    assert.equal(result.delta, 0, 'at the clamp, recent drift is zero')
    assert.equal(result.alert, null)
  })
})

// ══════════════════════════════════════
// computeConsistencyScore (analytics)
// ══════════════════════════════════════

function repWithDeltas(muDeltas: number[]): ScopedReputation {
  const base = createScopedReputation('principal-1', 'agent-1', 'scope-a')
  const observations: ReputationObservation[] = muDeltas.map((delta, i) => ({
    timestamp: new Date(1_700_000_000_000 + i * 60_000).toISOString(),
    success: delta >= 0,
    evidenceClass: 'standard',
    muDelta: delta,
    sigmaDelta: 0,
  }))
  return { ...base, recentObservations: observations }
}

describe('computeConsistencyScore — no history', () => {
  it('undefined recentObservations → no_history, score=0', () => {
    const rep = createScopedReputation('p', 'a', 's')
    assert.equal(rep.recentObservations, undefined)
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'no_history')
    assert.equal(result.score, 0)
    assert.equal(result.stddev, 0)
    assert.equal(result.mean, 0)
    assert.equal(result.observationsInWindow, 0)
  })

  it('empty recentObservations → no_history, score=0', () => {
    const rep: ScopedReputation = {
      ...createScopedReputation('p', 'a', 's'),
      recentObservations: [],
    }
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'no_history')
    assert.equal(result.score, 0)
    assert.equal(result.observationsInWindow, 0)
  })
})

describe('computeConsistencyScore — insufficient data', () => {
  it('1 observation → insufficient_data, score=0.5', () => {
    const rep = repWithDeltas([1.0])
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'insufficient_data')
    assert.equal(result.score, 0.5)
    assert.equal(result.observationsInWindow, 1)
    assert.equal(result.stddev, 0)
    assert.equal(result.mean, 1.0)
  })

  it('2 observations → insufficient_data, score=0.5', () => {
    const rep = repWithDeltas([1.0, 2.0])
    const result = computeConsistencyScore(rep)
    assert.equal(result.classification, 'insufficient_data')
    assert.equal(result.score, 0.5)
    assert.equal(result.observationsInWindow, 2)
    assert.equal(result.mean, 1.5)
    assert.ok(result.stddev > 0)
  })
})

describe('computeConsistencyScore — classification', () => {
  it('3 identical muDeltas → stddev=0, score=1.0, highly_consistent', () => {
    const rep = repWithDeltas([1.0, 1.0, 1.0])
    const result = computeConsistencyScore(rep)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
    assert.equal(result.classification, 'highly_consistent')
    assert.equal(result.mean, 1.0)
  })

  it('small variance → highly_consistent (stddev < 0.5)', () => {
    const rep = repWithDeltas([0.9, 1.0, 1.1])
    const result = computeConsistencyScore(rep)
    assert.ok(result.stddev < 0.5)
    assert.equal(result.classification, 'highly_consistent')
    assert.ok(result.score > 0.5)
  })

  it('medium variance → moderately_consistent (0.5 ≤ stddev < 1.5)', () => {
    const rep = repWithDeltas([0, 1, 2])
    const result = computeConsistencyScore(rep)
    assert.ok(result.stddev >= 0.5 && result.stddev < 1.5)
    assert.equal(result.classification, 'moderately_consistent')
  })

  it('large variance → inconsistent (stddev ≥ 1.5)', () => {
    const rep = repWithDeltas([3, -3, 3, -3, 3])
    const result = computeConsistencyScore(rep)
    assert.ok(result.stddev >= 1.5)
    assert.equal(result.classification, 'inconsistent')
    assert.ok(result.score < 0.5)
  })
})

describe('computeConsistencyScore — direction independence', () => {
  it('[-1,-1,-1] and [1,1,1] produce the same score', () => {
    const neg = computeConsistencyScore(repWithDeltas([-1, -1, -1]))
    const pos = computeConsistencyScore(repWithDeltas([1, 1, 1]))
    assert.equal(neg.score, pos.score)
    assert.equal(neg.stddev, pos.stddev)
    assert.equal(neg.classification, pos.classification)
    assert.equal(neg.mean, -1)
    assert.equal(pos.mean, 1)
  })
})

describe('computeConsistencyScore — §6.5 over-promiser paradox', () => {
  it('over-promiser: [-0.5, -0.5, -0.5, -0.5, -0.5] → highly_consistent, score=1.0', () => {
    const overPromiser = computeConsistencyScore(
      repWithDeltas([-0.5, -0.5, -0.5, -0.5, -0.5]),
    )
    assert.equal(overPromiser.stddev, 0)
    assert.equal(overPromiser.score, 1.0)
    assert.equal(overPromiser.classification, 'highly_consistent')
    assert.equal(overPromiser.mean, -0.5)
  })

  it('environment-sensitive: [3, -3, 3, -3, 3] → inconsistent, low score', () => {
    const envSensitive = computeConsistencyScore(
      repWithDeltas([3, -3, 3, -3, 3]),
    )
    assert.ok(envSensitive.stddev >= 1.5)
    assert.equal(envSensitive.classification, 'inconsistent')
    assert.ok(envSensitive.score < 0.5)
  })

  it('REGRESSION: over-promiser score > environment-sensitive score', () => {
    const overPromiser = computeConsistencyScore(
      repWithDeltas([-0.5, -0.5, -0.5, -0.5, -0.5]),
    )
    const envSensitive = computeConsistencyScore(
      repWithDeltas([3, -3, 3, -3, 3]),
    )
    assert.ok(
      overPromiser.score > envSensitive.score,
      `over-promiser (${overPromiser.score}) must score higher than env-sensitive (${envSensitive.score})`,
    )
    assert.ok(envSensitive.mean > 0)
    assert.ok(overPromiser.mean < 0)
  })
})

describe('computeConsistencyScore — windowSize', () => {
  it('default windowSize uses all available observations', () => {
    const rep = repWithDeltas([1, 1, 1, 5, 5, 5])
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 6)
  })

  it('windowSize=3 on a 10-observation buffer uses only the last 3', () => {
    const rep = repWithDeltas([5, -5, 5, -5, 5, -5, 5, 2, 2, 2])
    const result = computeConsistencyScore(rep, 3)
    assert.equal(result.observationsInWindow, 3)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
    assert.equal(result.mean, 2)
    assert.equal(result.classification, 'highly_consistent')
  })

  it('windowSize larger than buffer clamps to buffer length', () => {
    const rep = repWithDeltas([1, 1, 1])
    const result = computeConsistencyScore(rep, 100)
    assert.equal(result.observationsInWindow, 3)
  })

  it('windowSize=1 returns insufficient_data', () => {
    const rep = repWithDeltas([1, 1, 1, 1, 1])
    const result = computeConsistencyScore(rep, 1)
    assert.equal(result.observationsInWindow, 1)
    assert.equal(result.classification, 'insufficient_data')
    assert.equal(result.score, 0.5)
  })
})

describe('computeConsistencyScore — numerical correctness', () => {
  it('mean matches arithmetic mean of window', () => {
    const rep = repWithDeltas([2, 4, 6])
    const result = computeConsistencyScore(rep)
    assert.equal(result.mean, 4)
  })

  it('mean is correctly signed for negative values', () => {
    const rep = repWithDeltas([-2, -4, -6])
    const result = computeConsistencyScore(rep)
    assert.equal(result.mean, -4)
  })

  it('stddev matches expected value within float tolerance', () => {
    const rep = repWithDeltas([1, 2, 3, 4, 5])
    const result = computeConsistencyScore(rep)
    assert.ok(Math.abs(result.stddev - Math.sqrt(2)) < 1e-9)
    assert.equal(result.mean, 3)
  })

  it('score formula: stddev=0 → 1.0', () => {
    const rep = repWithDeltas([2, 2, 2])
    const result = computeConsistencyScore(rep)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
  })

  it('score formula: stddev=1 → 0.5', () => {
    const offset = Math.sqrt(1.5)
    const rep = repWithDeltas([10 - offset, 10, 10 + offset])
    const result = computeConsistencyScore(rep)
    assert.ok(Math.abs(result.stddev - 1) < 1e-9, `stddev was ${result.stddev}`)
    assert.ok(Math.abs(result.score - 0.5) < 1e-9, `score was ${result.score}`)
  })

  it('score is monotonically decreasing in stddev', () => {
    const low = computeConsistencyScore(repWithDeltas([1, 1.1, 0.9]))
    const mid = computeConsistencyScore(repWithDeltas([0, 1, 2]))
    const high = computeConsistencyScore(repWithDeltas([-3, 0, 3]))
    assert.ok(low.score > mid.score)
    assert.ok(mid.score > high.score)
    assert.ok(low.stddev < mid.stddev)
    assert.ok(mid.stddev < high.stddev)
  })
})

describe('computeConsistencyScore — purity', () => {
  it('does not mutate the input reputation', () => {
    const rep = repWithDeltas([1, 2, 3, 4, 5])
    const snapshot = JSON.stringify(rep)
    computeConsistencyScore(rep)
    assert.equal(JSON.stringify(rep), snapshot)
  })

  it('does not mutate the recentObservations array', () => {
    const rep = repWithDeltas([1, 2, 3])
    const originalLength = rep.recentObservations!.length
    const originalFirst = rep.recentObservations![0].muDelta
    computeConsistencyScore(rep, 2)
    assert.equal(rep.recentObservations!.length, originalLength)
    assert.equal(rep.recentObservations![0].muDelta, originalFirst)
  })
})

describe('computeConsistencyScore — integration with updateReputationFromResult', () => {
  it('window reflects the actual ring buffer state after several updates', () => {
    let rep = createScopedReputation('p', 'a', 's')
    for (let i = 0; i < 5; i++) {
      rep = updateReputationFromResult(rep, true, 'standard')
    }
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 5)
    assert.equal(result.stddev, 0)
    assert.equal(result.score, 1.0)
    assert.equal(result.classification, 'highly_consistent')
  })

  it('mixing critical success + trivial failure produces high variance', () => {
    let rep = createScopedReputation('p', 'a', 's')
    rep = updateReputationFromResult(rep, true, 'critical')
    rep = updateReputationFromResult(rep, false, 'critical')
    rep = updateReputationFromResult(rep, true, 'critical')
    rep = updateReputationFromResult(rep, false, 'critical')
    rep = updateReputationFromResult(rep, true, 'critical')
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 5)
    assert.ok(result.stddev >= 1.5, `stddev was ${result.stddev}`)
    assert.equal(result.classification, 'inconsistent')
  })

  it('a sequence of standard successes then failures produces measurable variance', () => {
    let rep = createScopedReputation('p', 'a', 's')
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, true, 'standard')
    }
    for (let i = 0; i < 3; i++) {
      rep = updateReputationFromResult(rep, false, 'standard')
    }
    const result = computeConsistencyScore(rep)
    assert.equal(result.observationsInWindow, 6)
    assert.ok(result.stddev > 1.4 && result.stddev < 1.6)
  })
})
