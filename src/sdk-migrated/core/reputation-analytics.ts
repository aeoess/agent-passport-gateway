// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Reputation Analytics — Drift, Consistency, Promotion Workflow
// ══════════════════════════════════════════════════════════════════
// Migrated from agent-passport-system/src/core/reputation-authority.ts
// (2026-04-17). The SDK retains the Bayesian math, tier definitions,
// and pure primitives (computeEffectiveScore, updateReputationFromResult,
// validatePromotionReview, applyTemporalDecay, confidenceBreakdown).
// The gateway takes the product intelligence:
//
//   - Sliding-window drift detection with severity-graded alerts
//   - Consistency (predictability) scoring from the ring buffer
//   - Signed promotion review creation (workflow, not primitive)
//   - Demotion trigger workflow
//
// These functions are analytics or workflow — they encode thresholds
// and policy that live outside the protocol and belong in the gateway's
// product layer.
// ══════════════════════════════════════════════════════════════════

import { randomBytes } from 'node:crypto'
import { canonicalize, sign } from 'agent-passport-system'
import type {
  ScopedReputation,
  EvidencePortfolio,
  PromotionReview,
  TierOrigin,
  DemotionCause,
  DemotionEvent,
} from 'agent-passport-system'

// ══════════════════════════════════════
// Promotion Reviews (workflow)
// ══════════════════════════════════════

/**
 * Create a signed promotion review.
 * The reviewer cryptographically commits: "I reviewed this agent's
 * evidence and approve/deny their promotion to tier X."
 *
 * Enforces: reviewer must be Earned (not Fiat), reviewer tier > target tier,
 * no self-promotion.
 *
 * Pair with `validatePromotionReview` from the SDK for verification —
 * creation is workflow (lives here), validation is pure crypto (lives in
 * the SDK as a primitive).
 */
export function createPromotionReview(opts: {
  agentId: string
  principalId: string
  scope: string
  fromTier: number
  toTier: number
  reviewerId: string
  reviewerTier: number
  reviewerOrigin: TierOrigin
  evidence: EvidencePortfolio
  effectiveScore: number
  verdict: 'promoted' | 'denied'
  reasoning: string
  reviewerPrivateKey: string
  probationDays?: number
}): PromotionReview {
  // Validation: only Earned agents can promote
  if (opts.reviewerOrigin !== 'earned') {
    throw new Error(
      `Reviewer origin is '${opts.reviewerOrigin}' — only 'earned' agents can approve promotions. ` +
      'Fiat and provisional agents lack the operational track record to evaluate others.'
    )
  }

  // Validation: reviewer must be above target tier
  if (opts.reviewerTier <= opts.toTier) {
    throw new Error(
      `Reviewer tier ${opts.reviewerTier} is not above target tier ${opts.toTier}. ` +
      'Agents can only approve promotions to tiers below their own.'
    )
  }

  // Validation: no self-promotion
  if (opts.reviewerId === opts.agentId) {
    throw new Error('Self-promotion is not allowed. A different agent or human must review.')
  }

  const now = new Date()
  const probationEnd = opts.verdict === 'promoted' && opts.probationDays !== 0
    ? new Date(now.getTime() + (opts.probationDays ?? 7) * 24 * 60 * 60 * 1000).toISOString()
    : undefined

  const payload: Omit<PromotionReview, 'signature'> = {
    reviewId: `promo-${randomBytes(8).toString('hex')}`,
    agentId: opts.agentId,
    principalId: opts.principalId,
    scope: opts.scope,
    fromTier: opts.fromTier,
    toTier: opts.toTier,
    reviewerId: opts.reviewerId,
    reviewerTier: opts.reviewerTier,
    reviewerOrigin: opts.reviewerOrigin,
    evidence: opts.evidence,
    effectiveScore: opts.effectiveScore,
    verdict: opts.verdict,
    reasoning: opts.reasoning,
    probationEndsAt: probationEnd,
    timestamp: now.toISOString(),
  }

  const signature = sign(canonicalize(payload), opts.reviewerPrivateKey)
  return { ...payload, signature }
}

// ══════════════════════════════════════
// Demotion (workflow)
// ══════════════════════════════════════

/**
 * Create a demotion event. Only behavioral demotions affect reputation.
 * Administrative (policy change, delegation expired) and environmental
 * (upstream revocation) demotions restrict authority but preserve reputation.
 */
export function triggerDemotion(opts: {
  agentId: string
  principalId: string
  scope: string
  currentTier: number
  cause: DemotionCause
  reason: string
}): DemotionEvent {
  const toTier = Math.max(0, opts.currentTier - 1)

  return {
    agentId: opts.agentId,
    principalId: opts.principalId,
    scope: opts.scope,
    fromTier: opts.currentTier,
    toTier,
    cause: opts.cause,
    reason: opts.reason,
    timestamp: new Date().toISOString(),
    affectsReputation: opts.cause === 'behavioral',
  }
}

// ══════════════════════════════════════
// Sliding Window Drift Detection
// Reference: Nanook PDR v2.19 §6.6, gap audit §3 row 8 / §5 rank 3.
//
// Rests on the recentObservations ring buffer maintained by
// updateReputationFromResult (SDK). The cumulative score is rep.mu (the
// running Bayesian aggregate). The windowed score reflects what the
// agent's recent behavior has done to mu — specifically, the sum of
// effective muDeltas across the last N observations. delta =
// sum(recent muDeltas) is signed: positive means recent events pushed
// mu up (improving), negative means down (degrading).
// ══════════════════════════════════════

/** Severity-graded drift alert. Null when severity === 'none'.
 *
 *  Default thresholds (0.15 warning / 0.30 critical) match NexusGuard AIP
 *  v0.5.48 — the implementation Nanook PDR v2.19 §6.6 references — for
 *  cross-system interop. They are NOT scientifically calibrated. Callers
 *  should override for their own deployments based on the variance profile
 *  of their fleet. */
export interface DriftAlert {
  severity: 'none' | 'warning' | 'critical'
  /** Signed delta. Positive = improving, negative = degrading. Same units as mu (0-100). */
  delta: number
  warningThreshold: number
  criticalThreshold: number
  direction: 'improving' | 'degrading' | 'stable'
  /** Short, actionable recommendation tied to severity + direction. */
  recommendation: string
}

/** Result of computeReputationDrift. The cumulative side is the running mu;
 *  the windowed side is the sum of effective muDeltas across the last N
 *  observations from the ring buffer. */
export interface ReputationDrift {
  /** Current cumulative mu (the running Bayesian aggregate). */
  cumulativeScore: number
  /** Sum of effective muDeltas across the last `observationsInWindow` events. */
  windowedScore: number
  /** Signed: positive = recent events pushed mu up; negative = pushed mu down. */
  delta: number
  /** The window size requested by the caller. */
  windowSize: number
  /** Actual number of observations the function used. */
  observationsInWindow: number
  /** Null when severity === 'none', otherwise the full alert. */
  alert: DriftAlert | null
}

/** Default thresholds matching NexusGuard AIP v0.5.48 (Nanook PDR v2.19 §6.6). */
export const DEFAULT_DRIFT_WARNING_THRESHOLD = 0.15
export const DEFAULT_DRIFT_CRITICAL_THRESHOLD = 0.30

/**
 * Compute sliding window drift on a ScopedReputation by reading the
 * recentObservations ring buffer and summing effective muDeltas across
 * the last `windowSize` events.
 *
 * Backward compatibility: when `rep.recentObservations` is undefined or
 * empty, returns a "no history available" early result with delta=0,
 * severity=none, alert=null. Callers can detect the no-history case by
 * checking `observationsInWindow === 0`.
 *
 * Default thresholds (0.15 / 0.30) match NexusGuard AIP v0.5.48 for
 * interop. Override per deployment based on the variance profile of
 * your fleet — these defaults are interop-friendly, not scientifically
 * calibrated.
 *
 * Reference: Nanook PDR v2.19 §6.6, gap audit §3 row 8 / §5 rank 3.
 */
export function computeReputationDrift(
  rep: ScopedReputation,
  windowSize: number,
  opts?: {
    warningThreshold?: number
    criticalThreshold?: number
  },
): ReputationDrift {
  const warningThreshold = opts?.warningThreshold ?? DEFAULT_DRIFT_WARNING_THRESHOLD
  const criticalThreshold = opts?.criticalThreshold ?? DEFAULT_DRIFT_CRITICAL_THRESHOLD
  const cumulativeScore = rep.mu

  // Backward-compat early return: no history available.
  const recent = rep.recentObservations
  if (!recent || recent.length === 0) {
    return {
      cumulativeScore,
      windowedScore: 0,
      delta: 0,
      windowSize,
      observationsInWindow: 0,
      alert: null,
    }
  }

  // Take the last min(windowSize, recent.length) entries. The ring buffer
  // is ordered oldest-to-newest, so slice from the tail.
  const observationsInWindow = Math.min(windowSize, recent.length)
  const windowSlice = recent.slice(recent.length - observationsInWindow)

  // delta = sum of effective muDeltas across the window.
  const delta = windowSlice.reduce((acc, obs) => acc + obs.muDelta, 0)
  const windowedScore = delta

  const absDelta = Math.abs(delta)
  let severity: 'none' | 'warning' | 'critical'
  if (absDelta >= criticalThreshold) severity = 'critical'
  else if (absDelta >= warningThreshold) severity = 'warning'
  else severity = 'none'

  let direction: 'improving' | 'degrading' | 'stable'
  if (delta > warningThreshold) direction = 'improving'
  else if (delta < -warningThreshold) direction = 'degrading'
  else direction = 'stable'

  let alert: DriftAlert | null = null
  if (severity !== 'none') {
    alert = {
      severity,
      delta,
      warningThreshold,
      criticalThreshold,
      direction,
      recommendation: buildDriftRecommendation(severity, direction),
    }
  }

  return {
    cumulativeScore,
    windowedScore,
    delta,
    windowSize,
    observationsInWindow,
    alert,
  }
}

/** Static recommendation text per severity + direction combination. */
function buildDriftRecommendation(
  severity: 'warning' | 'critical',
  direction: 'improving' | 'degrading' | 'stable',
): string {
  if (direction === 'improving') {
    return severity === 'critical'
      ? 'Recent reputation gain is large. Consider whether the rapid improvement is real evidence or a small-window artifact before promoting authority.'
      : 'Recent reputation gain is meaningful. Continue monitoring; promotion may be appropriate after window stabilizes.'
  }
  if (direction === 'degrading') {
    return severity === 'critical'
      ? 'Recent reputation loss is severe. Restrict authority and investigate root cause before allowing further high-stakes actions.'
      : 'Recent reputation loss is meaningful. Watch the next several events; consider narrowing scope if the trend continues.'
  }
  return 'Reputation drift crossed alert threshold without a clear directional signal. Review recent events.'
}

// ══════════════════════════════════════════════════════════════════
// Consistency Score — Predictability as a Separate Primitive
// ══════════════════════════════════════════════════════════════════
// Reference: Nanook PDR v2.19 §6.5 over-promiser robustness paradox,
// gap audit §3 row 21 / §5 rank 6.
//
// Nanook §6.5 surfaces a counterintuitive finding: chronic over-promisers
// score higher on NexusGuard's Robustness measure than environment-
// sensitive agents because Robustness measures condition-based variance
// and a consistent over-promiser has low variance. Predictability and
// performance are orthogonal axes.
// ══════════════════════════════════════════════════════════════════

/** A dedicated predictability primitive surfaced from the recent
 *  observations ring buffer. Orthogonal to performance. */
export interface ConsistencyScore {
  /** 0-1 score. 1.0 = perfectly consistent; 0.0 = maximally inconsistent. */
  score: number
  /** Standard deviation of muDelta across the window. Lower = more consistent. */
  stddev: number
  /** Mean muDelta across the window (signed; informational). */
  mean: number
  /** Number of observations used. */
  observationsInWindow: number
  /** Classification for callers that want a discrete signal. */
  classification:
    | 'no_history'
    | 'insufficient_data'
    | 'highly_consistent'
    | 'moderately_consistent'
    | 'inconsistent'
}

/**
 * Compute a consistency (predictability) score from a ScopedReputation's
 * recent observations ring buffer. Orthogonal to performance.
 *
 * Reads rep.recentObservations (populated by updateReputationFromResult
 * in the SDK). Computes stddev of muDelta across the window, then maps
 * to a (0, 1] score via 1 / (1 + stddev).
 *
 * Reference: Nanook PDR v2.19 §6.5, gap audit §5 rank 6.
 */
export function computeConsistencyScore(
  rep: ScopedReputation,
  windowSize?: number,
): ConsistencyScore {
  const recent = rep.recentObservations

  // No history at all: return a neutral-zero, clearly labelled.
  if (!recent || recent.length === 0) {
    return {
      score: 0,
      stddev: 0,
      mean: 0,
      observationsInWindow: 0,
      classification: 'no_history',
    }
  }

  // Take the tail of the ring buffer. Buffer is ordered oldest → newest.
  const effectiveWindow = Math.min(windowSize ?? Infinity, recent.length)
  const windowSlice = recent.slice(recent.length - effectiveWindow)
  const observationsInWindow = windowSlice.length

  // Mean of muDelta across the window (signed; informational only).
  const sum = windowSlice.reduce((acc, obs) => acc + obs.muDelta, 0)
  const mean = sum / observationsInWindow

  // Population variance (divide by N, not N-1).
  const varianceSum = windowSlice.reduce(
    (acc, obs) => acc + (obs.muDelta - mean) ** 2,
    0,
  )
  const variance = varianceSum / observationsInWindow
  const stddev = Math.sqrt(variance)

  // Fewer than 3 observations is not enough to measure variance meaningfully.
  if (observationsInWindow < 3) {
    return {
      score: 0.5,
      stddev,
      mean,
      observationsInWindow,
      classification: 'insufficient_data',
    }
  }

  // Score: 1 / (1 + stddev). Monotonic decreasing, bounded, no calibration.
  const score = 1 / (1 + stddev)

  // Discrete classification thresholds aligned with REPUTATION_UPDATES magnitudes.
  let classification: ConsistencyScore['classification']
  if (stddev < 0.5) classification = 'highly_consistent'
  else if (stddev < 1.5) classification = 'moderately_consistent'
  else classification = 'inconsistent'

  return {
    score,
    stddev,
    mean,
    observationsInWindow,
    classification,
  }
}
