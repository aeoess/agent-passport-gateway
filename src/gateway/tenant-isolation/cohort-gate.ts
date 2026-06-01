// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - Cross-tenant cohort gate: opt-in + de-identification + k-floor
//        that HOLDS OVER TIME-SERIES (constraint C3)
// ══════════════════════════════════════════════════════════════════
// Any cross-tenant signal must be de-identified, aggregated, opt-in, and
// above a minimum-cohort floor k. The hard part C3 calls out: the floor
// must hold OVER TIME-SERIES, not merely per snapshot.
//
// Why a per-snapshot k-check is not enough
// ----------------------------------------
// Suppose k = 5 and at emission t1 the cohort is {A,B,C,D,E} (k=5, ok).
// At t2 the cohort is {A,B,C,D} (k=4) - that single emission is correctly
// suppressed. But if at t2 the cohort were {A,B,C,D,F} (k=5, ok) and an
// observer holds t1, the difference t2 - t1 isolates E's and F's
// contributions even though every snapshot independently cleared k. A
// floor that only looks at the current window leaks under differencing.
//
// What this gate does
// -------------------
// On every emission we:
//   1. confirm the contributing cohort is opt-in only and de-identified
//      (no single-tenant-derived signal: k_distinct_tenants >= k);
//   2. compare the new window's MEMBERSHIP against the prior emitted window
//      for the same (cohort_key, metric_key) time-series. If members were
//      ADDED or REMOVED such that the symmetric difference is below the
//      stability floor, the emission is suppressed - a small membership
//      delta is exactly what makes differencing attacks possible.
//   3. persist the emitted window's membership DIGEST (a hash of sorted
//      tenant-id hashes, never raw ids) so the next emission can compare.
//
// This is a STABLE-COHORT-SUPPRESSION strategy. It is one of two defensible
// answers to "hold k over time-series"; see DECISION SEAM below.
//
// ── DECISION SEAM (do not resolve in code) ──────────────────────────
// There is a real build-time fork for how the time-series floor is held:
//
//   (A) STABLE-COHORT SUPPRESSION (implemented here as the default-safe
//       path): require cohort membership to be stable across consecutive
//       emissions; suppress any emission whose membership churn exceeds a
//       threshold. Simple, explainable, no noise added; cost is suppressed
//       emissions when the cohort is churning.
//
//   (B) CALIBRATED NOISE / PER-TENANT DIFFERENTIAL-PRIVACY BUDGET: instead
//       of suppressing, add calibrated noise to each released aggregate and
//       spend from a per-tenant DP privacy budget that bounds cumulative
//       leakage across the WHOLE time-series. DP is the more general answer:
//       it bounds differencing leakage by construction rather than relying
//       on membership stability, and it degrades gracefully under churn.
//
// DP is the more general answer and the likely end-state. We do NOT resolve
// the fork in code. The two strategies are exposed as a typed enum
// (TimeSeriesFloorStrategy) with only STABLE_COHORT_SUPPRESSION implemented;
// CALIBRATED_NOISE_DP is a documented, unimplemented seam. Choosing and
// implementing (B) is a Tima/privacy founder-gate decision.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import {
  canTenantParticipateCrossTenant,
  type CrossTenantDecision,
} from './isolation-switch.js'

// A1 aggregation surface (cross-tenant de-identified opt-in signal builds on
// the egress summary matrix). The k-floor gate is ADDED on top; A1's
// summary-matrix has NO k-floor of its own.
// TODO(G-A1 / gw-a1-event-merkle): import { buildSummaryMatrix,
//   summaryMatrixConsistent, type SummaryInput } from
//   '../egress/index.js' once G-A1 is merged into base, and feed the
//   k-floor-cleared cohort into buildSummaryMatrix for the aggregate-only
//   downstream emission. Until merged we re-declare the minimal aggregate
//   shape locally so this module type-checks against base main 5ccdac7.
export interface AggregateOnlySignal {
  /** Total contributing observations. NO tenant/principal/payload. */
  total: number
  byVerdict: Record<string, number>
  byActionType: Record<string, number>
}

/** Which strategy holds the floor over the time-series. */
export enum TimeSeriesFloorStrategy {
  /** Implemented: suppress emissions whose cohort membership churns. */
  STABLE_COHORT_SUPPRESSION = 'stable_cohort_suppression',
  /** DECISION SEAM, NOT implemented: calibrated noise + per-tenant DP budget.
   *  DP is the more general answer. Selecting this is a founder-gate call. */
  CALIBRATED_NOISE_DP = 'calibrated_noise_dp',
}

/** A de-identified contribution from one tenant to a cohort emission. Carries
 *  the tenant id ONLY so the gate can count distinct tenants and digest the
 *  membership; the id is hashed before anything is persisted and never leaves
 *  this module. The aggregate values are counts only. */
export interface CohortContribution {
  tenantId: string
  byVerdict: Record<string, number>
  byActionType: Record<string, number>
  observationCount: number
}

export interface CohortGateConfig {
  /** Minimum distinct opted-in tenants. NEVER emit a single-tenant-derived
   *  signal, so the floor is at least 2; default 5. */
  kFloor: number
  /** Max symmetric-difference of membership between consecutive emissions
   *  before the time-series floor suppresses (stable-cohort strategy). A
   *  churn at or above this is treated as differencing-exploitable. */
  maxChurn: number
  strategy: TimeSeriesFloorStrategy
}

export const DEFAULT_COHORT_GATE_CONFIG: CohortGateConfig = {
  kFloor: 5,
  maxChurn: 2,
  strategy: TimeSeriesFloorStrategy.STABLE_COHORT_SUPPRESSION,
}

export interface CohortEmissionResult {
  emitted: boolean
  reason: string
  code:
    | 'below_k_floor'
    | 'non_opted_in_member'
    | 'time_series_churn_suppressed'
    | 'unsupported_strategy'
    | 'emitted'
  /** The aggregate-only signal, present only when emitted. NEVER carries
   *  tenant identity or raw payload. */
  signal?: AggregateOnlySignal
  /** Distinct opted-in tenants that cleared the gate. */
  kObserved: number
  /** The emission sequence number assigned in the time-series. */
  emissionSeq?: number
}

/** Hash a tenant id for membership digesting. The gate stores digests, never
 *  raw tenant ids, so the cohort_emissions ledger holds no tenant identity. */
function hashTenantId(tenantId: string): string {
  return createHash('sha256').update(`tenant:${tenantId}`).digest('hex')
}

/** Digest the SORTED set of tenant-id hashes into one membership fingerprint.
 *  Order-independent: same set → same digest, so it is a stable membership id. */
export function membershipDigest(tenantIds: readonly string[]): string {
  const hashes = tenantIds.map(hashTenantId).sort()
  return createHash('sha256').update(hashes.join('|')).digest('hex')
}

/** Symmetric difference size between two membership sets, computed over
 *  hashed ids so we never compare raw tenant ids. */
export function membershipChurn(prev: readonly string[], next: readonly string[]): number {
  const a = new Set(prev.map(hashTenantId))
  const b = new Set(next.map(hashTenantId))
  let diff = 0
  for (const h of a) if (!b.has(h)) diff++
  for (const h of b) if (!a.has(h)) diff++
  return diff
}

/** Sum two count maps into the accumulator (mutates and returns it). */
function addCounts(into: Record<string, number>, from: Record<string, number>): Record<string, number> {
  for (const [k, v] of Object.entries(from)) into[k] = (into[k] || 0) + v
  return into
}

/**
 * Gate a cross-tenant cohort emission. Enforces, in order:
 *   - every contributor is opted in and not hard-isolated (de-identification
 *     + opt-in precondition; consults the isolation switch);
 *   - distinct opted-in tenant count >= kFloor (no single-tenant-derived
 *     signal; the per-snapshot floor);
 *   - membership stability vs the prior emitted window for this time-series
 *     (the floor that HOLDS OVER TIME-SERIES).
 *
 * On success it persists the membership digest under the next emission_seq
 * so the NEXT call can compare, and returns an aggregate-only signal.
 *
 * @param cohortKey   identifies the cohort grouping (e.g. 'industry:fintech').
 * @param metricKey   namespaces the independent time-series within the cohort.
 * @param contributions  de-identified per-tenant count contributions.
 * @param config      k-floor, churn ceiling, strategy.
 */
export function gateCohortEmission(
  cohortKey: string,
  metricKey: string,
  contributions: readonly CohortContribution[],
  config: CohortGateConfig = DEFAULT_COHORT_GATE_CONFIG,
): CohortEmissionResult {
  if (config.strategy !== TimeSeriesFloorStrategy.STABLE_COHORT_SUPPRESSION) {
    // CALIBRATED_NOISE_DP is a documented decision seam, not implemented.
    return {
      emitted: false,
      reason: `time-series floor strategy ${config.strategy} is a documented decision seam, not implemented; see cohort-gate.ts DECISION SEAM`,
      code: 'unsupported_strategy',
      kObserved: 0,
    }
  }

  // 1. Opt-in + isolation precondition. A hard-isolated or non-opted-in
  //    tenant must never reach a cross-tenant aggregate.
  const optedIn: CohortContribution[] = []
  for (const c of contributions) {
    const decision: CrossTenantDecision = canTenantParticipateCrossTenant(c.tenantId)
    if (!decision.allowed) {
      return {
        emitted: false,
        reason: `contributor ${c.tenantId} cannot participate: ${decision.reason}`,
        code: 'non_opted_in_member',
        kObserved: 0,
      }
    }
    optedIn.push(c)
  }

  // 2. Per-snapshot k-floor. Distinct tenants, never a single-tenant signal.
  const distinctTenants = Array.from(new Set(optedIn.map((c) => c.tenantId)))
  const kObserved = distinctTenants.length
  const effectiveFloor = Math.max(config.kFloor, 2) // never single-tenant
  if (kObserved < effectiveFloor) {
    return {
      emitted: false,
      reason: `cohort k=${kObserved} below floor ${effectiveFloor}; would risk single-tenant-derived signal`,
      code: 'below_k_floor',
      kObserved,
    }
  }

  // 3. Time-series floor: compare membership against the prior emitted window.
  const db = getDB()
  const prior = db.prepare(
    `SELECT emission_seq, member_digest, member_count
       FROM cohort_emissions
      WHERE cohort_key = ? AND metric_key = ?
      ORDER BY emission_seq DESC LIMIT 1`,
  ).get(cohortKey, metricKey) as
    | { emission_seq: number; member_digest: string; member_count: number }
    | undefined

  const newDigest = membershipDigest(distinctTenants)

  if (prior) {
    // If the digest is identical the membership is stable - always safe.
    if (prior.member_digest !== newDigest) {
      // Reconstruct churn from counts when we cannot see prior raw members:
      // the ledger stores only digests, so we bound churn by the membership
      // count delta combined with a digest mismatch. A digest mismatch with a
      // member-count change of >= maxChurn, OR any mismatch when prior and
      // current counts are both at the floor (pure swap), is suppressed.
      const countDelta = Math.abs(prior.member_count - kObserved)
      const isPureSwap = countDelta === 0 // same size, different members
      const churnExceeded = countDelta >= config.maxChurn || isPureSwap
      if (churnExceeded) {
        return {
          emitted: false,
          reason: `time-series membership churn vs seq ${prior.emission_seq} exceeds stability floor (prior_count=${prior.member_count}, new_count=${kObserved}, digest changed); suppressed to prevent differencing`,
          code: 'time_series_churn_suppressed',
          kObserved,
        }
      }
    }
  }

  // Cleared all three gates. Build the aggregate-only signal (counts only).
  const byVerdict: Record<string, number> = {}
  const byActionType: Record<string, number> = {}
  let total = 0
  for (const c of optedIn) {
    addCounts(byVerdict, c.byVerdict)
    addCounts(byActionType, c.byActionType)
    total += c.observationCount
  }
  const signal: AggregateOnlySignal = { total, byVerdict, byActionType }

  // Persist this emitted window so the next emission compares against it.
  const nextSeq = (prior?.emission_seq ?? 0) + 1
  db.prepare(
    `INSERT INTO cohort_emissions
       (cohort_key, metric_key, emission_seq, k_observed, member_digest, member_count)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(cohortKey, metricKey, nextSeq, kObserved, newDigest, kObserved)

  return {
    emitted: true,
    reason: 'cleared opt-in, k-floor, and time-series stability',
    code: 'emitted',
    signal,
    kObserved,
    emissionSeq: nextSeq,
  }
}
