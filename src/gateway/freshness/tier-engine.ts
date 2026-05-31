// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Risk-tiered freshness contracts (G-B3).
 *
 * Per-action RISK TIER sets the freshness window and the fail behavior, not
 * one global mode. The customer supplies the freshness evidence descriptor
 * (an `AttestationFreshness` record produced at the edge - a SPIFFE SVID, a
 * TPM quote, a rotating JWT). The gateway does NOT mint or own that evidence:
 * it observes the staleness the descriptor reports and applies the fail
 * behavior the action's tier dictates. Trust stays at the edge; the gateway
 * checks-before and records.
 *
 * Tier ladder (per the build spec):
 *   Tier 0 (read-only)                       - allow; record the stale check
 *   Tier 1 (internal write)                  - warn; require approval if stale
 *   Tier 2 (external or sensitive)           - deny if stale
 *   Tier 3 (money, secrets, production deploy) - fail closed always
 *
 * Freshness EVALUATION is consumed from the SDK (`isEvidenceFresh`,
 * `computeEvidenceAge`). This module never reimplements the freshness math -
 * it consumes the SDK semantics: rotating → age < ttl (missing ttl => not
 * fresh); snapshot → age < maxAge (missing maxAge => fresh); static → always
 * fresh.
 */

import type { AttestationFreshness } from 'agent-passport-system'

/** Local alias for the SDK freshness descriptor shape (re-exported for callers). */
export type AttestationFreshnessLike = AttestationFreshness

export type RiskTier = 0 | 1 | 2 | 3

/** Outcome a tier produces for an action, given the observed staleness. */
export type FreshnessOutcome =
  | 'allow'              // proceed; the staleness was recorded
  | 'warn'              // proceed, but the staleness is flagged for the trail
  | 'require_approval'  // hold pending a human/escalation approval
  | 'deny'              // refuse this action
  | 'fail_closed'       // refuse regardless of freshness (tier 3 default posture)

export interface FreshnessTierResult {
  /** The tier this action class resolved to. */
  tier: RiskTier
  /** What the gateway should do for this action given the freshness it saw. */
  outcome: FreshnessOutcome
  /** True when the tier's outcome blocks the action (deny / fail_closed / require_approval). */
  blocks: boolean
  /**
   * Whether the supplied evidence was fresh for its type, per the SDK.
   * `null` when no freshness evidence was supplied (no descriptor to evaluate).
   */
  fresh: boolean | null
  /** Observed evidence age in seconds (per the SDK), or null when no evidence supplied. */
  ageSeconds: number | null
  /** Stable code recorded in the receipt / evaluation reason. */
  reasonCode: string
  /** Human-readable, claims-safe explanation suitable for the audit trail. */
  detail: string
}

/**
 * Default action-class → tier mapping. Keyed on the task class (the first
 * `:`-segment of `action_type`, as produced by `deriveTaskClass`). This is a
 * conservative default that callers can override per action or per delegation;
 * unknown classes resolve to tier 2 (deny-if-stale) rather than tier 0, so the
 * default posture is cautious, not permissive.
 */
const DEFAULT_TIER_BY_TASK_CLASS: Record<string, RiskTier> = {
  // Tier 0 - read-only / observational
  read: 0,
  get: 0,
  list: 0,
  search: 0,
  query: 0,
  fetch: 0,
  view: 0,

  // Tier 1 - internal write
  write: 1,
  update: 1,
  create: 1,
  data: 1,
  note: 1,
  draft: 1,

  // Tier 2 - external or sensitive
  external: 2,
  email: 2,
  send: 2,
  message: 2,
  publish: 2,
  share: 2,
  notify: 2,
  webhook: 2,

  // Tier 3 - money, secrets, production deploy
  commerce: 3,
  payment: 3,
  pay: 3,
  transfer: 3,
  wallet: 3,
  secret: 3,
  secrets: 3,
  key: 3,
  admin: 3,
  deploy: 3,
  prod: 3,
  production: 3,
  release: 3,
}

const VALID_TIERS: ReadonlyArray<RiskTier> = [0, 1, 2, 3]

/** Narrow an arbitrary value to a RiskTier, or null if it is not 0..3. */
export function coerceRiskTier(value: unknown): RiskTier | null {
  if (typeof value === 'number' && VALID_TIERS.includes(value as RiskTier)) {
    return value as RiskTier
  }
  if (typeof value === 'string' && /^[0-3]$/.test(value.trim())) {
    return Number(value.trim()) as RiskTier
  }
  return null
}

/**
 * Resolve the risk tier for an action. Precedence:
 *   1. an explicit per-action tier (request field), if valid
 *   2. an explicit per-delegation tier (contract field), if valid
 *   3. the default task-class mapping
 *   4. fallback tier 2 (deny-if-stale) for unknown classes
 *
 * `explicitTier` and `delegationTier` are the additive request/contract fields;
 * passing them undefined falls through to the class mapping.
 */
export function resolveRiskTier(opts: {
  taskClass: string
  explicitTier?: unknown
  delegationTier?: unknown
}): RiskTier {
  const explicit = coerceRiskTier(opts.explicitTier)
  if (explicit !== null) return explicit

  const delegationTier = coerceRiskTier(opts.delegationTier)
  if (delegationTier !== null) return delegationTier

  const cls = (opts.taskClass || '').toLowerCase()
  if (Object.prototype.hasOwnProperty.call(DEFAULT_TIER_BY_TASK_CLASS, cls)) {
    return DEFAULT_TIER_BY_TASK_CLASS[cls]
  }
  // Unknown action class: be cautious, not permissive.
  return 2
}

/**
 * Evaluate freshness for the SUPPLIED evidence using the SDK semantics.
 *
 * `isFresh` and `computeAge` are the SDK functions, injected so this module
 * stays pure and unit-testable without a live SDK import. The evaluate path
 * passes the real `isEvidenceFresh` / `computeEvidenceAge`. When no freshness
 * descriptor is supplied, the result is `{ fresh: null }` and tier behavior
 * treats "no descriptor" as "could not confirm fresh".
 */
export function evaluateFreshnessTier(opts: {
  tier: RiskTier
  freshness?: AttestationFreshness | null
  isFresh: (f: AttestationFreshness, now?: Date) => boolean
  computeAge: (f: AttestationFreshness, now?: Date) => number
  now?: Date
}): FreshnessTierResult {
  const { tier, freshness, isFresh, computeAge, now } = opts

  // Tier 3 fails closed ALWAYS - independent of the freshness descriptor.
  // Money, secrets, and production deploys do not get a freshness bypass;
  // the descriptor is recorded for the trail but never relaxes the posture.
  if (tier === 3) {
    let fresh: boolean | null = null
    let ageSeconds: number | null = null
    if (freshness) {
      fresh = safeBool(() => isFresh(freshness, now))
      ageSeconds = safeNum(() => computeAge(freshness, now))
    }
    return {
      tier,
      outcome: 'fail_closed',
      blocks: true,
      fresh,
      ageSeconds,
      reasonCode: 'freshness_tier3_fail_closed',
      detail: 'Tier 3 action (money, secrets, or production deploy): fails closed regardless of evidence freshness.',
    }
  }

  // No freshness descriptor supplied: there is nothing to evaluate.
  // Tier 0 still allows (records that no stale check was possible); higher
  // tiers treat the absence as "freshness not confirmed".
  if (!freshness) {
    return resolveNoEvidence(tier)
  }

  const fresh = safeBool(() => isFresh(freshness, now))
  const ageSeconds = safeNum(() => computeAge(freshness, now))

  if (fresh === true) {
    return {
      tier,
      outcome: 'allow',
      blocks: false,
      fresh: true,
      ageSeconds,
      reasonCode: 'freshness_ok',
      detail: `Evidence is fresh for its type (observed age ${fmtAge(ageSeconds)}).`,
    }
  }

  // Evidence is stale (or its freshness could not be confirmed). Apply the
  // tier's stale-handling behavior.
  return resolveStale(tier, fresh === null ? null : false, ageSeconds)
}

function resolveNoEvidence(tier: RiskTier): FreshnessTierResult {
  switch (tier) {
    case 0:
      return {
        tier, outcome: 'allow', blocks: false, fresh: null, ageSeconds: null,
        reasonCode: 'freshness_tier0_no_evidence',
        detail: 'Tier 0 read-only: allowed; no freshness evidence supplied, so no stale check was possible.',
      }
    case 1:
      return {
        tier, outcome: 'warn', blocks: false, fresh: null, ageSeconds: null,
        reasonCode: 'freshness_tier1_no_evidence',
        detail: 'Tier 1 internal write: proceeding with a flag; no freshness evidence supplied to confirm.',
      }
    case 2:
    default:
      return {
        tier, outcome: 'deny', blocks: true, fresh: null, ageSeconds: null,
        reasonCode: 'freshness_tier2_no_evidence',
        detail: 'Tier 2 external or sensitive: denied; no freshness evidence supplied, so freshness could not be confirmed.',
      }
  }
}

function resolveStale(tier: RiskTier, fresh: boolean | null, ageSeconds: number | null): FreshnessTierResult {
  const ageStr = fmtAge(ageSeconds)
  switch (tier) {
    case 0:
      return {
        tier, outcome: 'allow', blocks: false, fresh, ageSeconds,
        reasonCode: 'freshness_tier0_stale_allowed',
        detail: `Tier 0 read-only: allowed despite stale evidence (observed age ${ageStr}); the staleness was recorded.`,
      }
    case 1:
      return {
        tier, outcome: 'require_approval', blocks: true, fresh, ageSeconds,
        reasonCode: 'freshness_tier1_stale_requires_approval',
        detail: `Tier 1 internal write: evidence is stale (observed age ${ageStr}); requires approval before proceeding.`,
      }
    case 2:
    default:
      return {
        tier, outcome: 'deny', blocks: true, fresh, ageSeconds,
        reasonCode: 'freshness_tier2_stale_denied',
        detail: `Tier 2 external or sensitive: denied; evidence is stale (observed age ${ageStr}).`,
      }
  }
}

function fmtAge(ageSeconds: number | null): string {
  if (ageSeconds === null) return 'unknown'
  return `${ageSeconds}s`
}

function safeBool(fn: () => boolean): boolean | null {
  try { return fn() } catch { return null }
}

function safeNum(fn: () => number): number | null {
  try { const n = fn(); return Number.isFinite(n) ? n : null } catch { return null }
}
