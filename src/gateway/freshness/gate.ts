// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Freshness gate (G-B3) - the thin adapter that the evaluate path calls.
 *
 * Responsibilities:
 *   1. Lazily load the SDK freshness primitives (consume, never reimplement),
 *      with the same lazy-import + fail-soft idiom the router already uses for
 *      scope and recovery.
 *   2. Parse the additive, backward-compatible request/contract freshness
 *      fields into an `AttestationFreshness` descriptor.
 *   3. Run the pure tier engine and return a gate result the router can fold
 *      into its existing `violations[]` / receipt flow.
 *   4. Hold the SDK Wave 2 integration stubs (M4 freshness recording; W2-B3
 *      revocation-mode evaluation) behind optional-import-returns-null guards,
 *      so the gateway never blocks on the SDK and falls through to the existing
 *      evaluate-only + SQL revocation behavior until Wave 2 lands.
 */

import type { AttestationFreshness } from 'agent-passport-system'
import {
  resolveRiskTier,
  evaluateFreshnessTier,
  coerceRiskTier,
  type RiskTier,
  type FreshnessTierResult,
} from './tier-engine.js'

// ── SDK freshness primitives (consume, do not reinvent) ──
// Mirror getScopeAuthorizes(): lazy import; on load failure, fail SOFT for the
// freshness math by treating evidence as not-confirmed-fresh, which makes the
// tier behavior conservative (higher tiers block) rather than silently passing.
type IsFresh = (f: AttestationFreshness, now?: Date) => boolean
type ComputeAge = (f: AttestationFreshness, now?: Date) => number

let _isFresh: IsFresh | null = null
let _computeAge: ComputeAge | null = null

async function getFreshnessFns(): Promise<{ isFresh: IsFresh; computeAge: ComputeAge }> {
  if (!_isFresh || !_computeAge) {
    try {
      const sdk: any = await import('agent-passport-system')
      _isFresh = sdk.isEvidenceFresh as IsFresh
      _computeAge = sdk.computeEvidenceAge as ComputeAge
    } catch (e) {
      // Fail conservative: unknown freshness => not fresh; age unknown.
      console.error('[freshness] Failed to load SDK freshness fns - evidence treated as not-fresh:', (e as Error).message)
      _isFresh = () => false
      _computeAge = () => 0
    }
  }
  return { isFresh: _isFresh, computeAge: _computeAge }
}

// ── Wave 2 stub: freshness RECORDING (SDK Wave 2 module M4) ──
// 2.6.0-alpha.3 exports freshness EVALUATION but no recording/emit primitive.
// Until M4 lands, we evaluate-only and persist the freshness verdict through
// the existing mintEvaluationReceipt path. This guard returns null today.
// TODO(W2-M4): replace stub with SDK freshness-recording primitive (recordFreshness).
let _recordFreshness: ((snapshot: unknown) => void) | null | undefined
async function getRecordFreshness(): Promise<((snapshot: unknown) => void) | null> {
  if (_recordFreshness === undefined) {
    try {
      const sdk: any = await import('agent-passport-system')
      _recordFreshness = typeof sdk.recordFreshness === 'function' ? sdk.recordFreshness : null
    } catch {
      _recordFreshness = null
    }
  }
  return _recordFreshness ?? null
}

// ── Wave 2 stub: revocation-MODE evaluation (SDK Wave 2 module W2-B3) ──
// The risk tier selects which credential-check mode / freshness window a tier
// enforces. The store-backed revocation-mode evaluator is not in alpha.3, so
// this guard returns null and the router falls through to its existing SQL
// revocation-state check. We surface the mode the tier WOULD select so the
// field is wired now (additive), and stub the live-mode enforcement.
// Never call core/delegation revoke*/cascade*/getRevocation - they throw MOVED.
// TODO(W2-B3): replace stub with SDK store-backed revocation-mode evaluator.
type RevocationModeEvaluator = (opts: unknown) => unknown
let _revocationModeEvaluator: RevocationModeEvaluator | null | undefined
async function getRevocationModeEvaluator(): Promise<RevocationModeEvaluator | null> {
  if (_revocationModeEvaluator === undefined) {
    try {
      const sdk: any = await import('agent-passport-system')
      _revocationModeEvaluator = typeof sdk.evaluateRevocationMode === 'function'
        ? sdk.evaluateRevocationMode
        : null
    } catch {
      _revocationModeEvaluator = null
    }
  }
  return _revocationModeEvaluator ?? null
}

/**
 * Credential-check mode a tier selects. This is the W2-B3 mode-selection
 * surface, wired now as an additive field. Tier 3 / Tier 2 demand the
 * strictest live check; tier 0 is on-accept (an acceptance stamp suffices).
 * The SELECTION is live; the live-mode ENFORCEMENT is stubbed (see above).
 */
export function selectRevocationMode(tier: RiskTier): 'on-accept' | 'on-process' | 'both' {
  switch (tier) {
    case 3:
    case 2:
      return 'both'
    case 1:
      return 'on-process'
    case 0:
    default:
      return 'on-accept'
  }
}

/**
 * Parse the additive freshness fields from a request/contract into an
 * `AttestationFreshness` descriptor, or null when none was supplied.
 *
 * Accepted shapes (all optional, backward-compatible):
 *   - `freshness`: a full `{ type, validAt, ttl?, maxAge? }` object, OR
 *   - `freshness_required` / loose fields: `{ type, valid_at|validAt, ttl, max_age|maxAge }`
 *
 * Anything malformed returns null (no descriptor); the tier engine then treats
 * the action as having no freshness evidence.
 */
export function parseFreshnessDescriptor(input: unknown): AttestationFreshness | null {
  if (!input || typeof input !== 'object') return null
  const raw = input as Record<string, unknown>

  const type = raw.type
  if (type !== 'snapshot' && type !== 'rotating' && type !== 'static') return null

  const validAt = (raw.validAt ?? raw.valid_at)
  if (typeof validAt !== 'string' || validAt.length === 0) return null
  // Reject a validAt that is not a parseable ISO timestamp.
  if (Number.isNaN(Date.parse(validAt))) return null

  const out: AttestationFreshness = { type, validAt }

  const ttl = raw.ttl
  if (typeof ttl === 'number' && Number.isFinite(ttl) && ttl >= 0) out.ttl = ttl

  const maxAge = (raw.maxAge ?? raw.max_age)
  if (typeof maxAge === 'number' && Number.isFinite(maxAge) && maxAge >= 0) out.maxAge = maxAge

  return out
}

export interface FreshnessGateResult extends FreshnessTierResult {
  /** The credential-check mode the tier selected (W2-B3 wiring; enforcement stubbed). */
  revocationMode: 'on-accept' | 'on-process' | 'both'
  /** True when the M4 recording primitive was available and consumed (false today). */
  recordedViaSdk: boolean
}

/**
 * Run the freshness gate for one action. Consumes the SDK freshness primitives,
 * resolves the tier, evaluates, selects the revocation mode, and attempts the
 * M4 recording stub. Pure-ish: the only side effect is the best-effort M4
 * recording attempt (a no-op until Wave 2).
 */
export async function runFreshnessGate(opts: {
  taskClass: string
  /** Additive request field: per-action tier override. */
  requestTier?: unknown
  /** Additive contract field: per-delegation tier. */
  delegationTier?: unknown
  /** Raw freshness descriptor from the request body (or null). */
  freshnessInput?: unknown
  now?: Date
}): Promise<FreshnessGateResult> {
  const tier = resolveRiskTier({
    taskClass: opts.taskClass,
    explicitTier: opts.requestTier,
    delegationTier: opts.delegationTier,
  })

  const freshness = parseFreshnessDescriptor(opts.freshnessInput)
  const { isFresh, computeAge } = await getFreshnessFns()

  const result = evaluateFreshnessTier({
    tier,
    freshness,
    isFresh,
    computeAge,
    now: opts.now,
  })

  const revocationMode = selectRevocationMode(tier)

  // W2-M4 recording stub: attempt to record the freshness snapshot via the SDK.
  // Returns null today; the verdict is persisted by the router via the receipt.
  let recordedViaSdk = false
  try {
    const record = await getRecordFreshness()
    if (record) {
      record({ tier, freshness, outcome: result.outcome, ageSeconds: result.ageSeconds })
      recordedViaSdk = true
    }
  } catch { /* recording is best-effort; never blocks the evaluation */ }

  // W2-B3 mode-enforcement stub: when the store-backed evaluator lands, the
  // selected mode would drive a live revocation check here. Today it is null,
  // so the router's existing SQL revocation-state check remains authoritative.
  try {
    const modeEval = await getRevocationModeEvaluator()
    if (modeEval) {
      // TODO(W2-B3): fold the store-backed revocation-mode verdict into the result.
      modeEval({ mode: revocationMode, tier })
    }
  } catch { /* mode evaluation is best-effort until W2-B3 */ }

  return { ...result, revocationMode, recordedViaSdk }
}

export { coerceRiskTier, resolveRiskTier, evaluateFreshnessTier }
export type { RiskTier, FreshnessTierResult }
