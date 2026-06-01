// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Enforcement modes (shadow / warn / approval / enforce / emergency)
// ══════════════════════════════════════════════════════════════════
// Pure mode-resolution logic. Given a raw policy verdict (permit | deny) plus
// a risk classification, the active mode decides whether a violation BLOCKS
// the action, only WARNS (records what would have been denied), needs human
// APPROVAL, or is recorded as evidence only.
//
// This is product intelligence (how well governance works), not a protocol
// primitive (what governance is). The underlying permit/deny verdict still
// comes from the SDK-backed scope/spend/type checks in enforce.ts; this
// module only layers the operator's chosen rollout posture on top.
//
// Design note: modes are a migration safety device. A customer turning on the
// gateway does not want day-one blocks breaking their fleet. They start in
// `observe`, watch the would-have-been-denied count, tune policies, then graduate
// to `enforce`. The mode never changes WHAT is a violation, only the consequence.
// ══════════════════════════════════════════════════════════════════

/**
 * The five rollout modes, from least to most strict.
 *
 *  observe   - evidence only. Nothing is ever blocked. The honest baseline a
 *              new customer starts in. Denials are recorded as "would have been
 *              denied" so the operator can see impact before enforcing.
 *  warn      - same as observe for blocking (nothing blocks), but the response
 *              surfaces the would-deny prominently so a human/agent sees it inline.
 *  approval  - blocks ONLY high-risk violations, routing them to human sign-off.
 *              Low/medium-risk violations pass through with a warning.
 *  enforce   - blocks every violation. The steady-state production posture.
 *  emergency - fail closed on high-risk: high-risk requests are blocked even if
 *              the underlying verdict was permit. Use during an active incident.
 */
export type EnforcementMode = 'observe' | 'warn' | 'approval' | 'enforce' | 'emergency'

export const ENFORCEMENT_MODES: readonly EnforcementMode[] = [
  'observe', 'warn', 'approval', 'enforce', 'emergency',
] as const

export function isEnforcementMode(v: unknown): v is EnforcementMode {
  return typeof v === 'string' && (ENFORCEMENT_MODES as readonly string[]).includes(v)
}

/** Coarse risk band for a request. Kept local (product intelligence). */
export type RiskLevel = 'low' | 'medium' | 'high'

/** The raw verdict the underlying policy check produced, before mode is applied. */
export type RawVerdict = 'permit' | 'deny'

/**
 * The effect a mode applies on top of the raw verdict.
 *
 *  permit            - allowed to proceed (no violation, or mode does not block it).
 *  block             - hard denied. The action does not run.
 *  warn              - NOT blocked. The action runs, but a "would have been denied"
 *                      signal is recorded and surfaced. This is the shadow signal.
 *  approval_required - blocked pending human sign-off (routes to the approval queue).
 */
export type ModeEffect = 'permit' | 'block' | 'warn' | 'approval_required'

export interface ModeDecisionInput {
  /** Underlying policy verdict from the scope/spend/type checks. */
  rawVerdict: RawVerdict
  /** Risk band for this request. */
  risk: RiskLevel
  /** Active mode for this request (resolved per workflow, falling back to tenant). */
  mode: EnforcementMode
}

export interface ModeDecision {
  mode: EnforcementMode
  rawVerdict: RawVerdict
  risk: RiskLevel
  /** What the mode decided to do. */
  effect: ModeEffect
  /** True when the action is actually stopped (block or approval_required). */
  blocked: boolean
  /**
   * True when there is a violation that this mode chose NOT to block.
   * This is the "would have been denied" counter that drives the migration metric.
   */
  wouldHaveBeenDenied: boolean
  /** Short machine reason for the mode-level outcome. */
  modeReason: string
}

/**
 * Apply an enforcement mode to a raw verdict + risk band.
 *
 * The matrix, read top to bottom by mode:
 *
 *   raw=permit  -> always permit (no violation to act on). The one exception is
 *                  `emergency`, which fails closed on high-risk even for permits,
 *                  because during an incident a high-risk permitted action is
 *                  exactly what you want to hold.
 *
 *   raw=deny    -> there is a violation. The mode decides the consequence:
 *     observe   -> warn  (evidence only, never blocks)
 *     warn      -> warn  (evidence only, surfaced inline)
 *     approval  -> high risk: approval_required (block pending sign-off);
 *                  low/medium: warn (let it through, record it)
 *     enforce   -> block (every violation)
 *     emergency -> high risk: block; low/medium: block as well (emergency is
 *                  strictly >= enforce for violations). The distinct emergency
 *                  behaviour is the permit-side fail-closed above.
 */
export function applyMode(input: ModeDecisionInput): ModeDecision {
  const { rawVerdict, risk, mode } = input

  const base = (effect: ModeEffect, reason: string): ModeDecision => ({
    mode,
    rawVerdict,
    risk,
    effect,
    blocked: effect === 'block' || effect === 'approval_required',
    // A violation (raw deny) that we did not block is a would-have-been-denied.
    wouldHaveBeenDenied: rawVerdict === 'deny' && (effect === 'warn' || effect === 'permit'),
    modeReason: reason,
  })

  // ── permit side ──
  if (rawVerdict === 'permit') {
    if (mode === 'emergency' && risk === 'high') {
      // Fail closed: a high-risk action is held during an incident even though
      // the standing policy would permit it. This is mode-derived, not a policy
      // violation, so it does not count as would-have-been-denied.
      return base('block', 'emergency_fail_closed_high_risk')
    }
    return base('permit', 'permitted')
  }

  // ── deny side (there is a violation) ──
  switch (mode) {
    case 'observe':
      return base('warn', 'observe_evidence_only')
    case 'warn':
      return base('warn', 'warn_would_deny')
    case 'approval':
      if (risk === 'high') return base('approval_required', 'approval_required_high_risk')
      return base('warn', 'approval_low_risk_warn_only')
    case 'enforce':
      return base('block', 'enforce_block_violation')
    case 'emergency':
      return base('block', 'emergency_block_violation')
    default: {
      // Exhaustiveness guard. Unknown mode fails closed on a violation.
      const _never: never = mode
      void _never
      return base('block', 'unknown_mode_fail_closed')
    }
  }
}

/**
 * Map the underlying policy result to a coarse risk band.
 *
 * SEAM: Wave 2 of the SDK is expected to ship a first-class request risk
 * classifier. Until then we derive risk locally from the scope root and the
 * shape of the violation. This is deliberately conservative: write/admin/commerce
 * roots and spend-budget violations are high risk; everything else is low/medium.
 *
 * TODO(W2-risk): replace this local heuristic with the SDK request-risk
 * primitive once it lands in agent-passport-system (the alpha.3 build only
 * exposes evaluateApsTxtRisk, which classifies an aps.txt document, not a live
 * gateway request). Call site stays the same; only the body of this function
 * changes to delegate to the SDK.
 */
export function classifyRequestRisk(opts: {
  scopeRequired: string
  violations: string[]
  estimatedCost?: number | null
}): RiskLevel {
  const scopeRoot = (opts.scopeRequired || '').split(':')[0].toLowerCase()
  const joinedViolations = (opts.violations || []).join(' ').toLowerCase()

  // High-risk scope roots: anything that can mutate state or move money.
  const HIGH_RISK_ROOTS = ['admin', 'commerce', 'payment', 'wallet', 'delete', 'revoke']
  if (HIGH_RISK_ROOTS.includes(scopeRoot)) return 'high'

  // Spend / budget violations are high risk regardless of scope root.
  if (joinedViolations.includes('budget') || joinedViolations.includes('spend') || joinedViolations.includes('cost')) {
    return 'high'
  }

  // Entity-ceiling and suspension violations are at least medium.
  if (joinedViolations.includes('ceiling') || joinedViolations.includes('suspended') || joinedViolations.includes('entity')) {
    return 'medium'
  }

  // Write-shaped capabilities are medium.
  if (joinedViolations.includes('write') || scopeRoot === 'data') return 'medium'

  return 'low'
}
