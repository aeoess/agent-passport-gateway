// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C2 layer (a): real-time pre-flight guards.
 *
 * Settled-decision constraint C2: real-time enforcement is COMPILED, STATELESS,
 * NON-TURING-COMPLETE guards evaluated pre-flight. There is NEVER an agent or an
 * LLM in this path. Governance automations (layer b) are post-flight only and
 * live in ../automations/.
 *
 * What "compiled, stateless, non-Turing-complete" means here, concretely:
 *
 *  - Compiled: a guard set is a fixed array of predicates frozen at module load
 *    (COMPILED_GUARDS below). Tenants do not supply guard code; they only toggle
 *    which of the named, vetted guards are active and supply scalar thresholds.
 *    No predicate is constructed from request data. No `eval`, no `new Function`,
 *    no regex compiled from caller input inside the hot path.
 *  - Stateless: a guard is a pure function of (context) -> decision. It reads no
 *    database, opens no socket, calls no clock beyond a caller-supplied value,
 *    and mutates nothing. The same input always yields the same output. This is
 *    asserted by the determinism test.
 *  - Non-Turing-complete: every guard is straight-line. There are no unbounded
 *    loops and no recursion. The only iteration is over the FIXED guard array
 *    and over a small, length-capped list of literal scope strings. Worst-case
 *    work is O(active_guards x cap), with both factors bounded by constants.
 *
 * Thin-gateway note: a guard BLOCKS pre-flight (deny-before), it never approves
 * a high-risk action on the gateway's own authority and it never mutates policy.
 * The enforcement decision that matters at value-moving time still lives at the
 * sink (B2 tokenEpochGuard, offline). These guards are a fail-closed front door
 * that runs before the billable evaluate decision in enforce.ts, nothing more.
 */

// Maximum number of literal scope tokens any guard will scan. A request that
// somehow carried more is treated as "scan the cap and stop" - bounded work,
// never an unbounded loop. This is the non-Turing-completeness guarantee.
export const GUARD_SCOPE_SCAN_CAP = 64

/** Immutable input a guard sees. No db handle, no request object, no mutation. */
export interface GuardContext {
  /** Agent posture status: 'active' | 'restricted' | 'suspended' | 'frozen' | 'revoked'. */
  readonly agentStatus: string
  /** The single scope the request asks to exercise. */
  readonly scopeRequired: string
  /** action_type, first segment is the task class. */
  readonly actionType: string
  /** Estimated cost in currency units (already parsed; 0 when absent). */
  readonly estimatedCost: number
  /** Whether this scope is on the tenant's high-risk list (resolved by caller). */
  readonly isHighRisk: boolean
  /**
   * Whether a signed, currently-live playbook authorizes this high-risk action.
   * Resolved by the caller from the playbook registry (layer c). The guard does
   * not look it up; it only reads the resolved boolean. This keeps the guard
   * stateless while still letting layer (c) gate high-risk auto-actions.
   */
  readonly coveredBySignedPlaybook: boolean
  /** Hard ceiling on per-action estimated cost, 0 = no ceiling configured. */
  readonly costCeiling: number
}

/** A guard's verdict. `block` is fail-closed deny-before; `pass` lets enforce continue. */
export interface GuardDecision {
  readonly verdict: 'pass' | 'block'
  /** Stable machine code, e.g. 'guard_suspended'. Empty when pass. */
  readonly code: string
  /** Human-readable reason. Empty when pass. */
  readonly reason: string
  /** Which named guard produced the block. Empty when pass. */
  readonly guard: string
}

const PASS: GuardDecision = { verdict: 'pass', code: '', reason: '', guard: '' }

/** A compiled guard: a name plus a pure, straight-line predicate. */
interface CompiledGuard {
  readonly name: string
  readonly evaluate: (ctx: GuardContext) => GuardDecision
}

/**
 * The COMPILED guard set. Fixed at module load. Order is significant: the first
 * guard to BLOCK wins (fail-closed, first-deny). Each predicate is straight-line
 * and reads only the immutable context. None of them mutate, loop unboundedly,
 * or touch IO. To add a guard you add a vetted named entry here; tenants cannot
 * inject one.
 */
const COMPILED_GUARDS: readonly CompiledGuard[] = Object.freeze([
  // 1. Posture: a suspended/frozen/revoked agent is blocked before anything else.
  {
    name: 'posture_lock',
    evaluate: (ctx): GuardDecision => {
      const s = ctx.agentStatus
      if (s === 'suspended' || s === 'frozen' || s === 'revoked') {
        return {
          verdict: 'block',
          code: 'guard_posture_lock',
          reason: `Agent posture "${s}" blocks all actions pre-flight`,
          guard: 'posture_lock',
        }
      }
      return PASS
    },
  },

  // 2. High-risk-without-playbook: a high-risk action with NO signed, live
  //    playbook covering it is blocked. This is the C1/C2 load-bearing guard:
  //    no free-form autonomous high-risk action exists outside a signed
  //    playbook, and the BLOCK is made pre-flight, statelessly, by a compiled
  //    predicate - never by an agent or an LLM deciding in the hot path.
  {
    name: 'high_risk_requires_signed_playbook',
    evaluate: (ctx): GuardDecision => {
      if (ctx.isHighRisk && !ctx.coveredBySignedPlaybook) {
        return {
          verdict: 'block',
          code: 'guard_high_risk_unsigned',
          reason:
            'High-risk action has no signed, live playbook covering it. ' +
            'Pre-sign a scoped, epoch-bound playbook to authorize it.',
          guard: 'high_risk_requires_signed_playbook',
        }
      }
      return PASS
    },
  },

  // 3. Cost ceiling: a single action whose estimated cost exceeds the configured
  //    per-action ceiling is blocked. A pure scalar compare, no state.
  {
    name: 'cost_ceiling',
    evaluate: (ctx): GuardDecision => {
      if (ctx.costCeiling > 0 && ctx.estimatedCost > ctx.costCeiling) {
        return {
          verdict: 'block',
          code: 'guard_cost_ceiling',
          reason: `Estimated cost ${ctx.estimatedCost} exceeds per-action ceiling ${ctx.costCeiling}`,
          guard: 'cost_ceiling',
        }
      }
      return PASS
    },
  },
])

/** Names of the compiled guards, for diagnostics and the active-set default. */
export const GUARD_NAMES: readonly string[] = Object.freeze(COMPILED_GUARDS.map(g => g.name))

/**
 * Evaluate the active compiled guards against a context. Pure and bounded:
 *
 *  - iterates the FIXED guard array once (length is a compile-time constant),
 *  - runs only straight-line predicates,
 *  - returns on the first BLOCK (fail-closed, first-deny),
 *  - never reads or writes IO, never mutates the context.
 *
 * `activeGuards` lets a tenant disable a vetted guard by name; an unknown name
 * is ignored (it can never enable un-vetted code). Passing undefined runs all.
 */
export function evaluateGuards(
  ctx: GuardContext,
  activeGuards?: readonly string[],
): GuardDecision {
  const active = activeGuards
    ? new Set(activeGuards)
    : null
  for (const guard of COMPILED_GUARDS) {
    if (active && !active.has(guard.name)) continue
    const decision = guard.evaluate(ctx)
    if (decision.verdict === 'block') return decision
  }
  return PASS
}

/**
 * Resolve whether a scope is high-risk against a tenant's high-risk scope list.
 * Pure, bounded by GUARD_SCOPE_SCAN_CAP: scans at most the cap, then stops. A
 * scope is high-risk if it equals a listed scope or sits under a listed prefix
 * (`listed:`). Uses ONLY literal string compares - no regex built from input.
 */
export function isScopeHighRisk(
  scopeRequired: string,
  highRiskScopes: readonly string[],
): boolean {
  const n = Math.min(highRiskScopes.length, GUARD_SCOPE_SCAN_CAP)
  for (let i = 0; i < n; i++) {
    const listed = highRiskScopes[i]
    if (scopeRequired === listed) return true
    if (scopeRequired.startsWith(listed + ':')) return true
  }
  return false
}

/**
 * The default high-risk scope vocabulary. These are the families that must never
 * auto-fire without a signed playbook: anything that revokes, freezes, moves
 * value, rotates roots, or deletes evidence. Tenants may extend this list via
 * configuration; they may not shrink the deny intent of layer (c).
 */
export const DEFAULT_HIGH_RISK_SCOPES: readonly string[] = Object.freeze([
  'admin:delete',
  'admin:write',
  'revocation:execute',
  'revocation:bump_epoch',
  'revocation:panic_freeze',
  'commerce:send',
  'wallet:transfer',
  'key:rotate_root',
  'evidence:delete',
])
