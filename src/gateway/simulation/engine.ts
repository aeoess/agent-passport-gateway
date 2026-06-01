// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Policy simulation over historical receipts
// ══════════════════════════════════════════════════════════════════
// Replays a CANDIDATE policy against the receipts a tenant has already
// produced (the policy_evaluations history) and reports what would have
// changed: which requests the candidate would newly deny, which it would
// newly permit, and which are unchanged. The output always carries the
// honest disclaimer (see disclaimer.ts) because it estimates the past and
// makes no claim about future safety.
//
// This is product intelligence layered over the recorded decision history.
// It never re-runs side effects and never touches live enforcement. The only
// SDK primitive it consumes is scopeAuthorizes (monotonic scope narrowing),
// reached through the same lazy-import seam enforce.ts uses, so the simulation
// matches the gateway's real scope semantics rather than reimplementing them.
// ══════════════════════════════════════════════════════════════════

import { getDB } from '../../db/schema.js'
import { SIMULATION_DISCLAIMER } from './disclaimer.js'
import { classifyRequestRisk, type RiskLevel } from './modes.js'

// ── SDK seam: scope authorization ─────────────────────────────────
// Same monotonic-narrowing scope check the live evaluate path uses. Loaded
// lazily so a missing SDK fails closed (deny) rather than throwing, and so the
// simulation reflects exactly what the gateway would have decided.
let _scopeAuthorizes: ((scopes: string[], required: string) => boolean) | null = null
async function getScopeAuthorizes(): Promise<(scopes: string[], required: string) => boolean> {
  if (!_scopeAuthorizes) {
    try {
      const sdk = await import('agent-passport-system')
      _scopeAuthorizes = sdk.scopeAuthorizes
    } catch (e) {
      // FAIL CLOSED: deny all scope checks when SDK unavailable, matching enforce.ts.
      console.error('[SECURITY][sim] Failed to load scopeAuthorizes - all sim scope checks DENY:', (e as Error).message)
      _scopeAuthorizes = () => false
    }
  }
  return _scopeAuthorizes
}

/**
 * A candidate policy to test. Deliberately small and declarative: this is a
 * what-if instrument, not a second policy engine. It expresses the common
 * tightening moves an operator makes before flipping to enforce.
 *
 *  allowScopes  - allowlist of scope prefixes the candidate would permit.
 *                 A request permits only if its scope is authorized by one of
 *                 these (via the SDK scopeAuthorizes monotonic check). If empty,
 *                 the allowlist is not applied (scope is not a denial reason).
 *  denyScopes   - explicit denylist of scope prefixes. Any request whose scope
 *                 matches is denied regardless of the allowlist. Always applied.
 *  spendCap     - per-request estimated-cost ceiling in dollars. A request whose
 *                 recorded estimated cost exceeds this is denied. null = no cap.
 *  blockHighRisk - when true, any request classified high risk is denied.
 */
export interface CandidatePolicy {
  name: string
  allowScopes?: string[]
  denyScopes?: string[]
  spendCap?: number | null
  blockHighRisk?: boolean
}

/** One historical decision row, as replayed. */
export interface HistoricalDecision {
  evaluationId: string
  agentId: string
  actionType: string
  scopeRequired: string
  /** verdict the gateway actually returned at the time. */
  historicalVerdict: 'permit' | 'deny'
  /** verdict the candidate policy would have returned. */
  candidateVerdict: 'permit' | 'deny'
  risk: RiskLevel
  /** machine reason for the candidate verdict. */
  candidateReason: string
  /** classification of the change relative to history. */
  delta: 'unchanged' | 'newly_denied' | 'newly_permitted'
}

export interface SimulationInput {
  tenantId: string
  candidate: CandidatePolicy
  /** Optional cap on how many historical rows to replay (most recent first). */
  limit?: number
  /** Optional scope of the replay to a single agent. */
  agentId?: string | null
}

export interface SimulationResult {
  candidate_policy: string
  /** Number of historical receipts replayed. */
  receipts_evaluated: number
  /** Counts of each delta class. */
  unchanged: number
  newly_denied: number
  newly_permitted: number
  /** Of the newly_denied, how many are high risk (the ones to look at first). */
  newly_denied_high_risk: number
  /** Up to a sample of the changed decisions, for operator inspection. */
  sample_changes: HistoricalDecision[]
  /** Honest disclaimer - present on every result. */
  disclaimer: string
  /** When the simulation ran. */
  simulated_at: string
  /** The window the replay covered, for reproducibility. */
  window: { agent_id: string | null; limit: number | null; oldest: string | null; newest: string | null }
}

interface EvalRow {
  id: string
  agent_id: string
  action_type: string
  scope_required: string
  verdict: string
  reason: string | null
  created_at: string
  estimated_cost?: number | null
}

/** Does a scope match any prefix in the list (root or exact or hierarchical child)? */
function scopeMatchesList(scope: string, list: string[]): boolean {
  const s = (scope || '').toLowerCase()
  for (const raw of list) {
    const p = (raw || '').toLowerCase().replace(/:?\*$/, '')
    if (!p) continue
    if (s === p) return true
    if (s.startsWith(p + ':')) return true
  }
  return false
}

/**
 * Evaluate one historical row against the candidate policy. Pure given the
 * injected scopeAuthorizes. Returns the candidate verdict + reason + risk.
 */
export function evaluateCandidate(
  row: { scopeRequired: string; violations: string[]; estimatedCost?: number | null },
  candidate: CandidatePolicy,
  scopeAuthorizes: (scopes: string[], required: string) => boolean,
): { verdict: 'permit' | 'deny'; reason: string; risk: RiskLevel } {
  const scope = row.scopeRequired || ''
  const risk = classifyRequestRisk({
    scopeRequired: scope,
    violations: row.violations,
    estimatedCost: row.estimatedCost ?? null,
  })

  // 1. Explicit denylist always wins.
  if (candidate.denyScopes && candidate.denyScopes.length > 0 && scopeMatchesList(scope, candidate.denyScopes)) {
    return { verdict: 'deny', reason: 'candidate_denylist', risk }
  }

  // 2. High-risk block.
  if (candidate.blockHighRisk && risk === 'high') {
    return { verdict: 'deny', reason: 'candidate_block_high_risk', risk }
  }

  // 3. Spend cap (per-request).
  if (candidate.spendCap != null && row.estimatedCost != null && row.estimatedCost > candidate.spendCap) {
    return { verdict: 'deny', reason: 'candidate_spend_cap', risk }
  }

  // 4. Allowlist: if present, the scope must be authorized by one of the
  //    allowed scopes via the SDK monotonic narrowing check.
  if (candidate.allowScopes && candidate.allowScopes.length > 0) {
    if (!scopeAuthorizes(candidate.allowScopes, scope)) {
      return { verdict: 'deny', reason: 'candidate_not_in_allowlist', risk }
    }
  }

  return { verdict: 'permit', reason: 'candidate_permit', risk }
}

/**
 * Run the candidate policy against the tenant's historical policy_evaluations
 * and produce the diff + disclaimer.
 */
export async function simulatePolicy(input: SimulationInput): Promise<SimulationResult> {
  const db = getDB()
  const scopeAuthorizes = await getScopeAuthorizes()
  const limit = input.limit && input.limit > 0 ? Math.min(input.limit, 50000) : null

  // estimated_cost is not a stored column on policy_evaluations; the recorded
  // reason text carries spend context. We replay on scope/risk and treat
  // estimatedCost as unavailable (null) unless a caller provides rows directly.
  // This keeps the replay faithful to what the receipt actually recorded.
  let sql = `SELECT id, agent_id, action_type, scope_required, verdict, reason, created_at
             FROM policy_evaluations WHERE tenant_id = ?`
  const params: unknown[] = [input.tenantId]
  if (input.agentId) { sql += ` AND agent_id = ?`; params.push(input.agentId) }
  sql += ` ORDER BY created_at DESC`
  if (limit) { sql += ` LIMIT ?`; params.push(limit) }

  const rows = db.prepare(sql).all(...params) as EvalRow[]

  let unchanged = 0
  let newlyDenied = 0
  let newlyPermitted = 0
  let newlyDeniedHighRisk = 0
  const sample: HistoricalDecision[] = []
  let oldest: string | null = null
  let newest: string | null = null

  for (const row of rows) {
    // Recover the violation reasons recorded at decision time so risk
    // classification matches what the gateway saw.
    const violations = row.reason ? [row.reason] : []
    const cand = evaluateCandidate(
      { scopeRequired: row.scope_required, violations, estimatedCost: row.estimated_cost ?? null },
      input.candidate,
      scopeAuthorizes,
    )

    const historicalVerdict: 'permit' | 'deny' = row.verdict === 'permit' ? 'permit' : 'deny'
    let delta: HistoricalDecision['delta'] = 'unchanged'
    if (cand.verdict === historicalVerdict) {
      unchanged++
    } else if (cand.verdict === 'deny') {
      newlyDenied++
      delta = 'newly_denied'
      if (cand.risk === 'high') newlyDeniedHighRisk++
    } else {
      newlyPermitted++
      delta = 'newly_permitted'
    }

    if (newest === null) newest = row.created_at // rows are DESC, first is newest
    oldest = row.created_at // last seen is oldest

    if (delta !== 'unchanged' && sample.length < 25) {
      sample.push({
        evaluationId: row.id,
        agentId: row.agent_id,
        actionType: row.action_type,
        scopeRequired: row.scope_required,
        historicalVerdict,
        candidateVerdict: cand.verdict,
        risk: cand.risk,
        candidateReason: cand.reason,
        delta,
      })
    }
  }

  return {
    candidate_policy: input.candidate.name,
    receipts_evaluated: rows.length,
    unchanged,
    newly_denied: newlyDenied,
    newly_permitted: newlyPermitted,
    newly_denied_high_risk: newlyDeniedHighRisk,
    sample_changes: sample,
    disclaimer: SIMULATION_DISCLAIMER,
    simulated_at: new Date().toISOString(),
    window: { agent_id: input.agentId || null, limit, oldest, newest },
  }
}
