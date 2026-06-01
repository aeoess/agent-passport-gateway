// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Migration readiness metric
// ══════════════════════════════════════════════════════════════════
// The number that tells an operator whether it is safe to graduate from a
// shadow mode (observe/warn) to enforce. Shape:
//
//   "0 blocked, 42 would-have-been-denied, 7 policies need tuning before enforce"
//
// Sources:
//   - blocked            : decisions that actually stopped an action (enforce /
//                          emergency / approval). In a shadow mode this is 0,
//                          which is the whole point of shadow mode.
//   - would_have_been_denied : violations the current mode let through but a
//                          stricter (enforce) mode would have blocked. This is
//                          the impact preview.
//   - policies_need_tuning : distinct agents (workflows) that produced at least
//                          one would-have-been-denied. Each is a place the
//                          operator should look before enforcing, because
//                          flipping to enforce today would start blocking them.
//
// We record one mode_observations row per request that produced a would-deny
// or a real block, so this metric is an aggregate query, not a guess.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { type EnforcementMode, type ModeDecision } from './modes.js'

/**
 * Create the mode_observations table. Idempotent. One row is appended whenever
 * a request under any mode produced either a real block or a would-have-been-
 * denied signal. Pure permits in a steady state are not recorded here (they are
 * already in policy_evaluations); this table is the migration-signal ledger.
 */
export function initModeObservationsTable(): void {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS mode_observations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      workflow_id TEXT NOT NULL DEFAULT '',
      agent_id TEXT NOT NULL,
      evaluation_id TEXT,
      mode TEXT NOT NULL,
      effect TEXT NOT NULL,
      risk TEXT NOT NULL,
      blocked INTEGER NOT NULL DEFAULT 0,
      would_have_been_denied INTEGER NOT NULL DEFAULT 0,
      scope_required TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_mode_obs_tenant ON mode_observations(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_mode_obs_workflow ON mode_observations(tenant_id, workflow_id);
  `)
}

/**
 * Record a mode decision for migration metrics. Only records rows that carry a
 * migration signal (a real block or a would-have-been-denied); pure permits are
 * skipped to keep the ledger to the signal. Best-effort: never throws into the
 * hot path. Returns true if a row was written.
 */
export function recordModeObservation(opts: {
  tenantId: string
  agentId: string
  workflowId?: string | null
  evaluationId?: string | null
  scopeRequired?: string | null
  decision: ModeDecision
}): boolean {
  const d = opts.decision
  // Skip pure permits with no signal.
  if (!d.blocked && !d.wouldHaveBeenDenied) return false
  try {
    const db = getDB()
    db.prepare(
      `INSERT INTO mode_observations
        (id, tenant_id, workflow_id, agent_id, evaluation_id, mode, effect, risk, blocked, would_have_been_denied, scope_required)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      randomUUID(),
      opts.tenantId,
      (opts.workflowId || '').trim(),
      opts.agentId,
      opts.evaluationId || null,
      d.mode,
      d.effect,
      d.risk,
      d.blocked ? 1 : 0,
      d.wouldHaveBeenDenied ? 1 : 0,
      opts.scopeRequired || null,
    )
    return true
  } catch (e) {
    console.error('[mode-obs] record failed:', (e as Error).message)
    return false
  }
}

export interface MigrationMetric {
  tenant_id: string
  workflow_id: string | null
  current_mode: EnforcementMode | null
  blocked: number
  would_have_been_denied: number
  /** Distinct agents that produced a would-have-been-denied; each needs review. */
  policies_need_tuning: number
  /** Of the would-have-been-denied, how many are high risk. */
  would_have_been_denied_high_risk: number
  /** The human-readable migration line. */
  summary: string
  /** True when nothing would be newly blocked by flipping to enforce. */
  ready_for_enforce: boolean
  generated_at: string
}

/**
 * Compute the migration readiness metric for a tenant (optionally scoped to a
 * single workflow). `currentMode` is passed in by the caller (resolved via
 * mode-config) so this module stays free of resolution policy.
 */
export function computeMigrationMetric(opts: {
  tenantId: string
  workflowId?: string | null
  currentMode?: EnforcementMode | null
  /** Only count observations from the last N days. null = all time. */
  windowDays?: number | null
}): MigrationMetric {
  const db = getDB()
  const wf = opts.workflowId != null ? (opts.workflowId || '').trim() : null
  const params: unknown[] = [opts.tenantId]
  let where = `tenant_id = ?`
  if (wf != null) { where += ` AND workflow_id = ?`; params.push(wf) }
  if (opts.windowDays && opts.windowDays > 0) {
    where += ` AND created_at > datetime('now', ?)`
    params.push(`-${Math.floor(opts.windowDays)} days`)
  }

  const agg = db.prepare(
    `SELECT
       SUM(blocked) AS blocked,
       SUM(would_have_been_denied) AS would_deny,
       SUM(CASE WHEN would_have_been_denied = 1 AND risk = 'high' THEN 1 ELSE 0 END) AS would_deny_high,
       COUNT(DISTINCT CASE WHEN would_have_been_denied = 1 THEN agent_id END) AS need_tuning
     FROM mode_observations WHERE ${where}`
  ).get(...params) as { blocked: number | null; would_deny: number | null; would_deny_high: number | null; need_tuning: number | null }

  const blocked = agg.blocked || 0
  const wouldDeny = agg.would_deny || 0
  const wouldDenyHigh = agg.would_deny_high || 0
  const needTuning = agg.need_tuning || 0

  const summary =
    `${blocked} blocked, ${wouldDeny} would-have-been-denied, ` +
    `${needTuning} ${needTuning === 1 ? 'policy needs' : 'policies need'} tuning before enforce`

  return {
    tenant_id: opts.tenantId,
    workflow_id: wf,
    current_mode: opts.currentMode || null,
    blocked,
    would_have_been_denied: wouldDeny,
    would_have_been_denied_high_risk: wouldDenyHigh,
    policies_need_tuning: needTuning,
    summary,
    // Ready when nothing new would be blocked by flipping to enforce.
    ready_for_enforce: wouldDeny === 0,
    generated_at: new Date().toISOString(),
  }
}
