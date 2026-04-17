// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Anomaly Detection (gateway copy — stateful state machine).
 *
 * The SDK exposes only the pure uncertainty-compliance primitive
 * (validateV2UncertaintyCompliance) and the shared types. This module
 * owns the action-history ledger, first-max-authority detection, and
 * delegation-concentration (Monolith) scoring that used to live in
 * src/v2/anomaly-v2.ts. Migrated under the AAIF boundary refactor on
 * 2026-04-17.
 */

import type {
  ActionRecord, AnomalyFlag, AnomalyType, ReviewMode, AssuranceClass,
  ConcentrationMetrics,
} from 'agent-passport-system'

const actionHistory: Map<string, ActionRecord[]> = new Map()
const anomalyFlags: AnomalyFlag[] = []

export function recordV2Action(record: ActionRecord): void {
  const existing = actionHistory.get(record.agent_id) || []
  existing.push(record)
  actionHistory.set(record.agent_id, existing)
}

export function getV2ActionHistory(agentId: string): ActionRecord[] {
  return actionHistory.get(agentId) || []
}

export function getV2AnomalyFlags(agentId?: string): AnomalyFlag[] {
  if (agentId) return anomalyFlags.filter(f => f.agent_id === agentId)
  return [...anomalyFlags]
}

export function getV2UnreviewedFlags(agentId?: string): AnomalyFlag[] {
  return getV2AnomalyFlags(agentId).filter(f => !f.reviewed)
}

// ═══════════════════════════════════════════════
// FIRST-MAX-AUTHORITY DETECTION
// ═══════════════════════════════════════════════

export function checkV2FirstMaxAuthority(record: ActionRecord): AnomalyFlag | null {
  const history = getV2ActionHistory(record.agent_id)
  const maxPrior = history.reduce(
    (max, r) => r.action_id !== record.action_id ? Math.max(max, r.authority_level) : max, 0,
  )
  if (record.authority_level > maxPrior) {
    const reviewMode: ReviewMode =
      record.risk_class === 'critical' || record.risk_class === 'high' ? 'sync' : 'async'
    const flag: AnomalyFlag = {
      id: `anomaly-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      agent_id: record.agent_id,
      anomaly_type: 'first_max_authority' as AnomalyType,
      action_id: record.action_id,
      description: `Authority level ${record.authority_level} first use (prev max: ${maxPrior})`,
      review_mode: reviewMode,
      reviewed: false, review_outcome: null,
      created_at: new Date().toISOString(),
      assurance_class: 'evidentially_auditable' as AssuranceClass,
    }
    anomalyFlags.push(flag)
    return flag
  }
  return null
}

// ═══════════════════════════════════════════════
// DELEGATION CONCENTRATION (Monolith Detection)
// ═══════════════════════════════════════════════

export function computeV2ConcentrationMetrics(
  agentId: string, flagThreshold: number = 0.7,
): ConcentrationMetrics {
  const history = getV2ActionHistory(agentId)
  if (history.length === 0) {
    return {
      agent_id: agentId, tasks_retained_ratio: 0, scope_utilization_breadth: 0,
      delegation_refusal_count: 0, single_agent_workflow_pct: 0,
      concentration_risk: 0, flagged: false, computed_at: new Date().toISOString(),
    }
  }
  const retained = history.filter(a => !a.was_delegated).length
  const tasksRetainedRatio = retained / history.length
  const complexTasks = history.filter(a => a.complexity > 0.5)
  const complexRetained = complexTasks.filter(a => !a.was_delegated).length
  const singleAgentPct = complexTasks.length > 0 ? complexRetained / complexTasks.length : 0
  const uniqueDels = new Set(history.map(a => a.delegation_ref))
  const scopeBreadth = Math.min(1, uniqueDels.size / Math.max(history.length * 0.3, 1))
  const refusals = history.filter(a => !a.was_delegated && a.complexity > 0.5).length

  const risk = tasksRetainedRatio * 0.3 + singleAgentPct * 0.4 +
    (1 - scopeBreadth) * 0.1 + Math.min(1, refusals / 10) * 0.2
  const flagged = risk > flagThreshold

  if (flagged) {
    const existing = anomalyFlags.find(
      f => f.agent_id === agentId && f.anomaly_type === 'delegation_concentration' && !f.reviewed,
    )
    if (!existing) {
      anomalyFlags.push({
        id: `conc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        agent_id: agentId,
        anomaly_type: 'delegation_concentration' as AnomalyType,
        action_id: history[history.length - 1].action_id,
        description: `Concentration risk ${(risk * 100).toFixed(1)}%: retained ${(tasksRetainedRatio * 100).toFixed(0)}%, ${(singleAgentPct * 100).toFixed(0)}% complex without delegation`,
        review_mode: 'async' as ReviewMode,
        reviewed: false, review_outcome: null,
        created_at: new Date().toISOString(),
        assurance_class: 'evidentially_auditable' as AssuranceClass,
      })
    }
  }

  return {
    agent_id: agentId,
    tasks_retained_ratio: Math.round(tasksRetainedRatio * 1000) / 1000,
    scope_utilization_breadth: Math.round(scopeBreadth * 1000) / 1000,
    delegation_refusal_count: refusals,
    single_agent_workflow_pct: Math.round(singleAgentPct * 1000) / 1000,
    concentration_risk: Math.round(risk * 1000) / 1000,
    flagged, computed_at: new Date().toISOString(),
  }
}

export function reviewV2AnomalyFlag(flagId: string, outcome: string): AnomalyFlag | undefined {
  const flag = anomalyFlags.find(f => f.id === flagId)
  if (!flag) return undefined
  flag.reviewed = true
  flag.review_outcome = outcome
  return flag
}

export function clearV2AnomalyStores(): void {
  actionHistory.clear()
  anomalyFlags.length = 0
}
