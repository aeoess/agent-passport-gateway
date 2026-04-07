// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Plan Limits Enforcement
 *
 * Checks tenant plan limits before allowing agent registration,
 * delegation creation, or evaluation processing.
 */

import { getDB, PLAN_LIMITS } from '../db/schema.js'
import type { Plan } from '../db/schema.js'

export interface LimitCheck {
  allowed: boolean
  reason?: string
  current: number
  limit: number
}

/**
 * Check if tenant can register another agent
 */
export function checkAgentLimit(tenantId: string, plan: Plan): LimitCheck {
  const db = getDB()
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free
  if (limits.maxAgents === -1) return { allowed: true, current: 0, limit: -1 }

  const count = db.prepare(
    `SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`
  ).get(tenantId) as { c: number }

  return {
    allowed: count.c < limits.maxAgents,
    reason: count.c >= limits.maxAgents
      ? `Agent limit reached (${count.c}/${limits.maxAgents}). Upgrade plan at aeoess.com/portal.html`
      : undefined,
    current: count.c,
    limit: limits.maxAgents,
  }
}

/**
 * Check if tenant has evaluation budget remaining this month
 */
export function checkEvaluationLimit(tenantId: string, plan: Plan): LimitCheck {
  const db = getDB()
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free
  if (limits.evaluationsPerMonth === -1) return { allowed: true, current: 0, limit: -1 }

  const monthStart = new Date()
  monthStart.setDate(1)
  monthStart.setHours(0, 0, 0, 0)

  const count = db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations
     WHERE tenant_id = ? AND created_at >= ?`
  ).get(tenantId, monthStart.toISOString()) as { c: number }

  return {
    allowed: count.c < limits.evaluationsPerMonth,
    reason: count.c >= limits.evaluationsPerMonth
      ? `Monthly evaluation limit reached (${count.c}/${limits.evaluationsPerMonth}). Upgrade at aeoess.com/portal.html`
      : undefined,
    current: count.c,
    limit: limits.evaluationsPerMonth,
  }
}

/**
 * Get plan usage summary for dashboard/account endpoint
 */
export function getPlanUsageSummary(tenantId: string, plan: Plan) {
  const agents = checkAgentLimit(tenantId, plan)
  const evaluations = checkEvaluationLimit(tenantId, plan)
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free

  return {
    plan,
    agents: { current: agents.current, limit: agents.limit, at_limit: !agents.allowed },
    evaluations: { current: evaluations.current, limit: evaluations.limit, at_limit: !evaluations.allowed },
    features: {
      compliance_reports: limits.complianceReports,
      sla: limits.sla,
    },
  }
}
