// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Financial Observability API — FinOps for agent fleets.
 *
 * GET /api/v1/finops/agents/:agentId/spend  — per-agent spend summary
 * GET /api/v1/finops/dashboard              — tenant-wide spend dashboard
 * GET /api/v1/finops/cost-per-task          — cost per successful task
 *
 * All queries aggregate existing DB tables. No new data collection.
 */

import { Router } from 'express'
import { getDB } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'

export const finopsRouter = Router()

// ── Period helper ──

function periodToSqlInterval(period: string): string {
  switch (period) {
    case '24h': return '-1 day'
    case '7d':  return '-7 days'
    case '30d': return '-30 days'
    case 'all': return '-100 years'
    default:    return '-7 days'
  }
}

// ═══════════════════════════════════════
// GET /api/v1/finops/agents/:agentId/spend — Per-Agent Spend Summary
// ═══════════════════════════════════════

finopsRouter.get('/finops/agents/:agentId/spend', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params
    const period = (req.query.period as string) || '7d'
    const interval = periodToSqlInterval(period)

    // Check agent exists
    const agent = db.prepare(
      `SELECT agent_id FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!agent) {
      return res.status(404).json({ error: `Agent "${agentId}" not found` })
    }

    // Delegation for spend limit
    const delegation = db.prepare(
      `SELECT spend_limit, spend_used FROM delegations
       WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
       ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agentId) as any

    // Spend from wallet transactions (confirmed sends)
    const spendTotal = db.prepare(
      `SELECT COALESCE(SUM(CAST(amount_xno AS REAL)), 0) as total,
              COUNT(*) as count
       FROM wallet_transactions
       WHERE tenant_id = ? AND from_agent_id = ? AND status = 'confirmed'
         AND created_at > datetime('now', ?)`
    ).get(tenant.id, agentId, interval) as any

    // Also check payment_transactions for fiat spend
    const fiatSpend = db.prepare(
      `SELECT COALESCE(SUM(amount), 0) as total,
              COUNT(*) as count
       FROM payment_transactions
       WHERE tenant_id = ? AND status IN ('confirmed', 'completed')
         AND created_at > datetime('now', ?)`
    ).get(tenant.id, interval) as any

    const totalSpend = Math.round((delegation?.spend_used || 0) * 100)
    const transactionCount = (spendTotal?.count || 0) + (fiatSpend?.count || 0)
    const avgPerTransaction = transactionCount > 0 ? Math.round(totalSpend / transactionCount) : 0
    const spendLimit = delegation?.spend_limit ? Math.round(delegation.spend_limit * 100) : 0
    const utilizationPercent = spendLimit > 0
      ? Math.round((totalSpend / spendLimit) * 10000) / 100
      : 0

    // Spend by day
    const byDay = db.prepare(
      `SELECT DATE(created_at) as date,
              COUNT(*) as count
       FROM policy_evaluations
       WHERE tenant_id = ? AND agent_id = ? AND verdict = 'permit'
         AND created_at > datetime('now', ?)
       GROUP BY DATE(created_at)
       ORDER BY date DESC`
    ).all(tenant.id, agentId, interval) as any[]

    res.json({
      agentId,
      period,
      totalSpend,
      currency: 'usd',
      transactionCount,
      avgPerTransaction,
      spendLimit,
      utilizationPercent,
      byMerchant: [],
      byDay: byDay.map((d: any) => ({ date: d.date, spend: 0, count: d.count })),
    })
  } catch (e: any) {
    console.error('[finops-spend]', e.message)
    res.status(500).json({ error: 'Failed to compute spend summary' })
  }
})


// ═══════════════════════════════════════
// GET /api/v1/finops/dashboard — Tenant-Wide Spend Dashboard
// ═══════════════════════════════════════

finopsRouter.get('/finops/dashboard', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const period = (req.query.period as string) || '7d'
    const interval = periodToSqlInterval(period)

    // Total spend across all agents
    const totalSpendRow = db.prepare(
      `SELECT COALESCE(SUM(spend_used), 0) as total
       FROM delegations
       WHERE tenant_id = ? AND status = 'active'`
    ).get(tenant.id) as any
    const totalSpend = Math.round((totalSpendRow?.total || 0) * 100)

    // Agent count
    const agentCountRow = db.prepare(
      `SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`
    ).get(tenant.id) as any
    const agentCount = agentCountRow?.c || 0
    const avgSpendPerAgent = agentCount > 0 ? Math.round(totalSpend / agentCount) : 0

    // Top agents by spend
    const topAgents = db.prepare(
      `SELECT d.child_agent_id as agentId,
              ROUND(d.spend_used * 100) as spend,
              COUNT(e.id) as taskCount
       FROM delegations d
       LEFT JOIN policy_evaluations e
         ON e.tenant_id = d.tenant_id AND e.agent_id = d.child_agent_id
         AND e.verdict = 'permit' AND e.created_at > datetime('now', ?)
       WHERE d.tenant_id = ? AND d.status = 'active'
       GROUP BY d.child_agent_id
       ORDER BY d.spend_used DESC
       LIMIT 10`
    ).all(interval, tenant.id) as any[]

    // Budget health
    const budgetHealth = db.prepare(
      `SELECT
         SUM(CASE WHEN spend_limit > 0 AND spend_used >= spend_limit THEN 1 ELSE 0 END) as over_budget,
         SUM(CASE WHEN spend_limit > 0 AND spend_used >= spend_limit * 0.8 AND spend_used < spend_limit THEN 1 ELSE 0 END) as above_80,
         SUM(CASE WHEN spend_limit > 0 AND spend_used < spend_limit * 0.8 THEN 1 ELSE 0 END) as healthy,
         SUM(CASE WHEN spend_limit IS NULL OR spend_limit = 0 THEN 1 ELSE 0 END) as no_limit
       FROM delegations
       WHERE tenant_id = ? AND status = 'active'`
    ).get(tenant.id) as any

    // Evaluation stats for period
    const evalStats = db.prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN verdict = 'permit' THEN 1 ELSE 0 END) as permits,
              SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) as denials
       FROM policy_evaluations
       WHERE tenant_id = ? AND created_at > datetime('now', ?)`
    ).get(tenant.id, interval) as any

    const totalEvals = evalStats?.total || 0
    const permits = evalStats?.permits || 0
    const denials = evalStats?.denials || 0

    res.json({
      tenantId: tenant.id,
      period,
      totalSpend,
      agentCount,
      avgSpendPerAgent,
      topAgents: topAgents.map((a: any) => ({
        agentId: a.agentId,
        spend: a.spend || 0,
        taskCount: a.taskCount || 0,
      })),
      topMerchants: [],
      budgetHealth: {
        agentsOverBudget: budgetHealth?.over_budget || 0,
        agentsAbove80Percent: budgetHealth?.above_80 || 0,
        agentsHealthy: (budgetHealth?.healthy || 0) + (budgetHealth?.no_limit || 0),
      },
      evaluationStats: {
        totalEvaluations: totalEvals,
        permits,
        denials,
        denialRate: totalEvals > 0 ? Math.round((denials / totalEvals) * 10000) / 100 : 0,
      },
    })
  } catch (e: any) {
    console.error('[finops-dashboard]', e.message)
    res.status(500).json({ error: 'Failed to compute dashboard' })
  }
})


// ═══════════════════════════════════════
// GET /api/v1/finops/cost-per-task — Cost Per Successful Task
// ═══════════════════════════════════════

finopsRouter.get('/finops/cost-per-task', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const period = (req.query.period as string) || '7d'
    const interval = periodToSqlInterval(period)
    const agentFilter = req.query.agentId as string

    let evalQuery = `SELECT COUNT(*) as total,
           SUM(CASE WHEN verdict = 'permit' THEN 1 ELSE 0 END) as successful,
           SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) as failed
    FROM policy_evaluations
    WHERE tenant_id = ? AND created_at > datetime('now', ?)`
    const params: any[] = [tenant.id, interval]

    if (agentFilter) {
      evalQuery += ` AND agent_id = ?`
      params.push(agentFilter)
    }

    const tasks = db.prepare(evalQuery).get(...params) as any

    // Spend for this period
    let spendQuery = `SELECT COALESCE(SUM(spend_used), 0) as total
    FROM delegations WHERE tenant_id = ? AND status = 'active'`
    const spendParams: any[] = [tenant.id]

    if (agentFilter) {
      spendQuery += ` AND child_agent_id = ?`
      spendParams.push(agentFilter)
    }

    const spendRow = db.prepare(spendQuery).get(...spendParams) as any
    const totalSpend = Math.round((spendRow?.total || 0) * 100)

    const total = tasks?.total || 0
    const successful = tasks?.successful || 0
    const failed = tasks?.failed || 0
    const costPerTask = total > 0 ? Math.round(totalSpend / total) : 0
    const costPerSuccessfulTask = successful > 0 ? Math.round(totalSpend / successful) : 0
    const wastedSpend = total > 0 && failed > 0
      ? Math.round(totalSpend * (failed / total))
      : 0

    res.json({
      period,
      tasks: {
        total,
        successful,
        failed,
        successRate: total > 0 ? Math.round((successful / total) * 1000) / 10 : 0,
      },
      cost: {
        totalSpend,
        costPerTask,
        costPerSuccessfulTask,
        wastedSpend,
      },
    })
  } catch (e: any) {
    console.error('[finops-cost-per-task]', e.message)
    res.status(500).json({ error: 'Failed to compute cost-per-task' })
  }
})
