// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Read-only cascade-preview seam for the revocation-RECOMMENDATION automation.
 *
 * G-B2 owns previewCascade (read-only blast-radius before a revoke). B2 is NOT
 * merged into this base, so we depend on its PUBLIC surface only and stub the
 * import. The revocation-recommendation automation (layer b) calls previewCascade
 * ONLY and surfaces recommendedActions; it MUST NOT call bumpEpoch / panicFreeze.
 * Recommend, never silently revoke.
 *
 * B2 public surface consumed (from .../revocation/cascade.ts):
 *   - previewCascade({ tenantId, targetType, targetId }): CascadePreview
 *   - walkDescendants(tenantId, rootAgentId): DelegationNode[]
 *   - type CascadeAction = 'revoke_now' | 'schedule' | 'freeze_first' | 'approval_only'
 *
 * TODO(G-B2 / gw-b2-revocation): replace the body with a direct import:
 *   import { previewCascade, walkDescendants } from '../revocation/index.js'
 * The shape returned here is a faithful subset of B2's CascadePreview so the swap
 * is mechanical. We deliberately do NOT import or call any mutating B2 function
 * (bumpEpoch/panicFreeze) from the recommendation path.
 */

import { getDB } from '../../db/schema.js'

export type CascadeActionSeam = 'revoke_now' | 'schedule' | 'freeze_first' | 'approval_only'

export interface DelegationNodeSeam {
  delegationId: string
  parent: string
  child: string
  scope: string[]
  status: string
  depth: number
}

/** Faithful subset of B2's CascadePreview. Read-only; changes nothing. */
export interface CascadePreviewSeam {
  tenantId: string
  targetType: 'agent' | 'delegation' | 'data_source'
  targetId: string
  affectedDelegations: DelegationNodeSeam[]
  affectedAgents: string[]
  activeWorkflows: number
  totalRevoked: number
  chainDepth: number
  recommendedActions: CascadeActionSeam[]
  generatedAt: string
}

const MAX_DEPTH = 32

/**
 * Mirror of B2 walkDescendants: forward delegation-tree descendants from a root
 * agent. Cycle-guarded by a seen-set and depth cap (non-Turing-complete walk).
 * Reads the same `delegations` table B2 reads. Pure read.
 */
export function walkDescendantsSeam(tenantId: string, rootAgentId: string): DelegationNodeSeam[] {
  const db = getDB()
  const out: DelegationNodeSeam[] = []
  const seenEdges = new Set<string>()
  const frontier: Array<{ agent: string; depth: number }> = [{ agent: rootAgentId, depth: 0 }]

  while (frontier.length > 0) {
    const { agent, depth } = frontier.shift()!
    if (depth >= MAX_DEPTH) continue
    const children = db.prepare(
      `SELECT id, parent_agent_id, child_agent_id, scope, status FROM delegations
       WHERE tenant_id = ? AND parent_agent_id = ? AND status = 'active'`,
    ).all(tenantId, agent) as any[]
    for (const c of children) {
      const edge = `${c.parent_agent_id}->${c.child_agent_id}`
      if (seenEdges.has(edge)) continue
      seenEdges.add(edge)
      const scopes = c.scope ? String(c.scope).split(',').map((s: string) => s.trim()).filter(Boolean) : []
      out.push({
        delegationId: c.id,
        parent: c.parent_agent_id,
        child: c.child_agent_id,
        scope: scopes,
        status: c.status,
        depth: depth + 1,
      })
      frontier.push({ agent: c.child_agent_id, depth: depth + 1 })
    }
  }
  return out
}

/**
 * Mirror of B2 previewCascade for targetType 'agent' (the recommendation path's
 * only need). READ-ONLY: it computes the blast radius and recommended action
 * options; it never mutates. The automation surfaces recommendedActions and
 * stops - the actual revoke/freeze stays the authenticated operator's call.
 */
export function previewCascadeSeam(opts: {
  tenantId: string
  targetType: 'agent' | 'delegation' | 'data_source'
  targetId: string
}): CascadePreviewSeam {
  const { tenantId, targetType, targetId } = opts
  let affectedDelegations: DelegationNodeSeam[] = []
  const agentSet = new Set<string>([targetId])

  if (targetType === 'agent') {
    affectedDelegations = walkDescendantsSeam(tenantId, targetId)
    for (const d of affectedDelegations) agentSet.add(d.child)
  } else if (targetType === 'delegation') {
    const db = getDB()
    const del = db.prepare(
      `SELECT id, parent_agent_id, child_agent_id, scope, status FROM delegations WHERE tenant_id = ? AND id = ?`,
    ).get(tenantId, targetId) as any
    if (del) {
      const scopes = del.scope ? String(del.scope).split(',').map((s: string) => s.trim()).filter(Boolean) : []
      affectedDelegations = [
        { delegationId: del.id, parent: del.parent_agent_id, child: del.child_agent_id, scope: scopes, status: del.status, depth: 1 },
        ...walkDescendantsSeam(tenantId, del.child_agent_id),
      ]
      agentSet.clear()
      agentSet.add(del.child_agent_id)
      for (const d of affectedDelegations) agentSet.add(d.child)
    }
  }

  const activeWorkflows = affectedDelegations.filter(d => d.status === 'active').length
  const chainDepth = affectedDelegations.reduce((m, d) => Math.max(m, d.depth), 0)
  const totalRevoked = affectedDelegations.length

  // Recommended-action heuristic mirrors B2 intent: a wider blast radius leans
  // toward freeze-first / approval-only rather than revoke-now. This is ADVICE.
  const recommendedActions: CascadeActionSeam[] = []
  if (totalRevoked === 0) {
    recommendedActions.push('revoke_now')
  } else if (chainDepth <= 1 && totalRevoked <= 2) {
    recommendedActions.push('revoke_now', 'schedule')
  } else if (activeWorkflows > 0) {
    recommendedActions.push('freeze_first', 'approval_only')
  } else {
    recommendedActions.push('schedule', 'approval_only')
  }

  return {
    tenantId,
    targetType,
    targetId,
    affectedDelegations,
    affectedAgents: [...agentSet],
    activeWorkflows,
    totalRevoked,
    chainDepth,
    recommendedActions,
    generatedAt: new Date().toISOString(),
  }
}
