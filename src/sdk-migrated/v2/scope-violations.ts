// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Scope Violations (gateway copy — stateful ledger).
 *
 * The SDK exposes the pure constraint-check primitive
 * (evaluateSemanticConstraints). This module owns the scope registry and
 * violation ledger that used to live in src/v2/semantic-scoping.ts.
 * Migrated under the AAIF boundary refactor on 2026-04-17.
 */

import {
  evaluateSemanticConstraints,
  type SemanticConstraint, type SemanticScope, type ScopeViolation,
} from 'agent-passport-system'

const scopes: Map<string, SemanticScope> = new Map()
const violations: ScopeViolation[] = []

export function defineSemanticScope(params: {
  delegation_id: string; base_action: string; constraints: SemanticConstraint[];
}): SemanticScope {
  const s: SemanticScope = {
    id: `semscope-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    delegation_id: params.delegation_id,
    base_action: params.base_action,
    constraints: params.constraints,
    created_at: new Date().toISOString(),
  }
  scopes.set(s.id, s)
  return s
}

export function checkSemanticCompliance(
  scopeId: string, agentId: string, actionMetadata: Record<string, string>,
): { compliant: boolean; violations: ScopeViolation[] } {
  const scope = scopes.get(scopeId)
  if (!scope) throw new Error(`Scope ${scopeId} not found`)
  const result = evaluateSemanticConstraints(scope, agentId, actionMetadata)
  for (const v of result.violations) violations.push(v)
  return result
}

export function getScopeViolations(agentId?: string): ScopeViolation[] {
  return agentId ? violations.filter(v => v.agent_id === agentId) : [...violations]
}

export function clearSemanticScopingStores(): void {
  scopes.clear(); violations.length = 0
}
