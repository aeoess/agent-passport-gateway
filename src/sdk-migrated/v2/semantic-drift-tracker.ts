// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Semantic Drift Tracker (gateway copy — stateful ledger).
 *
 * The SDK exposes only the pure keyword/similarity math (extractKeywords,
 * computeSemanticDrift). This module owns the intent-record ledger and
 * aggregate drift queries that used to live in src/v2/semantic-drift.ts.
 * Migrated under the AAIF boundary refactor on 2026-04-17.
 */

import {
  extractKeywords, computeSemanticDrift,
  type SemanticIntentRecord, type SemanticDriftResult,
} from 'agent-passport-system'

// ── Stores ──
const intentRecords: Map<string, SemanticIntentRecord> = new Map()
const driftResults: SemanticDriftResult[] = []

export function recordSemanticIntent(params: {
  agent_id: string; intent_id: string;
  declared_purpose: string; action_description: string;
  scope_ref: string;
}): SemanticIntentRecord {
  const declared_keywords = extractKeywords(params.declared_purpose)
  const action_keywords = extractKeywords(params.action_description)
  const record: SemanticIntentRecord = {
    id: `sem-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agent_id: params.agent_id,
    intent_id: params.intent_id,
    declared_purpose: params.declared_purpose,
    declared_keywords,
    action_description: params.action_description,
    action_keywords,
    scope_ref: params.scope_ref,
    timestamp: new Date().toISOString(),
  }
  intentRecords.set(record.id, record)
  return record
}

export function analyzeSemanticDrift(recordId: string): SemanticDriftResult {
  const record = intentRecords.get(recordId)
  if (!record) throw new Error(`Record ${recordId} not found`)
  const result = computeSemanticDrift(record)
  driftResults.push(result)
  return result
}

export function getDriftResults(agentId?: string): SemanticDriftResult[] {
  if (agentId) return driftResults.filter(r => r.agent_id === agentId)
  return [...driftResults]
}

export function getAgentDriftAverage(agentId: string): number {
  const results = getDriftResults(agentId)
  if (results.length === 0) return 0
  return results.reduce((s, r) => s + r.drift_score, 0) / results.length
}

export function isAgentSemanticRisk(agentId: string, threshold?: number): boolean {
  return getAgentDriftAverage(agentId) > (threshold || 0.5)
}

export function getSemanticRecord(id: string): SemanticIntentRecord | undefined {
  return intentRecords.get(id)
}

export function clearSemanticDriftStores(): void {
  intentRecords.clear()
  driftResults.length = 0
}
