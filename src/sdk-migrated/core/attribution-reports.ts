// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Attribution Report Generators — Product Policy
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). Merkle primitives and
// traceBeneficiary remain in the SDK; the weight-based report
// generators and their constant tables are product intelligence.
//
// Formula: weight = scope_weight × result × (1 + ln(1 + spend))
// ══════════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { v4 as uuidv4 } from 'uuid'
import {
  sign,
  canonicalize,
  hashReceipt, buildMerkleRoot,
} from 'agent-passport-system'
import type {
  ActionReceipt,
  AttributionEntry, AttributionReport,
} from 'agent-passport-system'

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

// ══════════════════════════════════════
// ATTRIBUTION WEIGHTS — CONFIGURABLE, NOT GOSPEL
// ══════════════════════════════════════

export const DEFAULT_SCOPE_WEIGHTS: Record<string, number> = {
  code_execution: 1.0,
  system_control: 0.9,
  data_analysis: 0.8,
  git_operations: 0.7,
  coordination: 0.6,
  file_management: 0.5,
  browser_automation: 0.5,
  email_management: 0.4,
  web_search: 0.3
}

const RESULT_MULTIPLIER: Record<string, number> = {
  success: 1.0,
  partial: 0.5,
  failure: 0.0
}

export interface AttributionConfig {
  scopeWeights?: Record<string, number>
  defaultScopeWeight?: number
}

export function computeAttribution(
  receipts: ActionReceipt[],
  agentId: string,
  beneficiary: string,
  privateKey: string,
  config?: AttributionConfig
): AttributionReport {
  const weights = config?.scopeWeights || DEFAULT_SCOPE_WEIGHTS
  const defaultWeight = config?.defaultScopeWeight ?? 0.3
  const agentReceipts = receipts.filter(r => r.agentId === agentId)

  const entries: AttributionEntry[] = agentReceipts.map(receipt => {
    const sw = weights[receipt.action.scopeUsed] ?? defaultWeight
    const rm = RESULT_MULTIPLIER[receipt.result.status] ?? 0
    const spend = receipt.action.spend?.amount || 0
    const weight = sw * rm * (1 + Math.log(1 + spend))

    return {
      receiptId: receipt.receiptId,
      agentId: receipt.agentId,
      action: receipt.action.type,
      scopeUsed: receipt.action.scopeUsed,
      spend,
      resultStatus: receipt.result.status,
      weight: Math.round(weight * 1000) / 1000,
      timestamp: receipt.timestamp
    }
  })

  const totalWeight = entries.reduce((sum, e) => sum + e.weight, 0)
  const timestamps = entries.map(e => e.timestamp).sort()
  const receiptHashes = agentReceipts.map(r => hashReceipt(r))
  const merkleRoot = buildMerkleRoot(receiptHashes)
  const entriesHash = sha256(canonicalize(entries))

  const report: Omit<AttributionReport, 'signature'> = {
    reportId: 'attr_' + uuidv4().slice(0, 12),
    beneficiary,
    agentId,
    period: {
      from: timestamps[0] || new Date().toISOString(),
      to: timestamps[timestamps.length - 1] || new Date().toISOString()
    },
    entries,
    totalWeight: Math.round(totalWeight * 1000) / 1000,
    receiptCount: agentReceipts.length,
    merkleRoot,
    entriesHash,
    generatedAt: new Date().toISOString()
  }

  const canonical = canonicalize(report)
  const signature = sign(canonical, privateKey)
  return { ...report, signature }
}

// ══════════════════════════════════════
// MULTI-AGENT COLLABORATION ATTRIBUTION
// ══════════════════════════════════════

export interface CollaborationAttribution {
  collaborationId: string
  participants: {
    agentId: string
    beneficiary: string
    weight: number
    percentage: number
    receiptCount: number
  }[]
  totalWeight: number
  merkleRoot: string
  generatedAt: string
}

export function computeCollaborationAttribution(
  allReceipts: ActionReceipt[],
  beneficiaryMap: Map<string, string>,
  config?: AttributionConfig
): CollaborationAttribution {
  const weights = config?.scopeWeights || DEFAULT_SCOPE_WEIGHTS
  const defaultWeight = config?.defaultScopeWeight ?? 0.3

  const byAgent = new Map<string, ActionReceipt[]>()
  for (const r of allReceipts) {
    const list = byAgent.get(r.agentId) || []
    list.push(r)
    byAgent.set(r.agentId, list)
  }

  const participants: CollaborationAttribution['participants'] = []
  let totalWeight = 0

  for (const [agentId, receipts] of byAgent) {
    const w = receipts.reduce((sum, r) => {
      const sw = weights[r.action.scopeUsed] ?? defaultWeight
      const rm = RESULT_MULTIPLIER[r.result.status] ?? 0
      const spend = r.action.spend?.amount || 0
      return sum + sw * rm * (1 + Math.log(1 + spend))
    }, 0)

    totalWeight += w
    participants.push({
      agentId,
      beneficiary: beneficiaryMap.get(agentId) || 'unknown',
      weight: Math.round(w * 1000) / 1000,
      percentage: 0,
      receiptCount: receipts.length
    })
  }

  for (const p of participants) {
    p.percentage = totalWeight > 0 ? Math.round((p.weight / totalWeight) * 10000) / 100 : 0
  }

  participants.sort((a, b) => b.percentage - a.percentage)

  return {
    collaborationId: 'collab_' + uuidv4().slice(0, 12),
    participants,
    totalWeight: Math.round(totalWeight * 1000) / 1000,
    merkleRoot: buildMerkleRoot(allReceipts.map(r => hashReceipt(r))),
    generatedAt: new Date().toISOString()
  }
}
