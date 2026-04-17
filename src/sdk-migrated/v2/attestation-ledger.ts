// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS v2 Contextual Attestation Ledger (gateway copy — stateful).
 *
 * The SDK exposes signAttestation (primitive creation from params) and
 * assessV2AttestationQuality (pure quality scoring). This module owns
 * the attestation store and per-agent aggregate queries that used to
 * live in src/v2/attestation-v2.ts. Migrated under the AAIF boundary
 * refactor on 2026-04-17.
 */

import {
  signAttestation, assessV2AttestationQuality,
  type ContextualAttestation,
  type PolicyContext, type SemanticUncertainty, type AlternativeRejected,
} from 'agent-passport-system'

const attestationStore: Map<string, ContextualAttestation> = new Map()

export function getV2Attestation(id: string) { return attestationStore.get(id) }
export function getV2AttestationForAction(actionId: string) {
  return Array.from(attestationStore.values()).find(a => a.action_id === actionId)
}
export function getV2AttestationsForAgent(agentId: string) {
  return Array.from(attestationStore.values()).filter(a => a.agent_id === agentId)
}

export function createV2Attestation(params: {
  action_id: string
  agent_id: string
  delegation_ref: string
  context_understanding: string
  factors_considered: string[]
  alternatives_rejected: AlternativeRejected[]
  expected_outcome: string
  confidence: number
  semantic_uncertainty: SemanticUncertainty
  required: boolean
  policy_context: PolicyContext
  agent_private_key: string
}): ContextualAttestation {
  const att = signAttestation(params)
  attestationStore.set(att.id, att)
  return att
}

export function getV2AgentAttestationQualityAvg(agentId: string): number {
  const atts = getV2AttestationsForAgent(agentId)
  if (atts.length === 0) return 0
  const total = atts.reduce((s, a) => s + assessV2AttestationQuality(a).quality_score, 0)
  return Math.round((total / atts.length) * 100) / 100
}

export function clearV2AttestationStore(): void { attestationStore.clear() }
