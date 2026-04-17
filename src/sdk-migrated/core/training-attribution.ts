// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Training Attribution Receipt
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). Product intelligence —
// tracks when agent outputs derived from data sources are used for
// training, fine-tuning, or embedding generation. Links access receipts
// to downstream training events.
//
// The chain: data source → access receipt → agent output → training event
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'

// ── Training Event Types ──

export type TrainingUseType =
  | 'fine_tune'
  | 'lora_adapter'
  | 'embedding'
  | 'rag_index'
  | 'distillation'
  | 'evaluation'
  | 'synthetic_data'

// ── Training Attribution Receipt ──

export interface TrainingAttributionReceipt {
  trainingReceiptId: string
  trainingUseType: TrainingUseType
  modelId: string
  modelVersion?: string
  trainerId: string
  trainerPublicKey: string
  sourceAccessReceiptIds: string[]
  sourceContributionIds?: string[]
  executionFrameId: string
  outputContentHash: string
  inputDataHashes: string[]
  contributionWeights?: Record<string, number>
  timestamp: string
  datasetSize?: number
  trainingSplit?: 'train' | 'validation' | 'test'
  signature: string
}

// ── Training Attribution Verification ──

export interface TrainingAttributionVerification {
  valid: boolean
  errors: string[]
  signatureValid: boolean
  sourcesTraceable: boolean
  weightsValid: boolean
}

// ── Create Training Attribution Receipt ──

export function createTrainingAttribution(opts: {
  trainingUseType: TrainingUseType
  modelId: string
  modelVersion?: string
  trainerId: string
  trainerPublicKey: string
  trainerPrivateKey: string
  sourceAccessReceiptIds: string[]
  sourceContributionIds?: string[]
  executionFrameId: string
  outputContentHash: string
  inputDataHashes: string[]
  contributionWeights?: Record<string, number>
  datasetSize?: number
  trainingSplit?: 'train' | 'validation' | 'test'
}): TrainingAttributionReceipt {
  const payload = JSON.stringify({
    trainingUseType: opts.trainingUseType,
    modelId: opts.modelId,
    trainerId: opts.trainerId,
    sourceAccessReceiptIds: opts.sourceAccessReceiptIds,
    outputContentHash: opts.outputContentHash,
    timestamp: new Date().toISOString(),
  })
  const signature = crypto.createHash('sha256').update(payload + opts.trainerPrivateKey).digest('hex')

  return {
    trainingReceiptId: 'trar_' + crypto.randomUUID(),
    trainingUseType: opts.trainingUseType,
    modelId: opts.modelId,
    modelVersion: opts.modelVersion,
    trainerId: opts.trainerId,
    trainerPublicKey: opts.trainerPublicKey,
    sourceAccessReceiptIds: opts.sourceAccessReceiptIds,
    sourceContributionIds: opts.sourceContributionIds,
    executionFrameId: opts.executionFrameId,
    outputContentHash: opts.outputContentHash,
    inputDataHashes: opts.inputDataHashes,
    contributionWeights: opts.contributionWeights,
    timestamp: new Date().toISOString(),
    datasetSize: opts.datasetSize,
    trainingSplit: opts.trainingSplit,
    signature,
  }
}

// ── Verify Training Attribution Receipt ──

export function verifyTrainingAttribution(
  receipt: TrainingAttributionReceipt,
  knownAccessReceiptIds?: Set<string>,
): TrainingAttributionVerification {
  const errors: string[] = []

  const signatureValid = !!receipt.signature && receipt.signature.length === 64
  if (!signatureValid) errors.push('Invalid or missing signature')

  let sourcesTraceable = true
  if (knownAccessReceiptIds) {
    for (const id of receipt.sourceAccessReceiptIds) {
      if (!knownAccessReceiptIds.has(id)) {
        sourcesTraceable = false
        errors.push(`Referenced access receipt ${id} not found`)
      }
    }
  }

  let weightsValid = true
  if (receipt.contributionWeights) {
    const sum = Object.values(receipt.contributionWeights).reduce((s, w) => s + w, 0)
    if (Math.abs(sum - 1.0) > 0.01) {
      weightsValid = false
      errors.push(`Contribution weights sum to ${sum}, expected ~1.0`)
    }
    for (const id of Object.keys(receipt.contributionWeights)) {
      if (!receipt.sourceAccessReceiptIds.includes(id)) {
        weightsValid = false
        errors.push(`Weight references unknown access receipt ${id}`)
      }
    }
  }

  return {
    valid: errors.length === 0 && signatureValid,
    errors,
    signatureValid,
    sourcesTraceable,
    weightsValid,
  }
}

// ── Training Attribution Ledger ──

export interface TrainingAttributionLedger {
  receipts: Map<string, TrainingAttributionReceipt>
  byModel: Map<string, Set<string>>
  bySource: Map<string, Set<string>>
  byTrainer: Map<string, Set<string>>
}

export function createTrainingLedger(): TrainingAttributionLedger {
  return {
    receipts: new Map(),
    byModel: new Map(),
    bySource: new Map(),
    byTrainer: new Map(),
  }
}

function addToSet(map: Map<string, Set<string>>, key: string, value: string): void {
  if (!map.has(key)) map.set(key, new Set())
  map.get(key)!.add(value)
}

export function recordTrainingAttribution(
  ledger: TrainingAttributionLedger,
  receipt: TrainingAttributionReceipt,
): void {
  ledger.receipts.set(receipt.trainingReceiptId, receipt)
  addToSet(ledger.byModel, receipt.modelId, receipt.trainingReceiptId)
  addToSet(ledger.byTrainer, receipt.trainerId, receipt.trainingReceiptId)
  for (const srcId of receipt.sourceAccessReceiptIds) {
    addToSet(ledger.bySource, srcId, receipt.trainingReceiptId)
  }
}

export function getModelDataSources(
  ledger: TrainingAttributionLedger,
  modelId: string,
): { accessReceiptId: string; weight: number; trainingUseType: TrainingUseType }[] {
  const trainingIds = ledger.byModel.get(modelId)
  if (!trainingIds) return []

  const sources: Map<string, { weight: number; useType: TrainingUseType }> = new Map()
  for (const tid of trainingIds) {
    const receipt = ledger.receipts.get(tid)!
    for (const srcId of receipt.sourceAccessReceiptIds) {
      const weight = receipt.contributionWeights?.[srcId] ?? (1 / receipt.sourceAccessReceiptIds.length)
      const existing = sources.get(srcId)
      if (existing) {
        existing.weight += weight
      } else {
        sources.set(srcId, { weight, useType: receipt.trainingUseType })
      }
    }
  }

  return Array.from(sources.entries()).map(([id, v]) => ({
    accessReceiptId: id, weight: v.weight, trainingUseType: v.useType,
  }))
}

export function getSourceTrainingCount(
  ledger: TrainingAttributionLedger,
  accessReceiptId: string,
): number {
  return ledger.bySource.get(accessReceiptId)?.size ?? 0
}


// ══════════════════════════════════════════════════════════════════════
// Derivation Chain — Multi-Hop Training Attribution
// ══════════════════════════════════════════════════════════════════════

export interface DerivationRecord {
  derivationId: string
  agentId: string
  agentPublicKey: string
  outputContentHash: string
  outputDescription: string
  sourceAccessReceiptIds: string[]
  sourceWeights?: Record<string, number>
  executionFrameId: string
  timestamp: string
  signature: string
}

export function createDerivation(opts: {
  agentId: string
  agentPublicKey: string
  agentPrivateKey: string
  outputContentHash: string
  outputDescription: string
  sourceAccessReceiptIds: string[]
  sourceWeights?: Record<string, number>
  executionFrameId: string
}): DerivationRecord {
  const payload = JSON.stringify({
    agentId: opts.agentId,
    outputContentHash: opts.outputContentHash,
    sourceAccessReceiptIds: opts.sourceAccessReceiptIds,
    timestamp: new Date().toISOString(),
  })
  const signature = crypto.createHash('sha256').update(payload + opts.agentPrivateKey).digest('hex')

  return {
    derivationId: 'derv_' + crypto.randomUUID(),
    agentId: opts.agentId,
    agentPublicKey: opts.agentPublicKey,
    outputContentHash: opts.outputContentHash,
    outputDescription: opts.outputDescription,
    sourceAccessReceiptIds: opts.sourceAccessReceiptIds,
    sourceWeights: opts.sourceWeights,
    executionFrameId: opts.executionFrameId,
    timestamp: new Date().toISOString(),
    signature,
  }
}

export interface DerivationStore {
  records: Map<string, DerivationRecord>
  byOutput: Map<string, string>
  bySource: Map<string, Set<string>>
}

export function createDerivationStore(): DerivationStore {
  return { records: new Map(), byOutput: new Map(), bySource: new Map() }
}

export function recordDerivation(store: DerivationStore, record: DerivationRecord): void {
  store.records.set(record.derivationId, record)
  store.byOutput.set(record.outputContentHash, record.derivationId)
  for (const srcId of record.sourceAccessReceiptIds) {
    if (!store.bySource.has(srcId)) store.bySource.set(srcId, new Set())
    store.bySource.get(srcId)!.add(record.derivationId)
  }
}

export interface ResolvedAttribution {
  originalAccessReceiptId: string
  transitiveWeight: number
  hops: number
  path: string[]
}

export function resolveAttributionChain(
  trainingReceipt: TrainingAttributionReceipt,
  derivationStore: DerivationStore,
  maxDepth: number = 10,
): ResolvedAttribution[] {
  const results: Map<string, ResolvedAttribution> = new Map()
  const visited: Set<string> = new Set()

  function resolve(
    accessReceiptId: string,
    weight: number,
    depth: number,
    path: string[],
  ): void {
    if (depth > maxDepth) return
    if (visited.has(accessReceiptId)) {
      const existing = results.get(accessReceiptId)
      if (existing) { existing.transitiveWeight += weight }
      else { results.set(accessReceiptId, { originalAccessReceiptId: accessReceiptId, transitiveWeight: weight, hops: depth, path: [...path] }) }
      return
    }
    visited.add(accessReceiptId)

    const derivations = derivationStore.bySource.get(accessReceiptId)

    if (!derivations || derivations.size === 0) {
      const existing = results.get(accessReceiptId)
      if (existing) {
        existing.transitiveWeight += weight
      } else {
        results.set(accessReceiptId, {
          originalAccessReceiptId: accessReceiptId,
          transitiveWeight: weight,
          hops: depth,
          path: [...path],
        })
      }
      return
    }

    for (const derivId of derivations) {
      const deriv = derivationStore.records.get(derivId)!
      for (const srcId of deriv.sourceAccessReceiptIds) {
        const srcWeight = deriv.sourceWeights?.[srcId]
          ?? (1 / deriv.sourceAccessReceiptIds.length)
        resolve(srcId, weight * srcWeight, depth + 1, [...path, derivId])
      }
    }
  }

  for (const srcId of trainingReceipt.sourceAccessReceiptIds) {
    const weight = trainingReceipt.contributionWeights?.[srcId]
      ?? (1 / trainingReceipt.sourceAccessReceiptIds.length)
    resolve(srcId, weight, 0, [])
  }

  return Array.from(results.values()).sort((a, b) => b.transitiveWeight - a.transitiveWeight)
}
