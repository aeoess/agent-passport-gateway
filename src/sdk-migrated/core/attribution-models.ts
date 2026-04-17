// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Attribution Models — gateway product policy
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK (data-source-attribution.ts) on 2026-04-17. The SDK
// keeps Merkle commitment + signed-report shape + the schema baseline
// 'equal' model + caller-supplied 'custom' weights. The weighted models
// (access_weighted, recency_weighted) live here because their hardcoded
// constants — most importantly the 1-day half-life on recency decay —
// are gateway tuning decisions per pricing surface, not protocol
// primitives.
//
// Usage: call computeAccessWeights or computeRecencyWeights to produce
// a customWeights map, then call the SDK's computeDataSourceAttribution
// with model='custom' and the resulting map.
// ══════════════════════════════════════════════════════════════════════

import { computeDataSourceAttribution } from 'agent-passport-system'
import type {
  DataAccessReceipt, DataSourceAttributionReport,
} from 'agent-passport-system'

/** Gateway product policy: half-life used by recency_weighted decay.
 *  Tuned for a daily news-velocity pricing surface. */
export const RECENCY_HALF_LIFE_MS = 24 * 60 * 60 * 1000 // 1 day

// ══════════════════════════════════════════════════════════════════════
// WEIGHT COMPUTERS
// ══════════════════════════════════════════════════════════════════════

function groupBySource(receipts: DataAccessReceipt[]): Map<string, DataAccessReceipt[]> {
  const grouped = new Map<string, DataAccessReceipt[]>()
  for (const r of receipts) {
    const list = grouped.get(r.sourceReceiptId) || []
    list.push(r)
    grouped.set(r.sourceReceiptId, list)
  }
  return grouped
}

/** access_weighted: more accesses → higher contribution. Returns
 *  un-normalized counts; the SDK 'custom' path normalizes them. */
export function computeAccessWeights(receipts: DataAccessReceipt[]): Map<string, number> {
  const grouped = groupBySource(receipts)
  const weights = new Map<string, number>()
  for (const [sourceId, list] of grouped) weights.set(sourceId, list.length)
  return weights
}

/** recency_weighted: exponential decay on time-since-most-recent-access.
 *  Half-life is gateway product policy — see RECENCY_HALF_LIFE_MS. */
export function computeRecencyWeights(
  receipts: DataAccessReceipt[],
  halfLifeMs: number = RECENCY_HALF_LIFE_MS,
  now: number = Date.now(),
): Map<string, number> {
  const grouped = groupBySource(receipts)
  const weights = new Map<string, number>()
  for (const [sourceId, list] of grouped) {
    const mostRecent = Math.max(...list.map(r => new Date(r.timestamp).getTime()))
    const age = now - mostRecent
    const decay = Math.pow(2, -age / halfLifeMs)
    weights.set(sourceId, decay)
  }
  return weights
}

// ══════════════════════════════════════════════════════════════════════
// CONVENIENCE WRAPPERS — call SDK with pre-computed weights
// ══════════════════════════════════════════════════════════════════════

export interface WeightedAttributionOptions {
  outputArtifactId: string
  outputType: 'decision' | 'content' | 'model' | 'action'
  accessReceipts: DataAccessReceipt[]
  sourceDescriptors?: Map<string, string>
  generatorPublicKey: string
  generatorPrivateKey: string
}

/** Note: returned report's signed `attributionModel` field will be
 *  'custom' because that is what was actually signed by the SDK. The
 *  gateway helper merely supplies the access-weighted custom weights. */
export function computeAccessWeightedAttribution(
  opts: WeightedAttributionOptions,
): DataSourceAttributionReport {
  const customWeights = computeAccessWeights(opts.accessReceipts)
  return computeDataSourceAttribution({
    ...opts,
    model: 'custom',
    customWeights,
  })
}

export interface RecencyAttributionOptions extends WeightedAttributionOptions {
  /** Override the gateway default half-life. */
  halfLifeMs?: number
  /** Override the time anchor used for decay calculation (testing). */
  now?: number
}

/** Note: returned report's signed `attributionModel` field will be
 *  'custom' because that is what was actually signed by the SDK. The
 *  gateway helper merely supplies the recency-decayed custom weights. */
export function computeRecencyWeightedAttribution(
  opts: RecencyAttributionOptions,
): DataSourceAttributionReport {
  const customWeights = computeRecencyWeights(
    opts.accessReceipts,
    opts.halfLifeMs ?? RECENCY_HALF_LIFE_MS,
    opts.now ?? Date.now(),
  )
  return computeDataSourceAttribution({
    outputArtifactId: opts.outputArtifactId,
    outputType: opts.outputType,
    accessReceipts: opts.accessReceipts,
    sourceDescriptors: opts.sourceDescriptors,
    generatorPublicKey: opts.generatorPublicKey,
    generatorPrivateKey: opts.generatorPrivateKey,
    model: 'custom',
    customWeights,
  })
}
