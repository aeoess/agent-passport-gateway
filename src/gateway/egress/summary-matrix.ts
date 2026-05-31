// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Structural Summary Matrix
// ══════════════════════════════════════════════════════════════════
// The structural summary that travels downstream with the Merkle root. It is
// a small, aggregate-only matrix: counts bucketed by the dimensions a SIEM
// cares about (verdict, action class) plus the batch envelope. It carries no
// per-receipt payload, so streaming it costs a fixed small amount regardless
// of how many receipts the batch aggregated. Granular leaves stay in the
// outbox and are fetched out of band on anomaly.
// ══════════════════════════════════════════════════════════════════

/** A single receipt's structural facts, the only inputs the summary needs.
 *  Intentionally free of payload, tenant, principal, or spend fields. */
export interface SummaryInput {
  verdict?: string | null
  actionType?: string | null
}

/** Aggregate structural summary for a batch. Counts only. */
export interface SummaryMatrix {
  total: number
  byVerdict: Record<string, number>
  byActionType: Record<string, number>
}

const UNKNOWN = 'unknown'

/** Build the structural summary from the batch's structural inputs. Counts
 *  are deterministic given the same multiset of inputs. */
export function buildSummaryMatrix(inputs: readonly SummaryInput[]): SummaryMatrix {
  const byVerdict: Record<string, number> = {}
  const byActionType: Record<string, number> = {}
  for (const item of inputs) {
    const verdict = normalizeKey(item.verdict)
    const action = normalizeKey(item.actionType)
    byVerdict[verdict] = (byVerdict[verdict] || 0) + 1
    byActionType[action] = (byActionType[action] || 0) + 1
  }
  return { total: inputs.length, byVerdict, byActionType }
}

function normalizeKey(value: string | null | undefined): string {
  if (typeof value !== 'string') return UNKNOWN
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : UNKNOWN
}

/** Cross-check that a summary's bucket counts sum to its declared total.
 *  Returns false if a downstream summary was truncated or tampered with. */
export function summaryMatrixConsistent(matrix: SummaryMatrix): boolean {
  const verdictSum = sumValues(matrix.byVerdict)
  const actionSum = sumValues(matrix.byActionType)
  return verdictSum === matrix.total && actionSum === matrix.total
}

function sumValues(rec: Record<string, number>): number {
  let total = 0
  for (const v of Object.values(rec)) total += v
  return total
}
