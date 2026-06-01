// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Wave 2 integration seam: contributor-weighted settlement
// ══════════════════════════════════════════════════════════════════
// GEM ships the plain receipt-batch Merkle path today (core/receipt-ledger
// + core/attribution string-hash leaves), which is stable in the installed
// SDK alpha.3. The axis-weighted contributor settlement Merkle path lives in
// the SDK Wave 2 module v2/attribution-settlement and is not part of the
// installed alpha. This file is the typed boundary GEM aggregates against so
// the Wave 2 surface can drop in without touching the aggregator.
//
// The SDK's own core/data-settlement generateSettlement / verifySettlement
// are deprecated stubs that throw by design; the settlement implementation
// home is the gateway. GEM therefore never calls those SDK functions.
// ══════════════════════════════════════════════════════════════════

/** A contributor-weighted leaf, as the Wave 2 axis-weighted settlement path
 *  would produce. Kept as a typed shape so callers and tests can describe the
 *  seam without the Wave 2 module being present. */
export interface ContributorLeaf {
  contributorId: string
  /** Normalized axis weight in [0, 1]. */
  weight: number
  /** Hex leaf digest the Wave 2 path would derive for this contributor. */
  leafHash: string
}

export interface ContributorSettlementResult {
  /** Whether the contributor-weighted path was actually computed. While the
   *  Wave 2 module is stubbed this is false and the plain receipt-batch root
   *  is authoritative. */
  computed: boolean
  /** Axis-weighted Merkle root, when computed. */
  merkleRoot: string | null
  /** Reason the path was not computed (stub marker), when applicable. */
  reason?: string
}

/**
 * Compute the contributor-weighted (axis-weighted) settlement root.
 *
 * STUB: returns computed:false until the Wave 2 module is wired. The plain
 * receipt-batch Merkle root from the aggregator is authoritative in the
 * meantime, so callers do not block on this.
 *
 * // TODO(W2-attribution-settlement): replace this stub with the SDK
 * //   v2/attribution-settlement path (aggregateAttributionPrimitives,
 * //   buildContributorMerklePath, signSettlementRecord, verifySettlementRecord).
 */
export function computeContributorSettlement(
  _leaves: readonly ContributorLeaf[],
): ContributorSettlementResult {
  return {
    computed: false,
    merkleRoot: null,
    reason: 'wave2_attribution_settlement_not_installed',
  }
}

/** Whether the contributor-weighted Wave 2 path is available. Always false
 *  against the installed alpha; flips when the Wave 2 module is wired. */
export function contributorSettlementAvailable(): boolean {
  return false
}
