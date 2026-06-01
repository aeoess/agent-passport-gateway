// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D2 - hash-manifest Merkle backbone selection.
// ══════════════════════════════════════════════════════════════════
// The bundle hash-manifest needs ONE tamper-evidence backbone. There are two
// existing producers of Merkle roots over receipts in the gateway, and a third
// in the not-yet-merged G-A1 event spine. G-D2 introduces no fourth Merkle
// implementation: it canonicalizes leaves with the SDK and folds them with the
// SDK buildMerkleRoot, and it can reference the existing receipt_window_seals
// or the G-A1 batch root when those are present.
//
// Backbone preference order:
//   1. G-A1 GEM batch root + proveLeafInBatch inclusion proofs (when A1 lands).
//   2. existing enforce.ts receipt_window_seals commitment (when a seal covers
//      the in-scope receipts).
//   3. SDK buildMerkleRoot over the bundle's own canonical leaf hashes.
//
// Today the assembler always has path 3 available and references path 2 when a
// seal exists. Path 1 is stubbed behind a typed seam until A1 merges to base.
// ══════════════════════════════════════════════════════════════════

import {
  buildMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  canonicalize,
  canonicalHash,
} from 'agent-passport-system'
import type { BundleLeaf } from './types.js'

// ── G-A1 event-spine seam ──────────────────────────────────────────
// The G-A1 egress surface (MerkleAggregator / proveLeafInBatch / verifyLeafProof
// / fetchLeaves) is the preferred backbone. G-A1 is a local branch NOT merged
// into this module's base, so the import is stubbed. Its public surface, read
// from gw-a1-event-merkle/src/gateway/egress/index.ts, is:
//   proveLeafInBatch(batch, leafHash): ReceiptInclusionProof | null
//   verifyLeafProof(proof): boolean
//   fetchLeaves(tenantId, batchId): LeafRecord[]
//   EgressEnvelope { batchId, merkleRoot, epoch, ... }
//
// TODO(G-A1 / gw-a1-event-merkle): replace gemBatchBackbone() with a real
//   import { proveLeafInBatch, verifyLeafProof, fetchLeaves } from
//   '../egress/index.js' and pull batch merkleRoot + per-leaf inclusion proofs
//   once A1 lands on base. Until then this returns available:false and the
//   assembler falls back to the SDK leaf-Merkle path.

export interface GemBatchBackboneResult {
  available: boolean
  merkleRoot: string | null
  /** Inclusion proofs keyed by leafHash, when available. */
  inclusionProofs: Record<string, unknown> | null
  reason?: string
}

export function gemBatchBackbone(
  _tenantId: string,
  _leafHashes: readonly string[],
): GemBatchBackboneResult {
  return {
    available: false,
    merkleRoot: null,
    inclusionProofs: null,
    reason: 'g_a1_event_spine_not_merged_to_base',
  }
}

/** Whether the G-A1 batch backbone is available on the current base. */
export function gemBatchBackboneAvailable(): boolean {
  return false
}

// ── Canonical leaf hashing (SDK, frozen primitive path) ─────────────

/**
 * Canonical hash of a record for a hash-manifest leaf. Uses the SDK
 * canonicalize + canonicalHash so an external verifier reaches the same leaf
 * hash regardless of property ordering. We do NOT hand-roll a canonicalizer;
 * the SDK canonicalize is the cross-verifier-stable form.
 */
export function canonicalLeafHash(record: Record<string, unknown>): string {
  return canonicalHash(record)
}

/** Canonical string form of a record, for the verifier instructions. */
export function canonicalForm(record: Record<string, unknown>): string {
  return canonicalize(record)
}

// ── SDK leaf-Merkle backbone (always available fallback) ────────────

export interface LeafMerkleResult {
  merkleRoot: string
  /** Inclusion proof per leaf hash. */
  inclusionProofs: Record<string, unknown>
}

/**
 * Fold the bundle's own canonical leaf hashes into a Merkle root with the SDK
 * buildMerkleRoot, and generate an inclusion proof per leaf. This is the
 * always-available backbone used when neither the G-A1 batch root nor an
 * existing receipt-window seal covers the in-scope records.
 */
export function sdkLeafMerkle(leaves: readonly BundleLeaf[]): LeafMerkleResult {
  const leafHashes = leaves.map((l) => l.leafHash)
  if (leafHashes.length === 0) {
    return { merkleRoot: buildMerkleRoot([]), inclusionProofs: {} }
  }
  const merkleRoot = buildMerkleRoot(leafHashes)
  const inclusionProofs: Record<string, unknown> = {}
  for (const h of leafHashes) {
    const proof = generateMerkleProof(leafHashes, h)
    if (proof) inclusionProofs[h] = proof
  }
  return { merkleRoot, inclusionProofs }
}

/**
 * Verify a previously generated SDK Merkle inclusion proof. Re-exported so an
 * edge verifier and the tests use the same SDK verifier the gateway used to
 * build the proof, rather than a second implementation.
 */
export function verifyLeafInclusion(proof: unknown): boolean {
  try {
    // The SDK MerkleProof shape: { receiptHash, root, proof, index }.
    return verifyMerkleProof(proof as never)
  } catch {
    return false
  }
}
