// APS Regulated Action Profile v0: transparency publisher (private gateway).
//
// Anchors the pre-committed intent into an append-only Merkle log AT THE reserved STATE, before
// execution. Produces an inclusion proof the public verifier can check against a registered root.
// This provides NON-EQUIVOCATION, not truth (SCITT-shaped, draft-ietf-scitt-architecture): it
// shows the log did not present different histories to different parties; it does not establish
// that the anchored statement is true. The leaf/root construction matches the public verifier and the
// conformance generator so anchors verify across the boundary.

import { jcsHash } from './disposition.js'

export interface TransparencyAnchor {
  transparency_ref: {
    type: 'enterprise_merkle_log'
    log_id: string
    inclusion_proof: Array<{ dir: 'L' | 'R'; hash: string }>
    anchored_at_state: 'reserved'
    tree_size: number
    leaf_hash: string
  }
  log_id: string
  root: string
}

/**
 * Anchor a reserved intent. The leaf binds receipt_id + intent_hash + state=reserved. For v0 the
 * log is modeled as a two-leaf tree (the intent leaf plus a deterministic sibling); the registered
 * root is returned so the caller can register it in the verifier context.
 */
export function anchorReservedIntent(receiptId: string, intentHash: string, logId = 'enterprise-log-1'): TransparencyAnchor {
  const leaf = jcsHash({ receipt_id: receiptId, intent_hash: intentHash, state: 'reserved' })
  const sibling = jcsHash({ sibling: receiptId })
  const root = jcsHash({ l: leaf, r: sibling })
  return {
    transparency_ref: {
      type: 'enterprise_merkle_log',
      log_id: logId,
      inclusion_proof: [{ dir: 'R', hash: sibling }],
      anchored_at_state: 'reserved',
      tree_size: 2,
      leaf_hash: leaf,
    },
    log_id: logId,
    root,
  }
}

/** Recompute the root from a leaf + proof (the same check the verifier performs). */
export function verifyInclusion(leafHash: string, proof: Array<{ dir: 'L' | 'R'; hash: string }>, expectedRoot: string): boolean {
  let acc = leafHash
  for (const step of proof) {
    acc = step.dir === 'L' ? jcsHash({ l: step.hash, r: acc }) : jcsHash({ l: acc, r: step.hash })
  }
  return acc === expectedRoot
}
