// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GatewayTypeInterceptor (Module 3) — evidentiary type safety at the
// gateway action-authorization boundary
// ══════════════════════════════════════════════════════════════════
// Composes four public SDK primitives. Owns no state of its own.
//
//   1. verifyEvidenceClaim    — static registry check (Module 2)
//   2. computeDownstreamTaint — cascade closure from upheld/remedied
//                                contestations (Module 4)
//   3. ContestabilityReceipt  — surfaces filed/under_review records
//                                directly against the staged evidence
//   4. ClaimType + RecordType — registry vocabulary (Module 1 / 1.5)
//
// Boundary contract: deny on the first failing check. Permit only
// when (a) the registry profile validates, (b) no upheld or remedied
// contestation taints any staged record, and (c) no open contestation
// (filed / under_review) targets a staged record. The interceptor
// never logs, mutates state, or fans out — it returns a typed verdict
// and the caller decides what to do.
// ══════════════════════════════════════════════════════════════════

import {
  verifyEvidenceClaim,
  computeDownstreamTaint,
  isContestationTainting,
} from 'agent-passport-system'
import type {
  ClaimType,
  RecordType,
  ClaimVerificationResult,
  TaintedSet,
  ContestabilityReceipt,
  ContestStatus,
} from 'agent-passport-system'

export interface InterceptorEvidence {
  recordType: RecordType
  /** Opaque to the interceptor; verifyEvidenceClaim does not introspect it. */
  record: unknown
  /** Required for cascade and contestation routing. Records without a
   *  receiptId still type-check via verifyEvidenceClaim but are
   *  invisible to the contestation hooks (cannot be tainted, cannot
   *  be contested). */
  receiptId?: string
  /** Receipt_ids this record references — action_id, parent_receipt_id,
   *  derived_from, etc. The caller decides which fields surface here.
   *  The cascade primitive walks the graph the caller provides. */
  references?: string[]
}

export interface GatewayActionRequest {
  claimType: ClaimType
  /** Principal ID asserting the claim. Surfaced for audit/logging at
   *  the caller; the interceptor does not authenticate or cross-check
   *  it. Identity verification is upstream of this layer. */
  claimedBy: string
  evidence: InterceptorEvidence[]
  /** Active contestations the gateway has seen against any of the
   *  staged evidence or the action being authorized. The caller is
   *  responsible for narrowing to relevant entries; the interceptor
   *  inspects every receipt in the list. */
  contestationIndex: ContestabilityReceipt[]
  action: { kind: string; target: string }
}

export type InterceptReason =
  | 'evidence_validates'
  | 'forbidden_substitution'
  | 'missing_evidence'
  | 'profile_not_populated'
  | 'unsupported_claim_type'
  | 'bundle_requires_inclusion_proof'
  | 'tainted_upstream'
  | 'contested'

export interface GatewayInterceptResult {
  decision: 'permit' | 'deny'
  reason: InterceptReason
  verificationResult?: ClaimVerificationResult
  /** Populated when reason === 'tainted_upstream'. Carries the full
   *  TaintedSet from the SDK so the caller can produce a human-readable
   *  audit trail without re-running the cascade. */
  taintedRecords?: TaintedSet
  /** Populated when reason === 'contested'. */
  contestation?: {
    contestationId: string
    contestedRecordId: string
    status: ContestStatus
  }
}

export function interceptAction(req: GatewayActionRequest): GatewayInterceptResult {
  // Step 1: static registry type check.
  const verification = verifyEvidenceClaim({
    claim: { type: req.claimType, subject: req.claimedBy },
    evidence: req.evidence.map((e) => ({
      recordType: e.recordType,
      record: e.record,
      receiptId: e.receiptId,
    })),
  })

  if (verification.status !== 'valid') {
    // Map SDK statuses to interceptor reasons. The SDK emits one of:
    //   forbidden_substitution | missing_evidence | profile_not_populated
    //   unsupported_claim_type | bundle_requires_inclusion_proof | contested
    // Module 3 does not pass a resolver in step 1, so the SDK 'contested'
    // path is unreachable here — contestation routing happens in step 3
    // with full ContestabilityReceipt objects, not just statuses.
    return {
      decision: 'deny',
      reason: verification.status as InterceptReason,
      verificationResult: verification,
    }
  }

  // Step 2: cascade taint from upheld or remedied contestations.
  // Each tainting contestation contributes its closure; if any staged
  // evidence falls in any closure, deny. We surface only the first
  // hit so the audit trail points to one root cause.
  const candidates = req.evidence
    .filter((e): e is InterceptorEvidence & { receiptId: string } => e.receiptId !== undefined)
    .map((e) => ({
      receiptId: e.receiptId,
      recordType: e.recordType,
      references: e.references ?? [],
    }))

  const stagedReceiptIds = new Set(candidates.map((c) => c.receiptId))

  for (const contest of req.contestationIndex) {
    if (!isContestationTainting(contest)) continue
    const taintedSet = computeDownstreamTaint(contest, candidates)
    if (taintedSet === null) continue
    const hit = taintedSet.tainted.find((t) => stagedReceiptIds.has(t.receiptId))
    if (hit !== undefined) {
      return {
        decision: 'deny',
        reason: 'tainted_upstream',
        verificationResult: verification,
        taintedRecords: taintedSet,
      }
    }
  }

  // Step 3: open contestations directly against staged evidence.
  // 'filed' and 'under_review' block; 'rejected', 'abandoned',
  // 'expired' do not. 'upheld' and 'remedied' are already handled by
  // step 2 via cascade and would also block here, but we leave the
  // cascade path authoritative for those (it produces the full
  // taint payload). This branch covers the case where the
  // contestation is open but unresolved — the action stages a
  // record that someone has actively challenged.
  for (const contest of req.contestationIndex) {
    const status = contest.controller_response?.status ?? 'filed'
    if (status !== 'filed' && status !== 'under_review') continue
    if (!stagedReceiptIds.has(contest.action_id)) continue
    return {
      decision: 'deny',
      reason: 'contested',
      verificationResult: verification,
      contestation: {
        contestationId: contest.receipt_id,
        contestedRecordId: contest.action_id,
        status,
      },
    }
  }

  // Step 4: all checks pass.
  return {
    decision: 'permit',
    reason: 'evidence_validates',
    verificationResult: verification,
  }
}
