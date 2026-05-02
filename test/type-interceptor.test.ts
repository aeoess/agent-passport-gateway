// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// GatewayTypeInterceptor (Module 3) — boundary integration tests.
//
// Five canonical scenarios:
//   1. permit:  BINDING_COMMITMENT with valid PromotionEvent + Statement
//   2. deny:    BINDING_COMMITMENT with only ActionReceipt (forbidden_substitution)
//   3. deny:    AUTHORITY_TO_EXECUTE with valid evidence but Action tainted
//               via cascade from an upheld contestation against an upstream record
//   4. deny:    valid evidence with a 'filed' contestation against the staged
//               action receipt itself (contested, blocking)
//   5. deny:    EFFECT_SAFETY_ATTESTED with a full procedural chain
//               (profile_not_populated — no false permit on a stub claim)

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  ClaimType,
  RecordType,
} from 'agent-passport-system'
import type {
  ContestabilityReceipt,
  ScopeOfClaim,
  ContestStatus,
} from 'agent-passport-system'

import { interceptAction } from '../src/gateway/type-interceptor.js'

const SCOPE: ScopeOfClaim = {
  asserts: 'Test contestation for interceptor.',
  does_not_assert: ['that the contestation is meritorious'],
  capture_mode: 'self_attested',
  completeness: 'complete',
  self_attested: true,
}

function contestation(opts: {
  receiptId: string
  actionId: string
  status?: ContestStatus
}): ContestabilityReceipt {
  const base: ContestabilityReceipt = {
    claim_type: 'aps:contestability:v1',
    receipt_id: opts.receiptId,
    timestamp: '2026-05-02T00:00:00.000Z',
    signer_did: 'did:aps:test-subject-001',
    scope_of_claim: SCOPE,
    contestant: { did: 'did:aps:test-subject-001', standing_basis: 'data_subject' },
    action_id: opts.actionId,
    grounds: 'test',
    requested_remedy: 'review',
    signature: '00'.repeat(64),
  }
  if (opts.status === undefined) return base
  return {
    ...base,
    controller_response: {
      status: opts.status,
      responded_at: '2026-05-02T01:00:00.000Z',
      responder_did: 'aa'.repeat(32),
      response_signature: '00'.repeat(64),
    },
  }
}

describe('GatewayTypeInterceptor — boundary integration', () => {
  it('permits BINDING_COMMITMENT with valid PromotionEvent + ProvisionalStatement', () => {
    const result = interceptAction({
      claimType: ClaimType.BINDING_COMMITMENT,
      claimedBy: 'did:aps:principal:alice',
      evidence: [
        { recordType: RecordType.PromotionEvent, receiptId: 'promo_001', record: {} },
        { recordType: RecordType.ProvisionalStatement, receiptId: 'stmt_001', record: {} },
      ],
      contestationIndex: [],
      action: { kind: 'commit', target: 'agreement_001' },
    })
    assert.equal(result.decision, 'permit')
    assert.equal(result.reason, 'evidence_validates')
  })

  it('denies BINDING_COMMITMENT with only ActionReceipt (forbidden_substitution)', () => {
    const result = interceptAction({
      claimType: ClaimType.BINDING_COMMITMENT,
      claimedBy: 'did:aps:principal:alice',
      evidence: [
        { recordType: RecordType.ActionReceipt, receiptId: 'act_001', record: {} },
      ],
      contestationIndex: [],
      action: { kind: 'commit', target: 'agreement_001' },
    })
    assert.equal(result.decision, 'deny')
    assert.equal(result.reason, 'forbidden_substitution')
    assert.equal(result.verificationResult?.status, 'forbidden_substitution')
  })

  it('denies AUTHORITY_TO_EXECUTE when staged evidence is downstream of an upheld contestation', () => {
    // Upheld contestation against action_001 (an upstream record the
    // staged AuthorityBoundaryReceipt depends on). The cascade should
    // taint auth_001 because it references action_001.
    const upheld = contestation({
      receiptId: 'contest_001',
      actionId: 'action_001',
      status: 'upheld',
    })

    const result = interceptAction({
      claimType: ClaimType.AUTHORITY_TO_EXECUTE,
      claimedBy: 'did:aps:principal:alice',
      evidence: [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
          references: ['action_001'],
        },
      ],
      contestationIndex: [upheld],
      action: { kind: 'execute', target: 'commerce.purchase' },
    })

    assert.equal(result.decision, 'deny')
    assert.equal(result.reason, 'tainted_upstream')
    assert.notEqual(result.taintedRecords, undefined)
    if (result.taintedRecords === undefined) return
    assert.equal(result.taintedRecords.rootActionId, 'action_001')
    assert.equal(result.taintedRecords.rootContestationId, 'contest_001')
    const hit = result.taintedRecords.tainted.find((t) => t.receiptId === 'auth_001')
    assert.notEqual(hit, undefined)
    assert.equal(hit?.taintDepth, 1)
  })

  it('denies when an open (filed) contestation targets the staged action receipt', () => {
    const filed = contestation({
      receiptId: 'contest_open_001',
      actionId: 'auth_001',  // contesting the staged record directly
      status: 'filed',
    })

    const result = interceptAction({
      claimType: ClaimType.AUTHORITY_TO_EXECUTE,
      claimedBy: 'did:aps:principal:alice',
      evidence: [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
        },
      ],
      contestationIndex: [filed],
      action: { kind: 'execute', target: 'commerce.purchase' },
    })

    assert.equal(result.decision, 'deny')
    assert.equal(result.reason, 'contested')
    assert.equal(result.contestation?.contestationId, 'contest_open_001')
    assert.equal(result.contestation?.contestedRecordId, 'auth_001')
    assert.equal(result.contestation?.status, 'filed')
  })

  it('denies EFFECT_SAFETY_ATTESTED with a full procedural chain (profile_not_populated)', () => {
    // The protocol does not certify effect safety. A fully-populated
    // procedural chain must NOT produce a permit; it must produce a
    // typed acknowledgement that the claim is unanswerable.
    const result = interceptAction({
      claimType: ClaimType.EFFECT_SAFETY_ATTESTED,
      claimedBy: 'did:aps:principal:alice',
      evidence: [
        { recordType: RecordType.AuthorityBoundaryReceipt, receiptId: 'auth_001', record: {} },
        { recordType: RecordType.DecisionReceipt, receiptId: 'dec_001', record: {} },
        { recordType: RecordType.ActionReceipt, receiptId: 'act_001', record: {} },
        { recordType: RecordType.DerivationReceipt, receiptId: 'der_001', record: {} },
      ],
      contestationIndex: [],
      action: { kind: 'execute', target: 'paper8_scenario' },
    })

    assert.equal(result.decision, 'deny')
    assert.equal(result.reason, 'profile_not_populated')
    assert.equal(result.verificationResult?.status, 'profile_not_populated')
  })

  it('rejected contestations do not block a permit', () => {
    // Sanity check that the interceptor follows SDK contestation
    // semantics: 'rejected' is not a blocking status.
    const rejected = contestation({
      receiptId: 'contest_rej_001',
      actionId: 'auth_001',
      status: 'rejected',
    })

    const result = interceptAction({
      claimType: ClaimType.AUTHORITY_TO_EXECUTE,
      claimedBy: 'did:aps:principal:alice',
      evidence: [
        {
          recordType: RecordType.AuthorityBoundaryReceipt,
          receiptId: 'auth_001',
          record: {},
        },
      ],
      contestationIndex: [rejected],
      action: { kind: 'execute', target: 'commerce.purchase' },
    })
    assert.equal(result.decision, 'permit')
    assert.equal(result.reason, 'evidence_validates')
  })
})
