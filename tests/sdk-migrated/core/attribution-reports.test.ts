// Attribution report generators — migrated from SDK (2026-04-17).
// Covers computeAttribution, computeCollaborationAttribution, and the
// scope-weight constants. Merkle/trace primitives are still exercised by
// the SDK suite at tests/attribution.test.ts.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, createReceipt, clearStores,
  verifyAttributionReport,
} from 'agent-passport-system'
import type { Delegation, ActionReceipt } from 'agent-passport-system'
import {
  computeAttribution,
  computeCollaborationAttribution,
  DEFAULT_SCOPE_WEIGHTS,
} from '../../../src/sdk-migrated/core/attribution-reports.js'

const human = generateKeyPair()
const agentA = generateKeyPair()
const agentB = generateKeyPair()
const verifier = generateKeyPair()

function makeDelegation(): Delegation {
  return createDelegation({
    delegatedTo: agentA.publicKey,
    delegatedBy: human.publicKey,
    scope: ['code_execution', 'web_search', 'git_operations'],
    spendLimit: 1000,
    privateKey: human.privateKey
  })
}

function makeReceipt(d: Delegation, scope: string, spend: number, result: string = 'success'): ActionReceipt {
  return createReceipt({
    agentId: 'agent-a',
    delegationId: d.delegationId,
    delegation: d,
    action: { type: 'execute', target: 'task', scopeUsed: scope, spend: { amount: spend, currency: 'USD' } },
    result: { status: result, summary: 'done' },
    delegationChain: [human.publicKey, agentA.publicKey],
    privateKey: agentA.privateKey
  })
}

describe('Attribution Computation', () => {
  beforeEach(() => clearStores())

  it('computes attribution with correct weight formula', () => {
    const d = makeDelegation()
    const r1 = makeReceipt(d, 'code_execution', 10)
    const r2 = makeReceipt(d, 'web_search', 5)
    const report = computeAttribution(
      [r1, r2], 'agent-a', 'tymofii', verifier.privateKey
    )
    assert.equal(report.receiptCount, 2)
    assert.ok(report.totalWeight > 0)
    assert.ok(report.merkleRoot.length === 64)
    assert.ok(report.reportId.startsWith('attr_'))
  })

  it('failed actions contribute zero weight', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10, 'failure')
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    assert.equal(report.totalWeight, 0)
  })

  it('uses custom scope weights when provided', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 0)
    const defaultReport = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    const customReport = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey,
      { scopeWeights: { code_execution: 5.0 } }
    )
    assert.ok(customReport.totalWeight > defaultReport.totalWeight)
  })

  it('exposes sensible defaults via DEFAULT_SCOPE_WEIGHTS', () => {
    assert.equal(DEFAULT_SCOPE_WEIGHTS.code_execution, 1.0)
    assert.equal(DEFAULT_SCOPE_WEIGHTS.web_search, 0.3)
  })

  it('verifies valid attribution report signature (SDK verifier)', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    const v = verifyAttributionReport(report, verifier.publicKey)
    assert.ok(v.valid)
  })

  it('[ADVERSARIAL] rejects tampered attribution report', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    report.totalWeight = 999
    const v = verifyAttributionReport(report, verifier.publicKey)
    assert.ok(!v.valid)
  })

  it('[ADVERSARIAL] rejects attribution verified with wrong key', () => {
    const d = makeDelegation()
    const r = makeReceipt(d, 'code_execution', 10)
    const report = computeAttribution(
      [r], 'agent-a', 'tymofii', verifier.privateKey
    )
    const v = verifyAttributionReport(report, agentA.publicKey)
    assert.ok(!v.valid)
  })

  it('handles empty receipts', () => {
    const report = computeAttribution(
      [], 'agent-a', 'tymofii', verifier.privateKey
    )
    assert.equal(report.receiptCount, 0)
    assert.equal(report.totalWeight, 0)
  })

  it('anti-gaming: 1000x spend gets logarithmic (not linear) weight', () => {
    const d = makeDelegation()
    const small = makeReceipt(d, 'code_execution', 10)
    const huge = makeReceipt(d, 'code_execution', 10000)
    const attrSmall = computeAttribution([small], 'agent-a', 'x', verifier.privateKey)
    const attrHuge = computeAttribution([huge], 'agent-a', 'x', verifier.privateKey)
    const ratio = attrHuge.totalWeight / attrSmall.totalWeight
    assert.ok(ratio < 5, `1000x spend → ${ratio.toFixed(1)}x weight (logarithmic)`)
  })
})

describe('Collaboration Attribution', () => {
  beforeEach(() => clearStores())

  it('splits attribution between multiple agents', () => {
    const dA = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], spendLimit: 500, privateKey: human.privateKey
    })
    const dB = createDelegation({
      delegatedTo: agentB.publicKey, delegatedBy: human.publicKey,
      scope: ['web_search'], spendLimit: 500, privateKey: human.privateKey
    })
    const r1 = createReceipt({
      agentId: 'agent-a', delegationId: dA.delegationId, delegation: dA,
      action: { type: 'execute', target: 't', scopeUsed: 'code_execution', spend: { amount: 20, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey
    })
    const r2 = createReceipt({
      agentId: 'agent-b', delegationId: dB.delegationId, delegation: dB,
      action: { type: 'search', target: 't', scopeUsed: 'web_search', spend: { amount: 5, currency: 'USD' } },
      result: { status: 'success', summary: 'done' },
      delegationChain: [human.publicKey, agentB.publicKey],
      privateKey: agentB.privateKey
    })

    const beneficiaryMap = new Map([['agent-a', 'tymofii'], ['agent-b', 'tymofii']])
    const collab = computeCollaborationAttribution([r1, r2], beneficiaryMap)
    assert.equal(collab.participants.length, 2)
    const total = collab.participants.reduce((s, p) => s + p.percentage, 0)
    assert.ok(Math.abs(total - 100) < 0.1, 'Percentages sum to ~100')
  })
})
