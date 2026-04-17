// Attribution model tests — migrated from SDK after the policy-bearing
// weighted models (access_weighted, recency_weighted) and their
// hardcoded constants moved to the gateway. SDK keeps the schema
// baseline ('equal') and caller-supplied 'custom' weights.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  verifyDataSourceAttribution,
} from 'agent-passport-system'
import type { DataAccessReceipt } from 'agent-passport-system'
import {
  computeAccessWeights, computeRecencyWeights,
  computeAccessWeightedAttribution, computeRecencyWeightedAttribution,
  RECENCY_HALF_LIFE_MS,
} from '../../../src/sdk-migrated/core/attribution-models.js'

function makeReceipt(
  sourceReceiptId: string,
  agentId: string,
  timestamp?: string,
  perAccessAmount?: number,
): DataAccessReceipt {
  return {
    accessReceiptId: 'dacr_' + Math.random().toString(36).slice(2, 10),
    sourceReceiptId,
    sourceMode: 'gateway_verified',
    dataHash: 'abc123',
    agentId,
    agentPublicKey: 'agent_pub_key',
    principalId: 'principal_1',
    executionFrameId: 'frame_1',
    accessScope: 'read',
    accessMethod: 'api_call',
    declaredPurpose: 'inference:decision_support',
    termsAtAccessTime: {
      allowedPurposes: ['inference:decision_support'],
      requireAttribution: true,
      requireNotification: false,
      compensation: perAccessAmount
        ? { type: 'per_access', amount: perAccessAmount, currency: 'usd' }
        : { type: 'attribution_only' },
      derivativePolicy: 'attribution_required',
      auditVisibility: 'source_and_principal',
      revocable: true,
    },
    timestamp: timestamp || new Date().toISOString(),
    gatewayId: 'gateway_1',
    gatewayPublicKey: 'gw_pub',
    gatewaySignature: 'gw_sig',
  }
}

describe('Gateway weight computers', () => {
  it('computeAccessWeights returns counts per source', () => {
    const receipts = [
      makeReceipt('src_A', 'a'),
      makeReceipt('src_A', 'a'),
      makeReceipt('src_A', 'a'),
      makeReceipt('src_B', 'a'),
    ]
    const w = computeAccessWeights(receipts)
    assert.equal(w.get('src_A'), 3)
    assert.equal(w.get('src_B'), 1)
  })

  it('exports a 1-day default half-life for recency', () => {
    assert.equal(RECENCY_HALF_LIFE_MS, 24 * 60 * 60 * 1000)
  })

  it('computeRecencyWeights gives strictly higher weight to more recent source', () => {
    const now = Date.now()
    const recent = new Date(now).toISOString()
    const dayAgo = new Date(now - 86_400_000).toISOString()
    const w = computeRecencyWeights(
      [makeReceipt('src_recent', 'a', recent), makeReceipt('src_old', 'a', dayAgo)],
      RECENCY_HALF_LIFE_MS,
      now,
    )
    assert.ok(w.get('src_recent')! > w.get('src_old')!)
  })
})

describe('computeAccessWeightedAttribution', () => {
  let keys: { publicKey: string; privateKey: string }
  beforeEach(() => { keys = generateKeyPair() })

  it('more accesses → higher weight, percentages sum to 100', () => {
    const receipts = [
      makeReceipt('src_A', 'a'),
      makeReceipt('src_A', 'a'),
      makeReceipt('src_A', 'a'),
      makeReceipt('src_B', 'a'),
    ]
    const report = computeAccessWeightedAttribution({
      outputArtifactId: 'out_aw',
      outputType: 'content',
      accessReceipts: receipts,
      generatorPublicKey: keys.publicKey,
      generatorPrivateKey: keys.privateKey,
    })
    assert.equal(report.totalSources, 2)
    assert.equal(report.totalAccessEvents, 4)
    const srcA = report.sources.find(s => s.sourceReceiptId === 'src_A')!
    const srcB = report.sources.find(s => s.sourceReceiptId === 'src_B')!
    assert.equal(srcA.percentage, 75)
    assert.equal(srcB.percentage, 25)
  })

  it('produces a verifiable signed report', () => {
    const receipts = [makeReceipt('src_A', 'a'), makeReceipt('src_B', 'a')]
    const report = computeAccessWeightedAttribution({
      outputArtifactId: 'out_verify',
      outputType: 'decision',
      accessReceipts: receipts,
      generatorPublicKey: keys.publicKey,
      generatorPrivateKey: keys.privateKey,
    })
    const verification = verifyDataSourceAttribution(report, keys.publicKey)
    assert.equal(verification.valid, true)
  })
})

describe('computeRecencyWeightedAttribution', () => {
  let keys: { publicKey: string; privateKey: string }
  beforeEach(() => { keys = generateKeyPair() })

  it('recent source dominates the percentage breakdown', () => {
    const now = Date.now()
    const recent = new Date(now).toISOString()
    const dayAgo = new Date(now - 86_400_000).toISOString()
    const report = computeRecencyWeightedAttribution({
      outputArtifactId: 'out_rec',
      outputType: 'content',
      accessReceipts: [
        makeReceipt('src_recent', 'a', recent),
        makeReceipt('src_old', 'a', dayAgo),
      ],
      generatorPublicKey: keys.publicKey,
      generatorPrivateKey: keys.privateKey,
      now,
    })
    const r = report.sources.find(s => s.sourceReceiptId === 'src_recent')!
    const o = report.sources.find(s => s.sourceReceiptId === 'src_old')!
    assert.ok(r.percentage > o.percentage, 'recent should outweigh old')
    assert.ok(r.percentage > 60, 'recent should be > 60% under 1-day half-life')
  })

  it('honors a custom half-life override', () => {
    const now = Date.now()
    const recent = new Date(now).toISOString()
    const hourAgo = new Date(now - 3_600_000).toISOString()
    // Half-life 1 hour: 1-hour-old source weight = 0.5
    const w = computeRecencyWeights(
      [makeReceipt('src_recent', 'a', recent), makeReceipt('src_old', 'a', hourAgo)],
      3_600_000,
      now,
    )
    // recent weight 1.0; old weight 0.5
    assert.ok(Math.abs(w.get('src_recent')! - 1) < 1e-9)
    assert.ok(Math.abs(w.get('src_old')! - 0.5) < 1e-6)
  })
})
