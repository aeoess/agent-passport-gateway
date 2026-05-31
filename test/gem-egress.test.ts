// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Merkle aggregation egress tests
// ══════════════════════════════════════════════════════════════════
// Covers the mandated cases plus negatives:
//   - aggregation determinism (same leaves -> same root)
//   - root verifies against the leaves (inclusion proofs), incl. tamper reject
//   - summary-matrix accuracy and consistency check
//   - out-of-band leaf fetch returns the exact leaves
//   - egress retry and dead-letter on a failing downstream
//   - durable bus replay (Last-Event-ID reconnect window)
//   - public projection gate drops non-whitelisted fields
//   - Wave 2 contributor-settlement stub is inert
//
// PROOF / CLAIMS BOX
// Proves: a Merkle root plus an inclusion proof shows a specific receipt leaf
//   was in the aggregated batch the gateway emitted.
// Does NOT prove: anything about receipts the gateway never saw. Absence of a
//   leaf is not evidence the underlying event did not occur elsewhere.
// ══════════════════════════════════════════════════════════════════

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { initDB } from '../src/db/schema.js'
import { generateKeyPair, buildMerkleRoot } from 'agent-passport-system'

import {
  MerkleAggregator,
  proveLeafInBatch,
  verifyLeafProof,
  markCommittedAnchored,
  EgressDispatcher,
  backoffDelay,
  DEFAULT_RETRY_POLICY,
  buildSummaryMatrix,
  summaryMatrixConsistent,
  initLeafOutbox,
  fetchLeaves,
  fetchLeafHashes,
  leafCount,
  projectPublicBatch,
  anchorCommittedBatch,
  fetchBatchLeaves,
  egressCommittedBatch,
  computeContributorSettlement,
  contributorSettlementAvailable,
  type PendingReceipt,
  type EgressEnvelope,
  type EgressSink,
} from '../src/gateway/egress/index.js'
import { getMerkleRootAnchor, initAnchorTable } from '../src/gateway/rekor.js'
import { getEventBus } from '../src/gateway/events.js'

const KP = generateKeyPair()
const TENANT = 'tenant_gem_test'

function leaf(s: string): string {
  return 'sha256:' + createHash('sha256').update(s).digest('hex')
}

function makeAggregator(tenantId: string = TENANT): MerkleAggregator {
  return new MerkleAggregator({
    tenantId,
    committerPrivateKey: KP.privateKey,
    committerPublicKey: KP.publicKey,
    // Small count bound so commit fires deterministically in tests.
    batchConfig: { maxIntervalSeconds: 0, maxReceiptsPerBatch: 3, directAnchorCritical: false },
  })
}

const RECEIPTS: PendingReceipt[] = [
  { leafHash: leaf('r1'), verdict: 'permit', actionType: 'cloud:provision', sourceReceiptId: 'rcp_1' },
  { leafHash: leaf('r2'), verdict: 'deny', actionType: 'cloud:provision', sourceReceiptId: 'rcp_2' },
  { leafHash: leaf('r3'), verdict: 'permit', actionType: 'data:read', sourceReceiptId: 'rcp_3' },
]

before(() => {
  initDB(':memory:')
  initLeafOutbox()
  initAnchorTable()
})

// ── Aggregation determinism ──

describe('GEM aggregation determinism', () => {
  it('same leaves produce the same Merkle root', () => {
    const a = makeAggregator('tenant_det_a')
    const b = makeAggregator('tenant_det_b')
    for (const r of RECEIPTS) { a.add(r); b.add(r) }
    const ca = a.commit()
    const cb = b.commit()
    assert.equal(ca.batch.merkleRoot, cb.batch.merkleRoot)
  })

  it('leaf order does not change the root (sorted-leaf SDK primitive)', () => {
    const a = makeAggregator('tenant_ord_a')
    const b = makeAggregator('tenant_ord_b')
    for (const r of RECEIPTS) a.add(r)
    for (const r of [...RECEIPTS].reverse()) b.add(r)
    assert.equal(a.commit().batch.merkleRoot, b.commit().batch.merkleRoot)
  })

  it('the committed root matches the SDK buildMerkleRoot over the leaf hashes', () => {
    const agg = makeAggregator('tenant_root_match')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    assert.equal(committed.batch.merkleRoot, buildMerkleRoot(RECEIPTS.map((r) => r.leafHash)))
  })

  it('a different leaf set produces a different root', () => {
    const a = makeAggregator('tenant_diff_a')
    const b = makeAggregator('tenant_diff_b')
    for (const r of RECEIPTS) a.add(r)
    b.add(RECEIPTS[0]); b.add(RECEIPTS[1]); b.add({ leafHash: leaf('different'), verdict: 'permit' })
    assert.notEqual(a.commit().batch.merkleRoot, b.commit().batch.merkleRoot)
  })
})

// ── Inclusion proofs (root verifies against the leaves) ──

describe('GEM inclusion proofs', () => {
  it('every leaf in the batch produces a valid inclusion proof', () => {
    const agg = makeAggregator('tenant_incl')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    for (const r of RECEIPTS) {
      const proof = proveLeafInBatch(committed.batch, r.leafHash)
      assert.ok(proof, `expected proof for ${r.leafHash}`)
      assert.equal(verifyLeafProof(proof!), true)
      assert.equal(proof!.merkleRoot, committed.batch.merkleRoot)
    }
  })

  it('a leaf the gateway never saw has no inclusion proof (negative)', () => {
    const agg = makeAggregator('tenant_incl_neg')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const proof = proveLeafInBatch(committed.batch, leaf('never_seen'))
    assert.equal(proof, null)
  })

  it('a tampered inclusion proof fails verification (negative)', () => {
    const agg = makeAggregator('tenant_incl_tamper')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const proof = proveLeafInBatch(committed.batch, RECEIPTS[0].leafHash)
    assert.ok(proof)
    const tampered = { ...proof!, receiptHash: leaf('swapped') }
    assert.equal(verifyLeafProof(tampered), false)
  })

  it('an inclusion proof against a mutated root fails (negative)', () => {
    const agg = makeAggregator('tenant_incl_root')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const proof = proveLeafInBatch(committed.batch, RECEIPTS[1].leafHash)
    assert.ok(proof)
    const tampered = { ...proof!, merkleRoot: leaf('forged_root') }
    assert.equal(verifyLeafProof(tampered), false)
  })
})

// ── Summary-matrix accuracy ──

describe('GEM summary matrix', () => {
  it('counts receipts accurately by verdict and action type', () => {
    const summary = buildSummaryMatrix(RECEIPTS.map((r) => ({ verdict: r.verdict, actionType: r.actionType })))
    assert.equal(summary.total, 3)
    assert.equal(summary.byVerdict.permit, 2)
    assert.equal(summary.byVerdict.deny, 1)
    assert.equal(summary.byActionType['cloud:provision'], 2)
    assert.equal(summary.byActionType['data:read'], 1)
  })

  it('the committed envelope summary matches the receipts', () => {
    const agg = makeAggregator('tenant_summary')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    assert.equal(committed.summary.total, 3)
    assert.equal(committed.envelope.summary.byVerdict.permit, 2)
    assert.equal(committed.envelope.receiptCount, 3)
  })

  it('buckets missing fields under unknown without dropping the count', () => {
    const summary = buildSummaryMatrix([
      { verdict: 'permit', actionType: 'x' },
      { verdict: null, actionType: undefined },
      { verdict: '   ', actionType: '' },
    ])
    assert.equal(summary.total, 3)
    assert.equal(summary.byVerdict.unknown, 2)
    assert.equal(summary.byVerdict.permit, 1)
  })

  it('consistency check passes for a well-formed summary and fails when buckets are truncated', () => {
    const summary = buildSummaryMatrix(RECEIPTS.map((r) => ({ verdict: r.verdict, actionType: r.actionType })))
    assert.equal(summaryMatrixConsistent(summary), true)
    const truncated = { ...summary, byVerdict: { permit: 1 } }
    assert.equal(summaryMatrixConsistent(truncated), false)
  })
})

// ── Out-of-band leaf fetch returns the exact leaves ──

describe('GEM out-of-band leaf outbox', () => {
  it('fetches back the exact leaves in input order', () => {
    const agg = makeAggregator('tenant_oob')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const fetched = fetchLeaves('tenant_oob', committed.batch.batchId)
    assert.equal(fetched.length, RECEIPTS.length)
    assert.deepEqual(fetched.map((f) => f.leafHash), RECEIPTS.map((r) => r.leafHash))
    assert.deepEqual(fetched.map((f) => f.sourceReceiptId), RECEIPTS.map((r) => r.sourceReceiptId))
  })

  it('the fetched leaf hashes recompute the committed root', () => {
    const agg = makeAggregator('tenant_oob_root')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const hashes = fetchLeafHashes('tenant_oob_root', committed.batch.batchId)
    assert.equal(buildMerkleRoot(hashes), committed.batch.merkleRoot)
  })

  it('leaf fetch is tenant-scoped: another tenant gets nothing (negative)', () => {
    const agg = makeAggregator('tenant_oob_owner')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    assert.equal(fetchLeaves('tenant_oob_intruder', committed.batch.batchId).length, 0)
    assert.equal(leafCount('tenant_oob_owner', committed.batch.batchId), RECEIPTS.length)
  })

  it('an unknown batch id returns no leaves (negative)', () => {
    assert.equal(fetchLeaves(TENANT, 'batch_does_not_exist').length, 0)
  })

  it('fetchBatchLeaves emits a leaf_fetch event so access is observable', () => {
    const agg = makeAggregator('tenant_oob_event')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const seen: string[] = []
    const cb = (e: any) => { if (e.type === 'leaf_fetch') seen.push(e.data.batch_id) }
    getEventBus().subscribe('tenant_oob_event', cb)
    try {
      const leaves = fetchBatchLeaves('tenant_oob_event', committed.batch.batchId)
      assert.equal(leaves.length, RECEIPTS.length)
      assert.ok(seen.includes(committed.batch.batchId))
    } finally {
      getEventBus().unsubscribe('tenant_oob_event', cb)
    }
  })
})

// ── Egress retry and dead-letter ──

describe('GEM egress dispatcher retry and dead-letter', () => {
  const envelope: EgressEnvelope = {
    batchId: 'batch_disp',
    merkleRoot: leaf('root'),
    epoch: 0,
    previousBatchId: null,
    previousMerkleRoot: null,
    receiptCount: 3,
    committedAt: new Date().toISOString(),
    summary: buildSummaryMatrix(RECEIPTS.map((r) => ({ verdict: r.verdict, actionType: r.actionType }))),
    leafFetchRef: '/api/v1/egress/batches/batch_disp/leaves',
  }

  const noWait = async () => {}

  it('delivers on the first try when the sink accepts', async () => {
    let calls = 0
    const sink: EgressSink = async () => { calls++ }
    const d = new EgressDispatcher({ waitFn: noWait })
    const res = await d.dispatch(TENANT, sink, envelope)
    assert.equal(res.delivered, true)
    assert.equal(res.attempts, 1)
    assert.equal(calls, 1)
    assert.equal(res.deadLetter, null)
  })

  it('retries a flaky sink and eventually delivers', async () => {
    let calls = 0
    const sink: EgressSink = async () => {
      calls++
      if (calls < 3) throw new Error('downstream 503')
    }
    const d = new EgressDispatcher({ waitFn: noWait, policy: { maxAttempts: 4, baseDelayMs: 1, maxDelayMs: 1 } })
    const res = await d.dispatch(TENANT, sink, envelope)
    assert.equal(res.delivered, true)
    assert.equal(res.attempts, 3)
    assert.equal(calls, 3)
  })

  it('dead-letters after exhausting attempts on a persistently failing sink', async () => {
    let calls = 0
    const sink: EgressSink = async () => { calls++; throw new Error('downstream down') }
    const d = new EgressDispatcher({ waitFn: noWait, policy: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1 } })
    const res = await d.dispatch(TENANT, sink, { ...envelope, batchId: 'batch_dead' })
    assert.equal(res.delivered, false)
    assert.equal(res.attempts, 3)
    assert.equal(calls, 3)
    assert.ok(res.deadLetter)
    assert.equal(res.deadLetter!.envelope.batchId, 'batch_dead')
    assert.match(res.deadLetter!.lastError, /downstream down/)
    assert.equal(d.deadLetterCount(), 1)
  })

  it('emits egress_dispatched, egress_retry, and egress_dead_lettered on the bus', async () => {
    const events: string[] = []
    const cb = (e: any) => { if (e.type.startsWith('egress_')) events.push(e.type) }
    getEventBus().subscribe('tenant_egress_events', cb)
    try {
      const failing: EgressSink = async () => { throw new Error('nope') }
      const d = new EgressDispatcher({ waitFn: noWait, policy: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1 } })
      await d.dispatch('tenant_egress_events', failing, { ...envelope, batchId: 'batch_ev' })
      assert.ok(events.includes('egress_retry'))
      assert.ok(events.includes('egress_dead_lettered'))
      const ok: EgressSink = async () => {}
      await d.dispatch('tenant_egress_events', ok, { ...envelope, batchId: 'batch_ev2' })
      assert.ok(events.includes('egress_dispatched'))
    } finally {
      getEventBus().unsubscribe('tenant_egress_events', cb)
    }
  })

  it('redelivers a dead-lettered batch once the sink recovers', async () => {
    let healthy = false
    const sink: EgressSink = async () => { if (!healthy) throw new Error('still down') }
    const d = new EgressDispatcher({ waitFn: noWait, policy: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1 } })
    await d.dispatch(TENANT, sink, { ...envelope, batchId: 'batch_recover' })
    assert.equal(d.deadLetterCount(), 1)
    healthy = true
    const res = await d.redeliver(TENANT, sink, 'batch_recover')
    assert.ok(res)
    assert.equal(res!.delivered, true)
    assert.equal(d.deadLetterCount(), 0)
  })

  it('redeliver returns null for an unknown batch (negative)', async () => {
    const d = new EgressDispatcher({ waitFn: noWait })
    const res = await d.redeliver(TENANT, async () => {}, 'nope')
    assert.equal(res, null)
  })

  it('backoff grows exponentially and is capped', () => {
    const p = { maxAttempts: 6, baseDelayMs: 100, maxDelayMs: 500 }
    assert.equal(backoffDelay(1, p), 100)
    assert.equal(backoffDelay(2, p), 200)
    assert.equal(backoffDelay(3, p), 400)
    assert.equal(backoffDelay(4, p), 500)
    assert.equal(backoffDelay(10, p), 500)
    assert.equal(DEFAULT_RETRY_POLICY.maxAttempts >= 1, true)
  })
})

// ── End-to-end orchestration: anchor + egress ──

describe('GEM end-to-end: anchor root then egress envelope', () => {
  it('anchors the batch root through rekor and dispatches the envelope', async () => {
    const agg = makeAggregator('tenant_e2e')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()

    const delivered: EgressEnvelope[] = []
    const sink: EgressSink = async (env) => { delivered.push(env) }
    const d = new EgressDispatcher({ waitFn: async () => {} })

    const out = await egressCommittedBatch('tenant_e2e', committed, sink, d)
    assert.ok(out.anchorId)
    assert.equal(out.dispatch.delivered, true)
    assert.equal(delivered.length, 1)
    // The downstream envelope carries the root and summary, never the leaves.
    assert.equal(delivered[0].merkleRoot, committed.batch.merkleRoot)
    assert.equal((delivered[0] as any).leaves, undefined)
    assert.ok(delivered[0].leafFetchRef.includes(committed.batch.batchId))

    // The anchor record exists and is staged pending for batch submission.
    const anchor = getMerkleRootAnchor('tenant_e2e', committed.batch.batchId)
    assert.ok(anchor)
    assert.equal(anchor!.status, 'pending')
  })

  it('anchoring is idempotent per batch', () => {
    const agg = makeAggregator('tenant_idem')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const a = anchorCommittedBatch('tenant_idem', committed)
    const b = anchorCommittedBatch('tenant_idem', committed)
    assert.equal(a.anchorId, b.anchorId)
  })

  it('markCommittedAnchored advances anchor state to anchored', () => {
    const agg = makeAggregator('tenant_anchor_state')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    assert.equal(committed.anchor.state, 'batched_pending')
    const anchored = markCommittedAnchored(committed.anchor, 'rekor:anc_x', 'rekor')
    assert.equal(anchored.state, 'anchored')
  })
})

// ── Auto-batch trigger and chaining ──

describe('GEM auto-batch trigger and epoch chain', () => {
  it('maybeCommit fires only when the count bound is reached', () => {
    const agg = makeAggregator('tenant_trigger')
    agg.add(RECEIPTS[0])
    assert.equal(agg.maybeCommit(), null)
    agg.add(RECEIPTS[1])
    agg.add(RECEIPTS[2])
    const committed = agg.maybeCommit()
    assert.ok(committed)
    assert.equal(committed!.batch.receiptCount, 3)
    assert.equal(agg.pendingCount(), 0)
  })

  it('chains epochs and previous-root links across batches', () => {
    const agg = makeAggregator('tenant_chain')
    for (const r of RECEIPTS) agg.add(r)
    const first = agg.commit()
    agg.add({ leafHash: leaf('r4'), verdict: 'permit', actionType: 'x' })
    agg.add({ leafHash: leaf('r5'), verdict: 'permit', actionType: 'x' })
    const second = agg.commit()
    assert.equal(first.batch.epoch, 0)
    assert.equal(second.batch.epoch, 1)
    assert.equal(second.batch.previousBatchId, first.batch.batchId)
    assert.equal(second.batch.previousMerkleRoot, first.batch.merkleRoot)
  })

  it('committing an empty queue throws (negative)', () => {
    const agg = makeAggregator('tenant_empty')
    assert.throws(() => agg.commit(), /empty batch/)
  })
})

// ── Public projection gate (no leakage) ──

describe('GEM public projection gate', () => {
  it('projects only whitelisted fields and drops counts and leaf refs', () => {
    const agg = makeAggregator('tenant_proj')
    for (const r of RECEIPTS) agg.add(r)
    const committed = agg.commit()
    const pub = projectPublicBatch(committed.envelope)
    assert.equal(pub.merkle_root, committed.batch.merkleRoot)
    assert.equal(pub.schema_version, 'gem_batch_v1')
    // Non-whitelisted internals must not appear.
    assert.equal((pub as any).summary, undefined)
    assert.equal((pub as any).leafFetchRef, undefined)
    assert.equal((pub as any).receiptCount, undefined)
    assert.equal((pub as any).receipt_count, undefined)
  })
})

// ── Durable bus replay (Last-Event-ID reconnect window) ──

describe('GEM durable event bus replay', () => {
  it('replays buffered events to a late subscriber, then filters by afterId', () => {
    const bus = getEventBus()
    const t = 'tenant_replay'
    const e1 = bus.emit(t, { type: 'batch_committed', data: { n: 1 } })
    const e2 = bus.emit(t, { type: 'anchor_submitted', data: { n: 2 } })
    const all = bus.replay(t)
    assert.ok(all.length >= 2)
    const after = bus.replay(t, e1.id)
    assert.ok(after.find((e) => e.id === e2.id))
    assert.ok(!after.find((e) => e.id === e1.id))
  })

  it('replay can filter by event type', () => {
    const bus = getEventBus()
    const t = 'tenant_replay_filter'
    bus.emit(t, { type: 'batch_committed', data: {} })
    bus.emit(t, { type: 'egress_retry', data: {} })
    const onlyRetry = bus.replay(t, undefined, ['egress_retry'])
    assert.ok(onlyRetry.every((e) => e.type === 'egress_retry'))
    assert.ok(onlyRetry.length >= 1)
  })

  it('the backlog is bounded and does not grow without limit', () => {
    const bus = getEventBus()
    const t = 'tenant_replay_bound'
    for (let i = 0; i < 1000; i++) bus.emit(t, { type: 'egress_dispatched', data: { i } })
    assert.ok(bus.backlogSize(t) <= 256)
  })
})

// ── Wave 2 contributor-settlement stub is inert ──

describe('GEM Wave 2 settlement stub', () => {
  it('does not compute a contributor-weighted root until Wave 2 is wired', () => {
    const result = computeContributorSettlement([
      { contributorId: 'c1', weight: 0.6, leafHash: leaf('c1') },
      { contributorId: 'c2', weight: 0.4, leafHash: leaf('c2') },
    ])
    assert.equal(result.computed, false)
    assert.equal(result.merkleRoot, null)
    assert.equal(contributorSettlementAvailable(), false)
  })
})
