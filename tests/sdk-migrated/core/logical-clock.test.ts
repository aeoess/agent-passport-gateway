// LogicalClock tests — verify the per-instance counter wrapper around
// the SDK's pure timestamp math behaves the way per-gateway counters
// were specified to behave (monotonic, isolatable, mergeable).

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { compareTimestamps } from 'agent-passport-system'
import { LogicalClock } from '../../../src/sdk-migrated/core/logical-clock.js'

describe('LogicalClock — basic ticking', () => {
  it('produces monotonically increasing logical time', () => {
    const c = new LogicalClock()
    const t1 = c.tick('gw_test')
    const t2 = c.tick('gw_test')
    const t3 = c.tick('gw_test')
    assert.ok(t1.logicalTime < t2.logicalTime)
    assert.ok(t2.logicalTime < t3.logicalTime)
    assert.equal(t1.logicalTime, 1)
    assert.equal(t2.logicalTime, 2)
    assert.equal(t3.logicalTime, 3)
  })

  it('wall clock bounds bracket now within drift', () => {
    const c = new LogicalClock({ driftMs: 50 })
    const before = Date.now()
    const ts = c.tick('gw_test')
    const after = Date.now()
    assert.ok(ts.wallClockEarliest <= before)
    assert.ok(ts.wallClockLatest >= after)
  })

  it('honors the per-call driftMs override', () => {
    const c = new LogicalClock({ driftMs: 50 })
    const ts = c.tick('gw_test', 200)
    const span = ts.wallClockLatest - ts.wallClockEarliest
    assert.equal(span, 400)
  })
})

describe('LogicalClock — isolation between instances', () => {
  it('two clocks evolve independently', () => {
    const a = new LogicalClock()
    const b = new LogicalClock()
    a.tick('gw_a')
    a.tick('gw_a')
    b.tick('gw_b')
    assert.equal(a.current(), 2)
    assert.equal(b.current(), 1)
  })
})

describe('LogicalClock — observe (Lamport merge)', () => {
  it('pulls counter forward to observed.logicalTime + 1 when behind', () => {
    const c = new LogicalClock()
    c.observe({ logicalTime: 100, wallClockEarliest: 0, wallClockLatest: 0, gatewayId: 'gw_x' })
    assert.equal(c.current(), 101)
    const next = c.tick('gw_self')
    assert.equal(next.logicalTime, 102)
  })

  it('leaves counter alone when observed is older', () => {
    const c = new LogicalClock({ initial: 50 })
    c.observe({ logicalTime: 10, wallClockEarliest: 0, wallClockLatest: 0, gatewayId: 'gw_x' })
    assert.equal(c.current(), 50)
  })
})

describe('LogicalClock — reset', () => {
  it('reset restores starting state', () => {
    const c = new LogicalClock()
    c.tick('g'); c.tick('g'); c.tick('g')
    c.reset()
    assert.equal(c.current(), 0)
    const next = c.tick('g')
    assert.equal(next.logicalTime, 1)
  })
})

describe('LogicalClock — interplay with compareTimestamps', () => {
  it('same-gateway sequential ticks compare causally', async () => {
    const c = new LogicalClock()
    const t1 = c.tick('gw')
    // Simulate elapsed wall-clock time so ranges don't overlap.
    await new Promise(r => setTimeout(r, 110))
    const t2 = c.tick('gw')
    const ord = compareTimestamps(t1, t2)
    assert.ok(ord === 'definitely_before' || ord === 'causally_before')
  })
})
