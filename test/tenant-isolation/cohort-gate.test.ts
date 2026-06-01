// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-D4 / constraint C3 - cross-tenant cohort k-floor gate.
//
// The load-bearing assertions:
//   - NEVER emit a single-tenant-derived signal (k floor);
//   - the floor HOLDS OVER TIME-SERIES: two time-separated emissions where
//     the cohort membership churned are suppressed even though each cleared
//     k on its own snapshot (the differencing-attack case);
//   - non-opted-in / hard-isolated contributors are rejected;
//   - the CALIBRATED_NOISE_DP strategy is a documented seam, not implemented.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../../src/db/schema.js'
import {
  gateCohortEmission,
  membershipDigest,
  membershipChurn,
  setIsolationMode,
  setCohortOptIn,
  TimeSeriesFloorStrategy,
  DEFAULT_COHORT_GATE_CONFIG,
  type CohortContribution,
  type CohortGateConfig,
} from '../../src/gateway/tenant-isolation/index.js'

// Helper: create a tenant already in standard mode and opted in, so it can
// legitimately contribute to a cohort.
function makeOptedInTenant(id: string) {
  getDB().prepare(
    `INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`,
  ).run(id, id, `${id}@example.com`)
  setIsolationMode(id, 'standard')
  setCohortOptIn(id, true)
}

function contribution(id: string): CohortContribution {
  return {
    tenantId: id,
    byVerdict: { permit: 3, deny: 1 },
    byActionType: { 'cloud:provision': 4 },
    observationCount: 4,
  }
}

const CONFIG: CohortGateConfig = { ...DEFAULT_COHORT_GATE_CONFIG, kFloor: 5, maxChurn: 2 }

before(() => {
  initDB(':memory:')
})

describe('cohort gate - per-snapshot k floor (no single-tenant signal)', () => {
  beforeEach(() => {
    getDB().prepare(`DELETE FROM tenants`).run()
    getDB().prepare(`DELETE FROM cohort_emissions`).run()
  })

  it('suppresses a below-k cohort (k=4 < floor 5)', () => {
    const ids = ['a', 'b', 'c', 'd']
    ids.forEach(makeOptedInTenant)
    const r = gateCohortEmission('cohort:x', 'm1', ids.map(contribution), CONFIG)
    assert.equal(r.emitted, false)
    assert.equal(r.code, 'below_k_floor')
  })

  it('never emits a single-tenant signal even if kFloor is misconfigured to 1', () => {
    makeOptedInTenant('solo')
    const badConfig: CohortGateConfig = { ...CONFIG, kFloor: 1 }
    const r = gateCohortEmission('cohort:x', 'm1', [contribution('solo')], badConfig)
    // effectiveFloor = max(kFloor, 2), so a single tenant is always blocked.
    assert.equal(r.emitted, false)
    assert.equal(r.code, 'below_k_floor')
  })

  it('emits an aggregate-only signal at k>=floor, carrying NO tenant identity', () => {
    // Use distinctive multi-char tenant ids so the no-identity check is not
    // confused by single-char substrings of unrelated keys like action types.
    const ids = ['tnt-aaaa', 'tnt-bbbb', 'tnt-cccc', 'tnt-dddd', 'tnt-eeee']
    ids.forEach(makeOptedInTenant)
    const r = gateCohortEmission('cohort:x', 'm1', ids.map(contribution), CONFIG)
    assert.equal(r.emitted, true)
    assert.equal(r.kObserved, 5)
    assert.ok(r.signal)
    // The signal is counts only.
    assert.equal(r.signal!.total, 20) // 5 tenants * 4 observations
    assert.equal(r.signal!.byVerdict.permit, 15)
    assert.equal(r.signal!.byVerdict.deny, 5)
    // No tenant identity anywhere in the signal.
    const serialized = JSON.stringify(r.signal)
    for (const id of ids) {
      assert.ok(!serialized.includes(id), `signal must not contain tenant id ${id}`)
    }
  })
})

describe('cohort gate - opt-in / isolation precondition', () => {
  beforeEach(() => {
    getDB().prepare(`DELETE FROM tenants`).run()
    getDB().prepare(`DELETE FROM cohort_emissions`).run()
  })

  it('rejects the emission if any contributor is hard-isolated', () => {
    const ids = ['a', 'b', 'c', 'd', 'e']
    ids.forEach(makeOptedInTenant)
    // Add a sixth contributor that is hard-isolated (regulated).
    getDB().prepare(
      `INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`,
    ).run('regulated', 'regulated', 'regulated@example.com') // defaults to hard
    const contribs = [...ids, 'regulated'].map(contribution)
    const r = gateCohortEmission('cohort:x', 'm1', contribs, CONFIG)
    assert.equal(r.emitted, false)
    assert.equal(r.code, 'non_opted_in_member')
  })

  it('rejects the emission if any contributor has not opted in', () => {
    const ids = ['a', 'b', 'c', 'd']
    ids.forEach(makeOptedInTenant)
    // A standard-mode tenant that did NOT opt in.
    getDB().prepare(
      `INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`,
    ).run('std-no-optin', 'std-no-optin', 'sno@example.com')
    setIsolationMode('std-no-optin', 'standard')
    const r = gateCohortEmission('cohort:x', 'm1', [...ids, 'std-no-optin'].map(contribution), CONFIG)
    assert.equal(r.emitted, false)
    assert.equal(r.code, 'non_opted_in_member')
  })
})

describe('cohort gate - k floor HOLDS OVER TIME-SERIES (C3, the headline)', () => {
  beforeEach(() => {
    getDB().prepare(`DELETE FROM tenants`).run()
    getDB().prepare(`DELETE FROM cohort_emissions`).run()
  })

  it('two time-separated emissions with STABLE membership both emit', () => {
    const ids = ['a', 'b', 'c', 'd', 'e']
    ids.forEach(makeOptedInTenant)
    const first = gateCohortEmission('cohort:ts', 'metric', ids.map(contribution), CONFIG)
    assert.equal(first.emitted, true)
    assert.equal(first.emissionSeq, 1)
    // Same membership at t2 -> stable -> emits again.
    const second = gateCohortEmission('cohort:ts', 'metric', ids.map(contribution), CONFIG)
    assert.equal(second.emitted, true)
    assert.equal(second.emissionSeq, 2)
  })

  it('SUPPRESSES the second emission when membership churns (differencing risk)', () => {
    // t1 cohort {a,b,c,d,e} (k=5, ok).
    const t1 = ['a', 'b', 'c', 'd', 'e']
    t1.forEach(makeOptedInTenant)
    const first = gateCohortEmission('cohort:diff', 'metric', t1.map(contribution), CONFIG)
    assert.equal(first.emitted, true)

    // t2 cohort {a,b,c,d,f} (k=5, clears the per-snapshot floor) but a member
    // was swapped (e out, f in). Each snapshot independently passes k, yet
    // differencing t2 - t1 would isolate e and f. The time-series gate must
    // suppress this.
    makeOptedInTenant('f')
    const t2 = ['a', 'b', 'c', 'd', 'f']
    const second = gateCohortEmission('cohort:diff', 'metric', t2.map(contribution), CONFIG)
    assert.equal(second.emitted, false, 'a pure-swap second emission must be suppressed')
    assert.equal(second.code, 'time_series_churn_suppressed')
  })

  it('SUPPRESSES the second emission when the cohort shrinks across time', () => {
    // t1 {a,b,c,d,e,f,g} (k=7), t2 {a,b,c,d,e} (k=5). Both clear k=5, but the
    // shrink of 2 members across time enables differencing.
    const t1 = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    t1.forEach(makeOptedInTenant)
    const first = gateCohortEmission('cohort:shrink', 'metric', t1.map(contribution), CONFIG)
    assert.equal(first.emitted, true)
    const t2 = ['a', 'b', 'c', 'd', 'e']
    const second = gateCohortEmission('cohort:shrink', 'metric', t2.map(contribution), CONFIG)
    assert.equal(second.emitted, false)
    assert.equal(second.code, 'time_series_churn_suppressed')
  })

  it('independent metric_key time-series do not interfere', () => {
    const ids = ['a', 'b', 'c', 'd', 'e']
    ids.forEach(makeOptedInTenant)
    const m1 = gateCohortEmission('cohort:multi', 'metric-1', ids.map(contribution), CONFIG)
    const m2 = gateCohortEmission('cohort:multi', 'metric-2', ids.map(contribution), CONFIG)
    assert.equal(m1.emitted, true)
    assert.equal(m2.emitted, true)
    assert.equal(m1.emissionSeq, 1)
    assert.equal(m2.emissionSeq, 1) // separate series, separate counter
  })

  it('the emissions ledger stores membership DIGESTS, never raw tenant ids', () => {
    const ids = ['a', 'b', 'c', 'd', 'e']
    ids.forEach(makeOptedInTenant)
    gateCohortEmission('cohort:digest', 'metric', ids.map(contribution), CONFIG)
    const rows = getDB().prepare(`SELECT * FROM cohort_emissions`).all() as any[]
    assert.equal(rows.length, 1)
    const serialized = JSON.stringify(rows[0])
    for (const id of ids) {
      assert.ok(!serialized.includes(`"${id}"`), `ledger must not store raw tenant id ${id}`)
    }
    // member_digest is a sha256 hex.
    assert.match(rows[0].member_digest, /^[0-9a-f]{64}$/)
  })
})

describe('cohort gate - strategy fork is a documented decision seam', () => {
  it('CALIBRATED_NOISE_DP is not implemented (founder-gate decision)', () => {
    const ids = ['a', 'b', 'c', 'd', 'e']
    ids.forEach(makeOptedInTenant)
    const dpConfig: CohortGateConfig = {
      ...CONFIG,
      strategy: TimeSeriesFloorStrategy.CALIBRATED_NOISE_DP,
    }
    const r = gateCohortEmission('cohort:dp', 'metric', ids.map(contribution), dpConfig)
    assert.equal(r.emitted, false)
    assert.equal(r.code, 'unsupported_strategy')
    assert.match(r.reason, /decision seam/)
  })
})

describe('cohort gate - membership digest helpers', () => {
  it('membershipDigest is order-independent', () => {
    assert.equal(
      membershipDigest(['a', 'b', 'c']),
      membershipDigest(['c', 'a', 'b']),
    )
  })

  it('membershipDigest changes when a member changes', () => {
    assert.notEqual(
      membershipDigest(['a', 'b', 'c']),
      membershipDigest(['a', 'b', 'd']),
    )
  })

  it('membershipChurn counts the symmetric difference', () => {
    assert.equal(membershipChurn(['a', 'b', 'c'], ['a', 'b', 'c']), 0)
    assert.equal(membershipChurn(['a', 'b', 'c'], ['a', 'b', 'd']), 2) // c out, d in
    assert.equal(membershipChurn(['a', 'b'], ['a', 'b', 'c']), 1) // c in
  })
})
