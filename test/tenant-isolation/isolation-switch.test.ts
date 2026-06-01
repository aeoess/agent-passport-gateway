// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-D4 - per-tenant isolation switch (D2). Confirms:
//   - isolation-by-default: a freshly created tenant is hard isolated;
//   - a regulated (hard) tenant cannot reach any cross-tenant path even if a
//     buggy caller sets the opt-in flag;
//   - opting a hard tenant in is refused;
//   - moving to hard clears any standing opt-in.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../../src/db/schema.js'
import {
  getTenantIsolationState,
  canParticipateCrossTenant,
  canTenantParticipateCrossTenant,
  setIsolationMode,
  setCohortOptIn,
} from '../../src/gateway/tenant-isolation/index.js'

function makeTenant(id: string, email: string) {
  getDB().prepare(
    `INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`,
  ).run(id, id, email)
}

before(() => {
  initDB(':memory:')
})

describe('isolation switch - D2 isolation-by-default', () => {
  beforeEach(() => {
    getDB().prepare(`DELETE FROM tenants`).run()
  })

  it('a freshly created tenant defaults to hard isolation, not opted in', () => {
    makeTenant('t-default', 'default@example.com')
    const state = getTenantIsolationState('t-default')
    assert.ok(state)
    assert.equal(state!.isolationMode, 'hard')
    assert.equal(state!.cohortOptIn, false)
    assert.equal(state!.airGapped, false)
  })

  it('a regulated (hard) tenant cannot participate cross-tenant', () => {
    makeTenant('t-hard', 'hard@example.com')
    const decision = canTenantParticipateCrossTenant('t-hard')
    assert.equal(decision.allowed, false)
    assert.equal(decision.code, 'hard_isolation_block')
  })

  it('hard isolation blocks even when cohort_opt_in is somehow set (fail-safe order)', () => {
    makeTenant('t-buggy', 'buggy@example.com')
    // Simulate a buggy caller writing opt-in directly, bypassing setCohortOptIn.
    getDB().prepare(`UPDATE tenants SET cohort_opt_in = 1 WHERE id = ?`).run('t-buggy')
    const state = getTenantIsolationState('t-buggy')!
    assert.equal(state.isolationMode, 'hard')
    assert.equal(state.cohortOptIn, true) // the bad write took effect...
    const decision = canParticipateCrossTenant(state)
    // ...but hard isolation is checked BEFORE opt-in, so it still blocks.
    assert.equal(decision.allowed, false)
    assert.equal(decision.code, 'hard_isolation_block')
  })

  it('refuses to opt a hard-isolated tenant into the cohort', () => {
    makeTenant('t-refuse', 'refuse@example.com')
    const r = setCohortOptIn('t-refuse', true)
    assert.equal(r.applied, false)
    assert.match(r.reason, /move to standard first/)
  })

  it('standard + opted-in tenant may participate', () => {
    makeTenant('t-std', 'std@example.com')
    setIsolationMode('t-std', 'standard')
    const r = setCohortOptIn('t-std', true)
    assert.equal(r.applied, true)
    const decision = canTenantParticipateCrossTenant('t-std')
    assert.equal(decision.allowed, true)
    assert.equal(decision.code, 'permitted')
  })

  it('moving back to hard clears the standing opt-in', () => {
    makeTenant('t-revert', 'revert@example.com')
    setIsolationMode('t-revert', 'standard')
    setCohortOptIn('t-revert', true)
    assert.equal(getTenantIsolationState('t-revert')!.cohortOptIn, true)
    setIsolationMode('t-revert', 'hard')
    const state = getTenantIsolationState('t-revert')!
    assert.equal(state.isolationMode, 'hard')
    assert.equal(state.cohortOptIn, false)
    assert.equal(canTenantParticipateCrossTenant('t-revert').code, 'hard_isolation_block')
  })

  it('air-gapped standard tenant is blocked regardless of opt-in', () => {
    makeTenant('t-air', 'air@example.com')
    setIsolationMode('t-air', 'standard')
    setCohortOptIn('t-air', true)
    getDB().prepare(`UPDATE tenants SET air_gapped = 1 WHERE id = ?`).run('t-air')
    const decision = canTenantParticipateCrossTenant('t-air')
    assert.equal(decision.allowed, false)
    assert.equal(decision.code, 'air_gapped_block')
  })

  it('unknown tenant fails safe (blocked)', () => {
    assert.equal(getTenantIsolationState('nope'), null)
    assert.equal(canParticipateCrossTenant(null).allowed, false)
  })

  it('regulated-tenant isolation switch BLOCKS any cross-tenant path (spec test)', () => {
    // The headline spec assertion: a regulated tenant in hard isolation has
    // no reachable cross-tenant path. Even after explicitly trying to enrol it
    // (which the switch refuses), the participation check still blocks.
    makeTenant('t-regulated', 'regulated@example.com')
    const enrol = setCohortOptIn('t-regulated', true)
    assert.equal(enrol.applied, false)
    assert.equal(canTenantParticipateCrossTenant('t-regulated').allowed, false)
  })
})
