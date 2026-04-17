// ══════════════════════════════════════════════════════════════════
// Posture state-machine tests — migrated from SDK after the downgrade
// ratchet + manual upgrade workflow moved out of agent-passport-system.
// SDK retains tier types, constraint shapes, and pure helpers.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createInitialPosture, recordBehavioralFailure, recordBehavioralSuccess,
  upgradePosture, DEFAULT_DOWNGRADE_POLICY,
} from '../../../src/sdk-migrated/core/posture-state.js'

describe('Governance Posture — Initial State', () => {
  it('creates with default standard tier', () => {
    const p = createInitialPosture()
    assert.strictEqual(p.tier, 'standard')
    assert.strictEqual(p.consecutiveFailures, 0)
    assert.strictEqual(p.history.length, 0)
  })

  it('creates with custom initial tier', () => {
    const p = createInitialPosture('full_trust')
    assert.strictEqual(p.tier, 'full_trust')
  })

  it('exposes default downgrade policy thresholds', () => {
    assert.strictEqual(DEFAULT_DOWNGRADE_POLICY.fullToStandard, 3)
    assert.strictEqual(DEFAULT_DOWNGRADE_POLICY.standardToCautious, 5)
    assert.strictEqual(DEFAULT_DOWNGRADE_POLICY.cautiousToRestricted, 3)
    assert.strictEqual(DEFAULT_DOWNGRADE_POLICY.restrictedToQuarantine, 2)
  })
})

describe('Governance Posture — Auto-Downgrade', () => {
  it('does not downgrade below threshold', () => {
    let p = createInitialPosture('standard')
    p = recordBehavioralFailure(p, 'test failure 1')
    p = recordBehavioralFailure(p, 'test failure 2')
    assert.strictEqual(p.tier, 'standard', 'Should not downgrade after 2 failures')
    assert.strictEqual(p.consecutiveFailures, 2)
  })

  it('downgrades standard → cautious at threshold (5)', () => {
    let p = createInitialPosture('standard')
    for (let i = 0; i < 5; i++) {
      p = recordBehavioralFailure(p, `failure ${i + 1}`)
    }
    assert.strictEqual(p.tier, 'cautious')
    assert.strictEqual(p.consecutiveFailures, 0, 'Resets after downgrade')
    assert.strictEqual(p.history.length, 1)
    assert.strictEqual(p.history[0].from, 'standard')
    assert.strictEqual(p.history[0].to, 'cautious')
  })

  it('cascades through multiple tiers with sustained failures', () => {
    let p = createInitialPosture('full_trust')
    for (let i = 0; i < 3; i++) p = recordBehavioralFailure(p, 'fail')
    assert.strictEqual(p.tier, 'standard')
    for (let i = 0; i < 5; i++) p = recordBehavioralFailure(p, 'fail')
    assert.strictEqual(p.tier, 'cautious')
    for (let i = 0; i < 3; i++) p = recordBehavioralFailure(p, 'fail')
    assert.strictEqual(p.tier, 'restricted')
    for (let i = 0; i < 2; i++) p = recordBehavioralFailure(p, 'fail')
    assert.strictEqual(p.tier, 'quarantine')
    assert.strictEqual(p.history.length, 4)
  })

  it('cannot go below quarantine', () => {
    let p = createInitialPosture('quarantine')
    for (let i = 0; i < 10; i++) p = recordBehavioralFailure(p, 'fail')
    assert.strictEqual(p.tier, 'quarantine')
  })

  it('success resets consecutive failure counter', () => {
    let p = createInitialPosture('standard')
    p = recordBehavioralFailure(p, 'fail 1')
    p = recordBehavioralFailure(p, 'fail 2')
    assert.strictEqual(p.consecutiveFailures, 2)
    p = recordBehavioralSuccess(p)
    assert.strictEqual(p.consecutiveFailures, 0)
    assert.strictEqual(p.tier, 'standard', 'Tier unchanged by success')
  })

  it('success prevents downgrade by breaking consecutive chain', () => {
    let p = createInitialPosture('standard')
    for (let i = 0; i < 4; i++) p = recordBehavioralFailure(p, 'fail')
    p = recordBehavioralSuccess(p)
    for (let i = 0; i < 4; i++) p = recordBehavioralFailure(p, 'fail')
    assert.strictEqual(p.tier, 'standard', 'Should not downgrade — chain broken')
  })
})

describe('Governance Posture — Manual Upgrade', () => {
  it('upgrades one tier at a time', () => {
    let p = createInitialPosture('restricted')
    p = upgradePosture(p, 'did:aps:principal001', 'Behavior improved')
    assert.strictEqual(p.tier, 'cautious')
    assert.strictEqual(p.changedBy, 'did:aps:principal001')
    assert.strictEqual(p.history.length, 1)
  })

  it('cannot upgrade above full_trust', () => {
    let p = createInitialPosture('full_trust')
    const before = p.tier
    p = upgradePosture(p, 'did:aps:principal001', 'Already max')
    assert.strictEqual(p.tier, before)
  })

  it('upgrade resets failure counters', () => {
    let p = createInitialPosture('cautious')
    p = recordBehavioralFailure(p, 'fail')
    p = recordBehavioralFailure(p, 'fail')
    p = upgradePosture(p, 'did:aps:principal001', 'Reviewed and approved')
    assert.strictEqual(p.consecutiveFailures, 0)
    assert.strictEqual(p.failuresSinceChange, 0)
  })
})
