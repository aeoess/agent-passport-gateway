// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-C2 layer (c): customer pre-signed incident playbooks (constraint C1).
//
// Tests: a playbook fires ONLY pre-authorized actions; post-review is enforced;
// a high-risk action is blocked when no signed playbook covers it; the customer
// kill denies the playbook AT THE SINK (offline epoch check) with no gateway
// call in the kill path; root-rotation cascade-revokes stale playbooks.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../src/db/schema.js'
import { initLineageTables } from '../src/gateway/lineage.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import {
  initPlaybookTables,
  registerPlaybook,
  fireResponse,
  customerKillPlaybooks,
  reviewFire,
  pendingReviews,
  isPlaybookLive,
  scopeCoveredByLivePlaybook,
  findAuthorizingPlaybook,
  type PlaybookResponse,
} from '../src/gateway/playbooks/index.js'
import {
  getCurrentEpochSeam,
  tokenEpochGuardSeam,
} from '../src/gateway/playbooks/b2-seam.js'
import {
  evaluateGuards,
  isScopeHighRisk,
  DEFAULT_HIGH_RISK_SCOPES,
  type GuardContext,
} from '../src/gateway/guards/index.js'

const TENANT = 'tenant-playbook-test'
const SUBJECT = 'customer-root-delegation-1'

const RESPONSES: PlaybookResponse[] = [
  { responseId: 'r1', action: 'route_alert', scope: 'governance:route_alert' },
  { responseId: 'r2', action: 'recommend_freeze', scope: 'governance:recommend' },
]

before(() => {
  initDB(':memory:')
  initLineageTables()
  initGatewayIdentity()
  initPlaybookTables()
})

beforeEach(() => {
  const db = getDB()
  db.exec(`DELETE FROM gc2_playbooks; DELETE FROM gc2_playbook_fires;`)
  // Reset the customer-subject epoch counter so kill tests start clean.
  db.prepare(`DELETE FROM gateway_config WHERE key LIKE 'epoch:delegation:%'`).run()
})

function register(ttlHours = 24) {
  return registerPlaybook({
    tenantId: TENANT,
    name: 'incident-containment',
    trigger: 'integration_health:degraded',
    authorizedResponses: RESPONSES,
    delegationId: 'cust-signed-delegation-abc',
    subjectKind: 'delegation',
    subjectId: SUBJECT,
    ttlHours,
  })
}

describe('G-C2 playbooks - registration binds to the current epoch', () => {
  it('records the signed epoch and is live at registration', () => {
    const pb = register()
    assert.equal(pb.status, 'live')
    assert.equal(pb.signedEpoch, getCurrentEpochSeam(TENANT, 'delegation', SUBJECT))
    assert.equal(isPlaybookLive(pb).live, true)
    assert.ok(pb.recordSignature.length > 0)
  })
})

describe('G-C2 playbooks - fires ONLY pre-authorized actions', () => {
  it('fires a pre-authorized response', () => {
    register()
    const r = fireResponse({
      tenantId: TENANT,
      trigger: 'integration_health:degraded',
      responseScope: 'governance:route_alert',
      triggerPayload: { detail: 'x' },
    })
    assert.equal(r.fired, true)
    assert.equal(r.record?.reviewState, 'pending_review')
    assert.equal(r.record?.sinkAllowedAtFire, true)
  })

  it('REFUSES a response that is not in the signed playbook (no free-form response)', () => {
    register()
    const r = fireResponse({
      tenantId: TENANT,
      trigger: 'integration_health:degraded',
      responseScope: 'revocation:execute', // not an authorized response scope
      triggerPayload: null,
    })
    assert.equal(r.fired, false)
    assert.match(r.reason, /no live signed playbook/)
  })

  it('REFUSES a response under a trigger no playbook is registered for', () => {
    register()
    const r = fireResponse({
      tenantId: TENANT,
      trigger: 'some_other_trigger',
      responseScope: 'governance:route_alert',
      triggerPayload: null,
    })
    assert.equal(r.fired, false)
  })
})

describe('G-C2 playbooks - high-risk blocked when no signed playbook covers it', () => {
  it('scopeCoveredByLivePlaybook is false for an uncovered high-risk scope', () => {
    register() // covers governance:route_alert + governance:recommend, NOT revocation:execute
    assert.equal(scopeCoveredByLivePlaybook(TENANT, 'revocation:execute'), false)
  })
  it('scopeCoveredByLivePlaybook is true for a covered scope', () => {
    register()
    assert.equal(scopeCoveredByLivePlaybook(TENANT, 'governance:route_alert'), true)
  })
})

describe('G-C2 playbooks - mandatory post-review enforced', () => {
  it('a fire starts pending_review and must be reviewed', () => {
    register()
    const r = fireResponse({
      tenantId: TENANT,
      trigger: 'integration_health:degraded',
      responseScope: 'governance:route_alert',
      triggerPayload: null,
    })
    const fireId = r.record!.fireId
    assert.equal(pendingReviews(TENANT).length, 1)

    const reviewed = reviewFire({ tenantId: TENANT, fireId, reviewedBy: 'ops@customer', actionTaken: false })
    assert.equal(reviewed.reviewed, true)
    assert.equal(reviewed.reason, 'reviewed_ok')
    assert.equal(pendingReviews(TENANT).length, 0)
  })

  it('a fire cannot be reviewed twice', () => {
    register()
    const r = fireResponse({ tenantId: TENANT, trigger: 'integration_health:degraded', responseScope: 'governance:route_alert', triggerPayload: null })
    const fireId = r.record!.fireId
    reviewFire({ tenantId: TENANT, fireId, reviewedBy: 'ops', actionTaken: true })
    const again = reviewFire({ tenantId: TENANT, fireId, reviewedBy: 'ops', actionTaken: true })
    assert.equal(again.reviewed, false)
    assert.match(again.reason, /already/)
  })

  it('review requires a reviewer principal', () => {
    register()
    const r = fireResponse({ tenantId: TENANT, trigger: 'integration_health:degraded', responseScope: 'governance:route_alert', triggerPayload: null })
    const bad = reviewFire({ tenantId: TENANT, fireId: r.record!.fireId, reviewedBy: '', actionTaken: false })
    assert.equal(bad.reviewed, false)
  })
})

describe('G-C2 playbooks - customer kill is SINK-ENFORCED OFFLINE, no AEOESS in the path', () => {
  it('killing bumps the epoch so the signed epoch is stale at the sink', () => {
    const pb = register()
    // Before kill: the sink would honor the playbook's stamped epoch.
    assert.equal(tokenEpochGuardSeam({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, epoch: pb.signedEpoch }).allowed, true)

    // The CUSTOMER kills, authenticated as themselves. No gateway approval, no
    // AEOESS actor: killedBy is the customer principal.
    const kill = customerKillPlaybooks({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, killedBy: 'customer-admin@acme', reason: 'incident over' })
    assert.ok(kill.killedPlaybookIds.includes(pb.playbookId))

    // After kill: the SINK (offline epoch check) now denies the stamped epoch.
    // This is the enforcement point - no gateway call is needed for the sink to
    // deny; tokenEpochGuardSeam reads only the epoch counter.
    const sink = tokenEpochGuardSeam({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, epoch: pb.signedEpoch })
    assert.equal(sink.allowed, false)
    assert.match(sink.reason, /stale epoch/)
  })

  it('a killed playbook can no longer fire and is not live', () => {
    const pb = register()
    customerKillPlaybooks({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, killedBy: 'customer-admin@acme' })

    // The registry row is marked killed AND the live check (sink-style) fails.
    const live = isPlaybookLive({ ...pb })
    assert.equal(live.live, false)

    const r = fireResponse({ tenantId: TENANT, trigger: 'integration_health:degraded', responseScope: 'governance:route_alert', triggerPayload: null })
    assert.equal(r.fired, false, 'a killed playbook must not fire')
  })

  it('refuses a kill with no authenticated customer actor', () => {
    register()
    assert.throws(() => customerKillPlaybooks({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, killedBy: '' }))
  })
})

describe('G-C2 playbooks - root rotation cascade-revokes stale playbooks', () => {
  it('a later epoch bump (root rotation) makes a prior-epoch playbook stale at the sink', () => {
    const pb = register()
    // Simulate a root rotation: an authenticated actor bumps the subject epoch
    // (this is what the B2 GEMS engine does on root rotation). The playbook was
    // signed at the prior epoch and is now stale.
    customerKillPlaybooks({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, killedBy: 'root-rotation-actor', reason: 'root rotated' })
    assert.equal(findAuthorizingPlaybook(TENANT, 'integration_health:degraded', 'governance:route_alert'), null)
    assert.equal(isPlaybookLive(pb).live, false)
  })
})

describe('G-C2 layers (a)+(c) integration - guard resolves coverage from the live registry', () => {
  // This mirrors EXACTLY what enforce.ts does pre-flight: resolve high-risk,
  // resolve playbook coverage from the registry, then run the compiled guard.
  function guardForHighRiskScope(scope: string): GuardContext {
    const isHighRisk = isScopeHighRisk(scope, DEFAULT_HIGH_RISK_SCOPES)
    const covered = isHighRisk ? scopeCoveredByLivePlaybook(TENANT, scope) : false
    return {
      agentStatus: 'active',
      scopeRequired: scope,
      actionType: scope,
      estimatedCost: 0,
      isHighRisk,
      coveredBySignedPlaybook: covered,
      costCeiling: 0,
    }
  }

  it('a high-risk action is BLOCKED pre-flight when no signed playbook covers it', () => {
    // A playbook covering only governance scopes does NOT cover revocation:execute.
    registerPlaybook({
      tenantId: TENANT, name: 'pb', trigger: 'integration_health:degraded',
      authorizedResponses: RESPONSES, delegationId: 'd', subjectKind: 'delegation', subjectId: SUBJECT, ttlHours: 24,
    })
    const decision = evaluateGuards(guardForHighRiskScope('revocation:execute'))
    assert.equal(decision.verdict, 'block')
    assert.equal(decision.code, 'guard_high_risk_unsigned')
  })

  it('the same high-risk action PASSES once a live playbook covers its scope', () => {
    // Register a playbook whose authorized response covers revocation:execute.
    registerPlaybook({
      tenantId: TENANT, name: 'pb-revoke', trigger: 'breach:confirmed',
      authorizedResponses: [{ responseId: 'r', action: 'execute_revocation', scope: 'revocation:execute' }],
      delegationId: 'd2', subjectKind: 'delegation', subjectId: SUBJECT, ttlHours: 24,
    })
    const decision = evaluateGuards(guardForHighRiskScope('revocation:execute'))
    assert.equal(decision.verdict, 'pass')
  })

  it('after the customer kill, the covering playbook is stale and the action is BLOCKED again at pre-flight', () => {
    registerPlaybook({
      tenantId: TENANT, name: 'pb-revoke', trigger: 'breach:confirmed',
      authorizedResponses: [{ responseId: 'r', action: 'execute_revocation', scope: 'revocation:execute' }],
      delegationId: 'd2', subjectKind: 'delegation', subjectId: SUBJECT, ttlHours: 24,
    })
    assert.equal(evaluateGuards(guardForHighRiskScope('revocation:execute')).verdict, 'pass')
    // Customer kills (epoch bump). The registry coverage drops; the guard blocks.
    customerKillPlaybooks({ tenantId: TENANT, subjectKind: 'delegation', subjectId: SUBJECT, killedBy: 'customer-admin@acme' })
    const decision = evaluateGuards(guardForHighRiskScope('revocation:execute'))
    assert.equal(decision.verdict, 'block')
    assert.equal(decision.code, 'guard_high_risk_unsigned')
  })
})

describe('G-C2 playbooks - TTL expiry', () => {
  it('an expired playbook is not live even without an epoch bump', () => {
    const pb = register(1)
    // 2 hours past the 1-hour TTL.
    const future = Date.now() + 2 * 3600_000
    assert.equal(isPlaybookLive(pb, future).live, false)
  })
})
