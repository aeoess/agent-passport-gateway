// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Modes + policy simulation tests
// ══════════════════════════════════════════════════════════════════
// Covers:
//   - each enforcement mode behaves correctly (observe/warn record only,
//     approval blocks only high-risk, enforce blocks every violation,
//     emergency fails closed on high-risk permits).
//   - per-tenant and per-workflow mode resolution.
//   - policy simulation matches a replay of historical traffic.
//   - the honest disclaimer string is present in the simulation output.
//   - the migration metric reports blocked / would-have-been-denied / tuning.
// ══════════════════════════════════════════════════════════════════

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

import { initDB, getDB } from '../src/db/schema.js'
import { createTenant } from '../src/auth/api-keys.js'
import {
  applyMode,
  classifyRequestRisk,
  isEnforcementMode,
  ENFORCEMENT_MODES,
  type EnforcementMode,
} from '../src/gateway/simulation/modes.js'
import {
  initModeConfigTable,
  resolveMode,
  setMode,
  listModes,
  DEFAULT_MODE,
} from '../src/gateway/simulation/mode-config.js'
import {
  initModeObservationsTable,
  recordModeObservation,
  computeMigrationMetric,
} from '../src/gateway/simulation/migration-metric.js'
import {
  evaluateCandidate,
  simulatePolicy,
  type CandidatePolicy,
} from '../src/gateway/simulation/engine.js'
import { SIMULATION_DISCLAIMER } from '../src/gateway/simulation/disclaimer.js'

let dbPath: string

before(() => {
  dbPath = join(tmpdir(), `aeoess-modes-sim-test-${randomUUID()}.db`)
  initDB(dbPath)
  initModeConfigTable()
  initModeObservationsTable()
})

after(() => {
  try { getDB().close() } catch {}
  try {
    const fs = require('node:fs')
    fs.unlinkSync(dbPath)
    fs.unlinkSync(dbPath + '-wal')
    fs.unlinkSync(dbPath + '-shm')
  } catch {}
})

// SDK-faithful stub for scopeAuthorizes in the pure-function tests: a request
// scope is authorized if an allowed scope equals it or is a prefix root of it.
function fakeScopeAuthorizes(scopes: string[], required: string): boolean {
  if (scopes.includes('*')) return true
  return scopes.some(s => required === s || required.startsWith(s.replace(/:?\*$/, '') + ':'))
}

// ══════════════════════════════════════════════════════════════════
// 1. Each mode behaves correctly (pure applyMode matrix)
// ══════════════════════════════════════════════════════════════════

describe('applyMode - observe (evidence only, never blocks)', () => {
  it('a violation is recorded but never blocked', () => {
    for (const risk of ['low', 'medium', 'high'] as const) {
      const d = applyMode({ rawVerdict: 'deny', risk, mode: 'observe' })
      assert.equal(d.blocked, false, `observe must not block (${risk})`)
      assert.equal(d.effect, 'warn')
      assert.equal(d.wouldHaveBeenDenied, true, 'observe records would-have-been-denied')
    }
  })
  it('a permit stays a permit with no would-deny signal', () => {
    const d = applyMode({ rawVerdict: 'permit', risk: 'high', mode: 'observe' })
    assert.equal(d.blocked, false)
    assert.equal(d.effect, 'permit')
    assert.equal(d.wouldHaveBeenDenied, false)
  })
})

describe('applyMode - warn (shows would-deny, no block)', () => {
  it('a violation is surfaced as warn, not blocked', () => {
    const d = applyMode({ rawVerdict: 'deny', risk: 'high', mode: 'warn' })
    assert.equal(d.blocked, false)
    assert.equal(d.effect, 'warn')
    assert.equal(d.wouldHaveBeenDenied, true)
  })
})

describe('applyMode - approval (blocks only high-risk for sign-off)', () => {
  it('high-risk violation requires approval (blocked pending sign-off)', () => {
    const d = applyMode({ rawVerdict: 'deny', risk: 'high', mode: 'approval' })
    assert.equal(d.blocked, true)
    assert.equal(d.effect, 'approval_required')
    assert.equal(d.wouldHaveBeenDenied, false, 'a blocked request is not would-have-been-denied')
  })
  it('low and medium risk violations pass through with a warning', () => {
    for (const risk of ['low', 'medium'] as const) {
      const d = applyMode({ rawVerdict: 'deny', risk, mode: 'approval' })
      assert.equal(d.blocked, false, `approval must not block ${risk}-risk`)
      assert.equal(d.effect, 'warn')
      assert.equal(d.wouldHaveBeenDenied, true)
    }
  })
})

describe('applyMode - enforce (blocks every violation)', () => {
  it('every violation is blocked regardless of risk', () => {
    for (const risk of ['low', 'medium', 'high'] as const) {
      const d = applyMode({ rawVerdict: 'deny', risk, mode: 'enforce' })
      assert.equal(d.blocked, true, `enforce blocks ${risk}-risk violations`)
      assert.equal(d.effect, 'block')
      assert.equal(d.wouldHaveBeenDenied, false)
    }
  })
  it('a permit is allowed through', () => {
    const d = applyMode({ rawVerdict: 'permit', risk: 'high', mode: 'enforce' })
    assert.equal(d.blocked, false)
    assert.equal(d.effect, 'permit')
  })
})

describe('applyMode - emergency (fails closed on high-risk)', () => {
  it('fails closed: a high-risk PERMIT is blocked during an incident', () => {
    const d = applyMode({ rawVerdict: 'permit', risk: 'high', mode: 'emergency' })
    assert.equal(d.blocked, true, 'emergency holds high-risk even when policy would permit')
    assert.equal(d.effect, 'block')
    assert.equal(d.modeReason, 'emergency_fail_closed_high_risk')
    assert.equal(d.wouldHaveBeenDenied, false, 'fail-closed is mode-derived, not a policy violation')
  })
  it('a low-risk permit is still allowed', () => {
    const d = applyMode({ rawVerdict: 'permit', risk: 'low', mode: 'emergency' })
    assert.equal(d.blocked, false)
    assert.equal(d.effect, 'permit')
  })
  it('every violation is blocked', () => {
    for (const risk of ['low', 'medium', 'high'] as const) {
      const d = applyMode({ rawVerdict: 'deny', risk, mode: 'emergency' })
      assert.equal(d.blocked, true)
      assert.equal(d.effect, 'block')
    }
  })
})

describe('mode ordering invariant - strictness is monotone for violations', () => {
  it('if a less-strict mode blocks a violation, every stricter mode blocks it too', () => {
    // observe < warn < approval < enforce <= emergency on the violation axis.
    const order: EnforcementMode[] = ['observe', 'warn', 'approval', 'enforce', 'emergency']
    for (const risk of ['low', 'medium', 'high'] as const) {
      let sawBlock = false
      for (const mode of order) {
        const blocked = applyMode({ rawVerdict: 'deny', risk, mode }).blocked
        if (sawBlock) {
          assert.equal(blocked, true, `${mode} must stay blocking once a looser mode blocked (${risk})`)
        }
        if (blocked) sawBlock = true
      }
    }
  })
})

// ══════════════════════════════════════════════════════════════════
// 2. Risk classification
// ══════════════════════════════════════════════════════════════════

describe('classifyRequestRisk', () => {
  it('admin / commerce / wallet roots are high risk', () => {
    assert.equal(classifyRequestRisk({ scopeRequired: 'admin:delete', violations: [] }), 'high')
    assert.equal(classifyRequestRisk({ scopeRequired: 'commerce:send', violations: [] }), 'high')
    assert.equal(classifyRequestRisk({ scopeRequired: 'wallet:transfer', violations: [] }), 'high')
  })
  it('spend / budget violations are high risk regardless of scope root', () => {
    assert.equal(classifyRequestRisk({ scopeRequired: 'tool:web', violations: ['Cost $50 exceeds remaining budget $10'] }), 'high')
  })
  it('data writes are medium risk', () => {
    assert.equal(classifyRequestRisk({ scopeRequired: 'data:read', violations: [] }), 'medium')
  })
  it('a plain read tool is low risk', () => {
    assert.equal(classifyRequestRisk({ scopeRequired: 'tool:web_search', violations: [] }), 'low')
  })
})

// ══════════════════════════════════════════════════════════════════
// 3. Mode config - per-tenant and per-workflow resolution
// ══════════════════════════════════════════════════════════════════

describe('mode-config - resolution order', () => {
  it('defaults to observe when nothing is configured', () => {
    const { tenant } = createTenant({ name: 'D1 default', email: `d1-default-${randomUUID()}@example.com` })
    assert.equal(resolveMode(tenant.id), DEFAULT_MODE)
    assert.equal(DEFAULT_MODE, 'observe')
  })

  it('a tenant default overrides the global default', () => {
    const { tenant } = createTenant({ name: 'D1 tenant', email: `d1-tenant-${randomUUID()}@example.com` })
    setMode({ tenantId: tenant.id, mode: 'enforce' })
    assert.equal(resolveMode(tenant.id), 'enforce')
    assert.equal(resolveMode(tenant.id, 'some-workflow'), 'enforce', 'workflow falls back to tenant default')
  })

  it('a per-workflow override wins over the tenant default', () => {
    const { tenant } = createTenant({ name: 'D1 wf', email: `d1-wf-${randomUUID()}@example.com` })
    setMode({ tenantId: tenant.id, mode: 'enforce' })
    setMode({ tenantId: tenant.id, mode: 'observe', workflowId: 'risky-pipeline' })
    assert.equal(resolveMode(tenant.id), 'enforce', 'tenant default unchanged')
    assert.equal(resolveMode(tenant.id, 'risky-pipeline'), 'observe', 'workflow override applies')
    assert.equal(resolveMode(tenant.id, 'other-pipeline'), 'enforce', 'other workflows use tenant default')
  })

  it('setMode upserts in place (no duplicate slots)', () => {
    const { tenant } = createTenant({ name: 'D1 upsert', email: `d1-upsert-${randomUUID()}@example.com` })
    setMode({ tenantId: tenant.id, mode: 'warn' })
    setMode({ tenantId: tenant.id, mode: 'approval' })
    const configured = listModes(tenant.id)
    assert.equal(configured.length, 1)
    assert.equal(configured[0].mode, 'approval')
  })

  it('isEnforcementMode rejects junk and accepts every real mode', () => {
    for (const m of ENFORCEMENT_MODES) assert.equal(isEnforcementMode(m), true)
    assert.equal(isEnforcementMode('blockall'), false)
    assert.equal(isEnforcementMode(''), false)
    assert.equal(isEnforcementMode(null), false)
  })
})

// ══════════════════════════════════════════════════════════════════
// 4. evaluateCandidate - candidate policy logic
// ══════════════════════════════════════════════════════════════════

describe('evaluateCandidate', () => {
  it('denylist wins over everything', () => {
    const cand: CandidatePolicy = { name: 'p', denyScopes: ['admin'], allowScopes: ['admin'] }
    const r = evaluateCandidate({ scopeRequired: 'admin:write', violations: [] }, cand, fakeScopeAuthorizes)
    assert.equal(r.verdict, 'deny')
    assert.equal(r.reason, 'candidate_denylist')
  })
  it('blockHighRisk denies a high-risk request', () => {
    const cand: CandidatePolicy = { name: 'p', blockHighRisk: true }
    const r = evaluateCandidate({ scopeRequired: 'commerce:send', violations: [] }, cand, fakeScopeAuthorizes)
    assert.equal(r.verdict, 'deny')
    assert.equal(r.reason, 'candidate_block_high_risk')
  })
  it('spend cap denies an over-budget request', () => {
    const cand: CandidatePolicy = { name: 'p', spendCap: 10 }
    const r = evaluateCandidate({ scopeRequired: 'tool:x', violations: [], estimatedCost: 25 }, cand, fakeScopeAuthorizes)
    assert.equal(r.verdict, 'deny')
    assert.equal(r.reason, 'candidate_spend_cap')
  })
  it('allowlist denies a scope outside the allowlist', () => {
    const cand: CandidatePolicy = { name: 'p', allowScopes: ['tool:web_search'] }
    const r = evaluateCandidate({ scopeRequired: 'admin:delete', violations: [] }, cand, fakeScopeAuthorizes)
    assert.equal(r.verdict, 'deny')
    assert.equal(r.reason, 'candidate_not_in_allowlist')
  })
  it('allowlist permits a scope inside the allowlist', () => {
    const cand: CandidatePolicy = { name: 'p', allowScopes: ['tool'] }
    const r = evaluateCandidate({ scopeRequired: 'tool:web_search', violations: [] }, cand, fakeScopeAuthorizes)
    assert.equal(r.verdict, 'permit')
  })
})

// ══════════════════════════════════════════════════════════════════
// 5. Simulation matches a replay of historical traffic
// ══════════════════════════════════════════════════════════════════

// Seed policy_evaluations rows directly, mimicking what enforce.ts records.
function seedEval(tenantId: string, agentId: string, actionType: string, scope: string, verdict: 'permit' | 'deny', reason: string) {
  const db = getDB()
  db.prepare(
    `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(randomUUID(), tenantId, agentId, actionType, '', scope, verdict, reason, 1, actionType.split(':')[0])
}

describe('simulatePolicy - replay over historical receipts', () => {
  it('matches a hand-computed replay and carries the disclaimer', async () => {
    const { tenant } = createTenant({ name: 'D1 sim', email: `d1-sim-${randomUUID()}@example.com` })
    // History: 5 permits across tool: and admin:, all originally permitted.
    seedEval(tenant.id, 'agent-a', 'tool:web_search', 'tool:web_search', 'permit', 'ok')
    seedEval(tenant.id, 'agent-a', 'tool:fetch', 'tool:fetch', 'permit', 'ok')
    seedEval(tenant.id, 'agent-b', 'admin:delete', 'admin:delete', 'permit', 'ok')
    seedEval(tenant.id, 'agent-b', 'commerce:send', 'commerce:send', 'permit', 'ok')
    seedEval(tenant.id, 'agent-c', 'data:read', 'data:read', 'permit', 'ok')

    // Candidate: only allow tool:* - so admin/commerce/data would be newly denied.
    const result = await simulatePolicy({
      tenantId: tenant.id,
      candidate: { name: 'tool-only', allowScopes: ['tool'] },
    })

    assert.equal(result.receipts_evaluated, 5)
    assert.equal(result.unchanged, 2, 'the two tool: permits stay permitted')
    assert.equal(result.newly_denied, 3, 'admin, commerce, data become denied')
    assert.equal(result.newly_permitted, 0)
    // admin:delete + commerce:send are high-risk; data:read is medium.
    assert.equal(result.newly_denied_high_risk, 2)
    assert.equal(result.disclaimer, SIMULATION_DISCLAIMER, 'disclaimer present verbatim')
    assert.ok(result.disclaimer.includes('estimates'), 'disclaimer says estimates')
    assert.ok(result.disclaimer.includes('does not guarantee future safety'))
    assert.ok(result.disclaimer.includes('does not prove'), 'disclaimer refuses to claim proof')
    assert.ok(result.disclaimer.includes('does not make you compliant'), 'disclaimer refuses compliance claim')
    // Sample changes reflect the deltas.
    assert.ok(result.sample_changes.every(c => c.delta !== 'unchanged'))
    assert.equal(result.sample_changes.length, 3)
  })

  it('a candidate that newly permits historically-denied traffic is reported', async () => {
    const { tenant } = createTenant({ name: 'D1 sim2', email: `d1-sim2-${randomUUID()}@example.com` })
    // History: a denial recorded.
    seedEval(tenant.id, 'agent-x', 'tool:risky', 'tool:risky', 'deny', 'Scope "tool:risky" not in [tool:safe]')
    // Candidate that allows tool:* would now permit it.
    const result = await simulatePolicy({ tenantId: tenant.id, candidate: { name: 'open-tools', allowScopes: ['tool'] } })
    assert.equal(result.newly_permitted, 1)
    assert.equal(result.newly_denied, 0)
    assert.equal(result.sample_changes[0].delta, 'newly_permitted')
    assert.equal(result.disclaimer, SIMULATION_DISCLAIMER)
  })

  it('an empty history yields a well-formed result with the disclaimer', async () => {
    const { tenant } = createTenant({ name: 'D1 empty', email: `d1-empty-${randomUUID()}@example.com` })
    const result = await simulatePolicy({ tenantId: tenant.id, candidate: { name: 'noop' } })
    assert.equal(result.receipts_evaluated, 0)
    assert.equal(result.newly_denied, 0)
    assert.equal(result.disclaimer, SIMULATION_DISCLAIMER)
  })

  it('agent scoping limits the replay to one agent', async () => {
    const { tenant } = createTenant({ name: 'D1 scope', email: `d1-scope-${randomUUID()}@example.com` })
    seedEval(tenant.id, 'agent-1', 'admin:delete', 'admin:delete', 'permit', 'ok')
    seedEval(tenant.id, 'agent-2', 'admin:delete', 'admin:delete', 'permit', 'ok')
    const result = await simulatePolicy({ tenantId: tenant.id, candidate: { name: 'block-admin', denyScopes: ['admin'] }, agentId: 'agent-1' })
    assert.equal(result.receipts_evaluated, 1)
    assert.equal(result.newly_denied, 1)
    assert.equal(result.window.agent_id, 'agent-1')
  })
})

// ══════════════════════════════════════════════════════════════════
// 6. Migration metric - blocked / would-have-been-denied / tuning
// ══════════════════════════════════════════════════════════════════

describe('computeMigrationMetric', () => {
  it('reports the "0 blocked, N would-have-been-denied, M policies need tuning" line under observe', () => {
    const { tenant } = createTenant({ name: 'D1 metric', email: `d1-metric-${randomUUID()}@example.com` })
    // Two agents produce would-have-been-denied under observe; nothing blocked.
    for (const agent of ['agent-a', 'agent-a', 'agent-b']) {
      recordModeObservation({
        tenantId: tenant.id, agentId: agent, scopeRequired: 'admin:delete',
        decision: applyMode({ rawVerdict: 'deny', risk: 'high', mode: 'observe' }),
      })
    }
    const metric = computeMigrationMetric({ tenantId: tenant.id, currentMode: 'observe' })
    assert.equal(metric.blocked, 0)
    assert.equal(metric.would_have_been_denied, 3)
    assert.equal(metric.policies_need_tuning, 2, 'two distinct agents need tuning')
    assert.equal(metric.would_have_been_denied_high_risk, 3)
    assert.equal(metric.ready_for_enforce, false)
    assert.match(metric.summary, /^0 blocked, 3 would-have-been-denied, 2 policies need tuning before enforce$/)
  })

  it('reports ready_for_enforce when nothing would be newly blocked', () => {
    const { tenant } = createTenant({ name: 'D1 ready', email: `d1-ready-${randomUUID()}@example.com` })
    // No observations recorded -> nothing would be blocked.
    const metric = computeMigrationMetric({ tenantId: tenant.id, currentMode: 'observe' })
    assert.equal(metric.would_have_been_denied, 0)
    assert.equal(metric.ready_for_enforce, true)
    assert.match(metric.summary, /^0 blocked, 0 would-have-been-denied, 0 policies need tuning before enforce$/)
  })

  it('a real block under enforce counts as blocked, not would-have-been-denied', () => {
    const { tenant } = createTenant({ name: 'D1 blk', email: `d1-blk-${randomUUID()}@example.com` })
    recordModeObservation({
      tenantId: tenant.id, agentId: 'agent-z', scopeRequired: 'admin:delete',
      decision: applyMode({ rawVerdict: 'deny', risk: 'high', mode: 'enforce' }),
    })
    const metric = computeMigrationMetric({ tenantId: tenant.id, currentMode: 'enforce' })
    assert.equal(metric.blocked, 1)
    assert.equal(metric.would_have_been_denied, 0)
  })

  it('pure permits are not recorded as observations (no migration signal)', () => {
    const { tenant } = createTenant({ name: 'D1 permit', email: `d1-permit-${randomUUID()}@example.com` })
    const wrote = recordModeObservation({
      tenantId: tenant.id, agentId: 'agent-ok', scopeRequired: 'tool:web',
      decision: applyMode({ rawVerdict: 'permit', risk: 'low', mode: 'observe' }),
    })
    assert.equal(wrote, false)
    const metric = computeMigrationMetric({ tenantId: tenant.id })
    assert.equal(metric.blocked, 0)
    assert.equal(metric.would_have_been_denied, 0)
  })

  it('per-workflow scoping isolates the metric', () => {
    const { tenant } = createTenant({ name: 'D1 wfmetric', email: `d1-wfmetric-${randomUUID()}@example.com` })
    recordModeObservation({
      tenantId: tenant.id, agentId: 'agent-w', workflowId: 'wf-1', scopeRequired: 'admin:x',
      decision: applyMode({ rawVerdict: 'deny', risk: 'high', mode: 'observe' }),
    })
    const m1 = computeMigrationMetric({ tenantId: tenant.id, workflowId: 'wf-1' })
    const m2 = computeMigrationMetric({ tenantId: tenant.id, workflowId: 'wf-2' })
    assert.equal(m1.would_have_been_denied, 1)
    assert.equal(m2.would_have_been_denied, 0)
  })
})
