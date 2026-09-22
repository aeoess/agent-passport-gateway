// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// C1 (Day 217): direct unit coverage of checkBoundAuthorityChain -- the one private checker shared by
// the grant path and /evaluate. Exercises rows that cannot arise through the legitimate API (a forged
// or corrupted parent_delegation_id, a cross-tenant reference, a cycle, an over-long chain, an agent
// status outside the domain the chain treats as live) by writing directly to the delegations/agents
// tables. Each case must fail closed with its own stable code and hop index, never row data.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../../src/db/schema.js'
import { checkBoundAuthorityChain } from '../../src/gateway/enforce.js'

const T = 'tnt_c1checker'
const T2 = 'tnt_c1checker_other'

function seedAgent(tenant: string, id: string, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, 0)`).run(`row-${tenant}-${id}`, tenant, id, status)
}
function seedDel(opts: {
  id: string; tenant?: string; parent: string; child: string; status?: string; parentDelId?: string | null
}) {
  getDB().prepare(
    `INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, spend_limit, status, parent_delegation_id) VALUES (?, ?, ?, ?, 'data:read', 100, ?, ?)`
  ).run(opts.id, opts.tenant ?? T, opts.parent, opts.child, opts.status ?? 'active', opts.parentDelId ?? null)
}

before(() => {
  initDB(':memory:')
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T, 'Checker', 'checker@test.local')
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T2, 'CheckerOther', 'checker-other@test.local')
})

describe('checkBoundAuthorityChain - controls', () => {
  it('a terminal origination row (parent_delegation_id NULL) with a live grantor is ok', () => {
    seedAgent(T, 'ctl-root'); seedAgent(T, 'ctl-child')
    seedDel({ id: 'ctl-d1', parent: 'ctl-root', child: 'ctl-child', parentDelId: null })
    assert.deepEqual(checkBoundAuthorityChain(getDB(), T, 'ctl-d1'), { ok: true })
  })

  it('a multi-hop chain of live rows and live agents is ok', () => {
    seedAgent(T, 'ctlm-A'); seedAgent(T, 'ctlm-B'); seedAgent(T, 'ctlm-C')
    seedDel({ id: 'ctlm-d1', parent: 'ctlm-A', child: 'ctlm-B', parentDelId: null })
    seedDel({ id: 'ctlm-d2', parent: 'ctlm-B', child: 'ctlm-C', parentDelId: 'ctlm-d1' })
    assert.deepEqual(checkBoundAuthorityChain(getDB(), T, 'ctlm-d2'), { ok: true })
  })

  it('exactly 64 hops is still ok (the boundary is > 64, not >= 64)', () => {
    let prevId: string | null = null
    let prevAgent = 'deep-agent-0'
    seedAgent(T, prevAgent)
    for (let i = 1; i <= 64; i++) {
      const nextAgent = `deep-agent-${i}`
      seedAgent(T, nextAgent)
      const id = `deep-d${i}`
      seedDel({ id, parent: prevAgent, child: nextAgent, parentDelId: prevId })
      prevId = id
      prevAgent = nextAgent
    }
    assert.deepEqual(checkBoundAuthorityChain(getDB(), T, prevId as string), { ok: true })
  })
})

describe('checkBoundAuthorityChain - corruption fails closed with a stable code and hop', () => {
  it('missing parent row', () => {
    seedAgent(T, 'mp-B')
    seedDel({ id: 'mp-d1', parent: 'mp-B', child: 'mp-child', parentDelId: 'does-not-exist' })
    seedAgent(T, 'mp-child')
    const r = checkBoundAuthorityChain(getDB(), T, 'mp-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'missing_row')
    assert.equal(r.hop, 2)
  })

  it('cross-tenant parent row', () => {
    seedAgent(T, 'ct-B'); seedAgent(T2, 'ct-other-root')
    seedDel({ id: 'ct-parent', tenant: T2, parent: 'ct-other-root', child: 'ct-B', parentDelId: null })
    seedDel({ id: 'ct-d1', parent: 'ct-B', child: 'ct-child', parentDelId: 'ct-parent' })
    seedAgent(T, 'ct-child')
    const r = checkBoundAuthorityChain(getDB(), T, 'ct-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'cross_tenant')
    assert.equal(r.hop, 2)
  })

  it('continuity mismatch: the parent row child_agent_id does not match this row parent_agent_id', () => {
    seedAgent(T, 'cm-root'); seedAgent(T, 'cm-decoy'); seedAgent(T, 'cm-B'); seedAgent(T, 'cm-child')
    seedDel({ id: 'cm-parent', parent: 'cm-root', child: 'cm-decoy', parentDelId: null }) // child is decoy, NOT cm-B
    seedDel({ id: 'cm-d1', parent: 'cm-B', child: 'cm-child', parentDelId: 'cm-parent' }) // claims cm-parent bounds cm-B
    const r = checkBoundAuthorityChain(getDB(), T, 'cm-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'continuity_mismatch')
    assert.equal(r.hop, 2)
  })

  it('a 2-cycle is detected, not an infinite loop', () => {
    seedAgent(T, 'cyc-A'); seedAgent(T, 'cyc-B')
    seedDel({ id: 'cyc-d1', parent: 'cyc-A', child: 'cyc-B', parentDelId: 'cyc-d2' })
    seedDel({ id: 'cyc-d2', parent: 'cyc-B', child: 'cyc-A', parentDelId: 'cyc-d1' })
    const r = checkBoundAuthorityChain(getDB(), T, 'cyc-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'cycle')
  })

  it('a 65-hop chain exceeds the max hop bound', () => {
    let prevId: string | null = null
    let prevAgent = 'deep65-agent-0'
    seedAgent(T, prevAgent)
    for (let i = 1; i <= 65; i++) {
      const nextAgent = `deep65-agent-${i}`
      seedAgent(T, nextAgent)
      const id = `deep65-d${i}`
      seedDel({ id, parent: prevAgent, child: nextAgent, parentDelId: prevId })
      prevId = id
      prevAgent = nextAgent
    }
    const r = checkBoundAuthorityChain(getDB(), T, prevId as string)
    assert.equal(r.ok, false)
    assert.equal(r.code, 'max_hops_exceeded')
    assert.equal(r.hop, 65)
  })

  it('an inactive (non-active status) delegation row on the path fails closed', () => {
    seedAgent(T, 'ir-root'); seedAgent(T, 'ir-B'); seedAgent(T, 'ir-child')
    seedDel({ id: 'ir-parent', parent: 'ir-root', child: 'ir-B', parentDelId: null, status: 'revoked' })
    seedDel({ id: 'ir-d1', parent: 'ir-B', child: 'ir-child', parentDelId: 'ir-parent' })
    const r = checkBoundAuthorityChain(getDB(), T, 'ir-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'inactive_delegation')
    assert.equal(r.hop, 2)
  })

  it('a missing grantor agent fails closed', () => {
    seedDel({ id: 'ma-d1', parent: 'ma-ghost-grantor', child: 'ma-child', parentDelId: null })
    seedAgent(T, 'ma-child')
    const r = checkBoundAuthorityChain(getDB(), T, 'ma-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'missing_agent')
    assert.equal(r.hop, 1)
  })
})

describe('checkBoundAuthorityChain - agent status decides liveness at every hop', () => {
  it('a suspended grantor invalidates the chain', () => {
    seedAgent(T, 'sg-root', 'suspended'); seedAgent(T, 'sg-child')
    seedDel({ id: 'sg-d1', parent: 'sg-root', child: 'sg-child', parentDelId: null })
    const r = checkBoundAuthorityChain(getDB(), T, 'sg-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'agent_suspended')
  })

  it('a revoked grantor invalidates the chain', () => {
    seedAgent(T, 'rg-root', 'revoked'); seedAgent(T, 'rg-child')
    seedDel({ id: 'rg-d1', parent: 'rg-root', child: 'rg-child', parentDelId: null })
    const r = checkBoundAuthorityChain(getDB(), T, 'rg-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'agent_revoked')
  })

  it('a restricted grantor keeps the chain live', () => {
    seedAgent(T, 'restg-root', 'restricted'); seedAgent(T, 'restg-child')
    seedDel({ id: 'restg-d1', parent: 'restg-root', child: 'restg-child', parentDelId: null })
    assert.deepEqual(checkBoundAuthorityChain(getDB(), T, 'restg-d1'), { ok: true })
  })

  it('an unknown/other agent status (frozen) fails closed, not treated as live', () => {
    seedAgent(T, 'frz-root', 'frozen'); seedAgent(T, 'frz-child')
    seedDel({ id: 'frz-d1', parent: 'frz-root', child: 'frz-child', parentDelId: null })
    const r = checkBoundAuthorityChain(getDB(), T, 'frz-d1')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'agent_unknown_status')
  })
})
