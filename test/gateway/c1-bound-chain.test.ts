// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// C1 (Day 217) fix verification: bound parent delegation + ancestor-aware authority.
// Functional/HTTP-level coverage over the running gatewayRouter (same harness shape as the
// c1-ancestor-revocation-repro reproducer). Unit-level coverage of the checker itself (corruption
// cases) and the in-transaction race live in c1-bound-chain-checker.test.ts and
// c1-bound-chain-toctou.test.ts respectively.
//
// All /evaluate calls here use data:read (Tier < 3); commerce:checkout is Tier 3 and fails closed
// before any delegation check, which would confound these delegation-chain-focused assertions.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_c1chain'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

function seedAgent(id: string, isRoot = 0, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, ?)`).run(`row-${id}`, TENANT, id, status, isRoot)
}
async function grant(parent: string, child: string, spend: number) {
  const r = await post('/delegations', { parent_agent_id: parent, child_agent_id: child, scope: 'data:read', spend_limit: spend })
  return r
}
async function grantOk(parent: string, child: string, spend: number) {
  const r = await grant(parent, child, spend)
  assert.equal(r.status, 201, `setup grant ${parent}->${child}: ${await r.text()}`)
  return r
}
function delegationRow(parent: string, child: string): any {
  const row = getDB().prepare(`SELECT * FROM delegations WHERE tenant_id = ? AND parent_agent_id = ? AND child_agent_id = ?`).get(TENANT, parent, child) as any
  assert.ok(row, `no row ${parent}->${child}`)
  return row
}
function delegationId(parent: string, child: string): string { return delegationRow(parent, child).id }
function setCreatedAt(delegationId: string, iso: string) {
  getDB().prepare(`UPDATE delegations SET created_at = ? WHERE id = ?`).run(iso, delegationId)
}
async function verdict(agent: string): Promise<{ verdict: string; violations?: string[] }> {
  const body = await (await post('/evaluate', { agent_id: agent, action_type: 'data:read', scope_required: 'data:read', estimated_cost: 1 })).json() as any
  return { verdict: body.verdict, violations: body.violations }
}
async function revokeDelegation(id: string) {
  const r = await post('/revoke', { target_type: 'delegation', target_id: id, revoked_by: 'test' })
  assert.equal(r.status, 200, await r.text())
}
async function revokeAgent(id: string) {
  const r = await post('/revoke', { target_type: 'agent', target_id: id, revoked_by: 'test' })
  assert.equal(r.status, 200, await r.text())
}
async function setPosture(agentId: string, status: string, restricted_scopes?: string[]) {
  const r = await post(`/agents/${agentId}/posture`, { status, reason: 'test', restricted_scopes })
  assert.equal(r.status, 200, await r.text())
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'C1Chain', 'c1chain@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('C1 control: root-originated one-hop grant permits', () => {
  it('a fresh root grant to a fresh child permits', async () => {
    seedAgent('ctrl-root', 1); seedAgent('ctrl-child')
    await grantOk('ctrl-root', 'ctrl-child', 10)
    assert.equal((await verdict('ctrl-child')).verdict, 'permit')
  })
})

describe('C1 multi-inbound binding: revoking an unbound sibling inbound does not affect the bound child', () => {
  it('forward: B->C bound to P1->B; P2->B arrives later; revoking P1->B denies C', async () => {
    seedAgent('mib-P1', 1); seedAgent('mib-P2', 1); seedAgent('mib-B'); seedAgent('mib-C')
    await grantOk('mib-P1', 'mib-B', 100) // B's only inbound at this point
    await grantOk('mib-B', 'mib-C', 10)   // binds to P1->B
    await grantOk('mib-P2', 'mib-B', 100) // B now also has a second, later inbound -- does not rebind C
    await revokeDelegation(delegationId('mib-P1', 'mib-B'))
    assert.equal((await verdict('mib-C')).verdict, 'deny', 'C is bound to the specific P1->B row, now revoked')
  })

  it('reverse: B->C bound to P2->B (the newest inbound at grant time); revoking P1->B leaves C permitted', async () => {
    seedAgent('mibr-P1', 1); seedAgent('mibr-P2', 1); seedAgent('mibr-B'); seedAgent('mibr-C')
    await grantOk('mibr-P1', 'mibr-B', 100)
    await grantOk('mibr-P2', 'mibr-B', 100)
    // Force a deterministic ordering (created_at has 1s resolution): P2->B is the newest inbound.
    setCreatedAt(delegationId('mibr-P1', 'mibr-B'), '2000-01-01 00:00:01')
    setCreatedAt(delegationId('mibr-P2', 'mibr-B'), '2000-01-01 00:00:02')
    await grantOk('mibr-B', 'mibr-C', 10) // must bind to P2->B, the newest
    assert.equal(delegationRow('mibr-B', 'mibr-C').parent_delegation_id, delegationId('mibr-P2', 'mibr-B'))
    await revokeDelegation(delegationId('mibr-P1', 'mibr-B'))
    assert.equal((await verdict('mibr-C')).verdict, 'permit', 'C is bound to P2->B, untouched by revoking the unrelated P1->B')
  })
})

describe('C1 newest-inbound side effect, intentionally fail-closed', () => {
  it('C holds an older valid inbound and a newer inbound whose own chain is dead: /evaluate denies', async () => {
    seedAgent('nif-X', 1); seedAgent('nif-R2', 1); seedAgent('nif-Y'); seedAgent('nif-C')
    await grantOk('nif-X', 'nif-C', 10)   // C's older inbound: fully valid, root-originated
    await grantOk('nif-R2', 'nif-Y', 100) // Y's inbound
    await grantOk('nif-Y', 'nif-C', 10)   // C's newer inbound, bound to R2->Y
    setCreatedAt(delegationId('nif-X', 'nif-C'), '2000-01-01 00:00:01')
    setCreatedAt(delegationId('nif-Y', 'nif-C'), '2000-01-01 00:00:02') // strictly newer
    await revokeDelegation(delegationId('nif-R2', 'nif-Y')) // kills Y's chain, hence C's newer inbound
    assert.equal((await verdict('nif-C')).verdict, 'deny', 'the newest-inbound selection picks the dead chain even though an older valid inbound exists')
  })
})

describe('C1 agent posture propagates through the bound chain', () => {
  it('revoking an agent two hops up denies the grandchild', async () => {
    seedAgent('pos-A', 1); seedAgent('pos-B'); seedAgent('pos-C'); seedAgent('pos-D')
    await grantOk('pos-A', 'pos-B', 100); await grantOk('pos-B', 'pos-C', 50); await grantOk('pos-C', 'pos-D', 20)
    assert.equal((await verdict('pos-D')).verdict, 'permit', 'control')
    await revokeAgent('pos-B') // two hops above D
    assert.equal((await verdict('pos-D')).verdict, 'deny')
  })

  it('suspending an intermediate agent denies the grandchild; unsuspending restores it with no delegation row changes', async () => {
    seedAgent('susp-A', 1); seedAgent('susp-B'); seedAgent('susp-C'); seedAgent('susp-D')
    await grantOk('susp-A', 'susp-B', 100); await grantOk('susp-B', 'susp-C', 50); await grantOk('susp-C', 'susp-D', 20)
    assert.equal((await verdict('susp-D')).verdict, 'permit', 'control')
    const beforeStatuses = ['susp-A>susp-B', 'susp-B>susp-C', 'susp-C>susp-D'].map((k) => {
      const [p, c] = k.split('>'); return delegationRow(p, c).status
    })
    await setPosture('susp-B', 'suspended')
    assert.equal((await verdict('susp-D')).verdict, 'deny')
    await setPosture('susp-B', 'active')
    assert.equal((await verdict('susp-D')).verdict, 'permit', 'restored with no delegation row rewritten')
    const afterStatuses = ['susp-A>susp-B', 'susp-B>susp-C', 'susp-C>susp-D'].map((k) => {
      const [p, c] = k.split('>'); return delegationRow(p, c).status
    })
    assert.deepEqual(afterStatuses, beforeStatuses, 'no delegation row status changed across suspend/unsuspend')
  })

  it('suspending the terminal root grantor denies its immediate one-hop child (semantic change, see handoff)', async () => {
    seedAgent('root-susp-A', 1); seedAgent('root-susp-B')
    await grantOk('root-susp-A', 'root-susp-B', 10)
    assert.equal((await verdict('root-susp-B')).verdict, 'permit', 'control')
    await setPosture('root-susp-A', 'suspended')
    assert.equal((await verdict('root-susp-B')).verdict, 'deny', 'the terminal grantor is on the bound chain too')
  })
})

describe('C1 restricted versus suspended, pinned', () => {
  it('an intermediate agent set to restricted keeps its descendant permitted but cannot itself grant; suspended denies; restoring to active re-permits with no row changes', async () => {
    seedAgent('rvs-A', 1); seedAgent('rvs-B'); seedAgent('rvs-C'); seedAgent('rvs-F')
    await grantOk('rvs-A', 'rvs-B', 100); await grantOk('rvs-B', 'rvs-C', 50)
    assert.equal((await verdict('rvs-C')).verdict, 'permit', 'control')

    await setPosture('rvs-B', 'restricted', ['admin:delete'])
    assert.equal((await verdict('rvs-C')).verdict, 'permit', 'restricted keeps the chain live for the descendant')
    const grantAttempt = await grant('rvs-B', 'rvs-F', 5)
    assert.equal(grantAttempt.status, 403, 'a restricted agent keeps existing authority but cannot extend it')

    const beforeStatus = delegationRow('rvs-B', 'rvs-C').status
    await setPosture('rvs-B', 'suspended')
    assert.equal((await verdict('rvs-C')).verdict, 'deny', 'suspended invalidates the chain')

    await setPosture('rvs-B', 'active')
    assert.equal((await verdict('rvs-C')).verdict, 'permit', 'restored')
    assert.equal(delegationRow('rvs-B', 'rvs-C').status, beforeStatus, 'no delegation row was rewritten across the posture changes')
  })
})

describe('C1 grant-path route gate: an already-dead chain is rejected before the transaction', () => {
  it('a narrowing grant from a grantor whose ancestor chain is already revoked is 403 with a chain code', async () => {
    seedAgent('gate-A', 1); seedAgent('gate-B'); seedAgent('gate-C'); seedAgent('gate-new-child')
    await grantOk('gate-A', 'gate-B', 100); await grantOk('gate-B', 'gate-C', 50)
    await revokeDelegation(delegationId('gate-A', 'gate-B')) // kills C's chain before it ever tries to grant
    const r = await grant('gate-C', 'gate-new-child', 5)
    assert.equal(r.status, 403)
    const body = await r.json() as any
    assert.ok(body.code, 'route-level 403 carries a stable chain code')
    assert.equal(typeof body.hop, 'number')
  })
})
