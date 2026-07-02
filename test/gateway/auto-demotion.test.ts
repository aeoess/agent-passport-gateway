// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R4-1 (round-3 Consilium): audited demotion on subordination. is_root=1 survived
// an agent becoming a child, so the loop designate A -> A receives a (grantor-
// initiated) inbound -> inbound revoked -> A originates fresh budget again, with no
// new admin act and a stale audit row. Silent clearing was rejected (any grantor
// could destroy an admin's designation). Settled synthesis: when a designated root
// RECEIVES an inbound delegation it is demoted (is_root=0) IN THE SAME TRANSACTION
// as the delegation insert, and an audited auto_demotion row is written (carrying
// the causing delegation id + the grantor). Restoration is the existing audited
// POST /root-designations (re_root:true + reason, since it now has an ever-inbound).
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'
import { getEventBus } from '../../src/gateway/events.js'

const T = 'tnt_demote'
let server: Server, baseUrl: string
let role = 'user'
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
function seedAgent(id: string, isRoot = 0, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, ?)`).run(`row-${id}`, T, id, status, isRoot)
}
const isRootOf = (id: string) => (getDB().prepare(`SELECT is_root FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(T, id) as any)?.is_root
const demotionRows = (id: string) => getDB().prepare(`SELECT * FROM root_designations WHERE tenant_id = ? AND agent_id = ? AND action = 'auto_demotion'`).all(T, id) as any[]
const delCount = (child: string) => (getDB().prepare(`SELECT COUNT(*) c FROM delegations WHERE tenant_id = ? AND child_agent_id = ?`).get(T, child) as any).c

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T, 'Demote', 'dm@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: T, role, plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('R4-1 audited auto-demotion on subordination', () => {
  it('[FULL LOOP] designate -> subordinate (demoted+audited) -> revoke -> 403 DEAD -> re-designate -> grant', async () => {
    role = 'admin'
    seedAgent('A', 0, 'active')
    assert.equal((await post('/root-designations', { agent_id: 'A' })).status, 200)
    assert.equal(isRootOf('A'), 1, 'designated')
    role = 'user'
    // A designated root grantor subordinates A by delegating to it.
    seedAgent('gRoot', 1, 'active')
    const grant = await post('/delegations', { parent_agent_id: 'gRoot', child_agent_id: 'A', scope: 'commerce:checkout', spend_limit: 5 })
    const grantBody = await grant.json() as any
    assert.equal(grant.status, 201, JSON.stringify(grantBody))
    assert.equal(isRootOf('A'), 0, 'A demoted on receiving an inbound')
    const rows = demotionRows('A')
    assert.equal(rows.length, 1, 'exactly one auto_demotion audit row')
    assert.ok(rows[0].caused_by_delegation_id, 'demotion row carries the causing delegation id')

    // Revoke the inbound; A now has an ever-inbound (revoked) and is_root=0.
    const theDelId = getDB().prepare(`SELECT id FROM delegations WHERE tenant_id=? AND child_agent_id='A'`).get(T) as any
    await post('/revoke', { target_type: 'delegation', target_id: theDelId.id })
    seedAgent('newc', 0)
    const deadGrant = await post('/delegations', { parent_agent_id: 'A', child_agent_id: 'newc', scope: 'commerce:checkout', spend_limit: 1 })
    assert.equal(deadGrant.status, 403, 'A cannot originate after demotion (DEAD)')

    // Admin restores via the audited re-root path (A has ever-inbound -> re_root + reason required).
    role = 'admin'
    assert.equal((await post('/root-designations', { agent_id: 'A', re_root: true, reason: 'operator restore after subordination' })).status, 200)
    role = 'user'
    seedAgent('newc2', 0)
    assert.equal((await post('/delegations', { parent_agent_id: 'A', child_agent_id: 'newc2', scope: 'commerce:checkout', spend_limit: 1 })).status, 201, 'A grants again after re-designation')
  })

  it('[HOSTILE GRANTOR] any live grantor subordinating a root is audited (grantor recorded) and recoverable', async () => {
    role = 'admin'; seedAgent('R', 0, 'active')
    await post('/root-designations', { agent_id: 'R' })
    role = 'user'
    // A low-privilege but live grantor (a normal delegatee with an active inbound) subordinates R.
    seedAgent('rootX', 1, 'active'); seedAgent('mid', 0, 'active')
    await post('/delegations', { parent_agent_id: 'rootX', child_agent_id: 'mid', scope: 'commerce:checkout', spend_limit: 50 })
    const g = await post('/delegations', { parent_agent_id: 'mid', child_agent_id: 'R', scope: 'commerce:checkout', spend_limit: 1 })
    assert.equal(g.status, 201, await g.text())
    assert.equal(isRootOf('R'), 0, 'R demoted by the hostile grantor')
    const rows = demotionRows('R')
    assert.equal(rows.length, 1)
    assert.equal(rows[0].designated_by, 'mid', 'the causing grantor is recorded in the audit row')
    // Recoverable by an admin.
    role = 'admin'
    assert.equal((await post('/root-designations', { agent_id: 'R', re_root: true, reason: 'restore after hostile subordination' })).status, 200)
    assert.equal(isRootOf('R'), 1)
    role = 'user'
  })

  it('a delegation to a NON-root child writes NO demotion row', async () => {
    role = 'admin'; seedAgent('rootY', 1, 'active'); role = 'user'
    seedAgent('plainChild', 0, 'active')
    await post('/delegations', { parent_agent_id: 'rootY', child_agent_id: 'plainChild', scope: 'commerce:checkout', spend_limit: 5 })
    assert.equal(demotionRows('plainChild').length, 0, 'no demotion for a non-root child')
  })

  it('[R5-2] a root_auto_demotion event is emitted on demotion and absent on a non-root grant', async () => {
    const events: any[] = []
    getEventBus().subscribe(T, (ev: any) => { if (ev.type === 'root_auto_demotion') events.push(ev) })
    role = 'admin'; seedAgent('evRoot', 0, 'active')
    await post('/root-designations', { agent_id: 'evRoot' })
    role = 'user'
    seedAgent('evGrantor', 1, 'active')
    // Non-root grant first: must NOT emit a demotion event.
    seedAgent('evPlain', 0, 'active')
    await post('/delegations', { parent_agent_id: 'evGrantor', child_agent_id: 'evPlain', scope: 'commerce:checkout', spend_limit: 5 })
    assert.equal(events.length, 0, 'no demotion event for a non-root child')
    // Subordinate the designated root: must emit exactly one demotion event carrying the provenance.
    const g = await post('/delegations', { parent_agent_id: 'evGrantor', child_agent_id: 'evRoot', scope: 'commerce:checkout', spend_limit: 5 })
    const delId = (await g.json() as any).id
    assert.equal(events.length, 1, 'one demotion event on subordinating a root')
    assert.equal(events[0].data.agent, 'evRoot')
    assert.equal(events[0].data.grantor, 'evGrantor')
    assert.equal(events[0].data.caused_by_delegation_id, delId)
  })

  it('[ATOMIC] a failing demotion audit write rolls back the whole delegation', async () => {
    role = 'admin'; seedAgent('atomicRoot', 0, 'active')
    await post('/root-designations', { agent_id: 'atomicRoot' })
    role = 'user'
    seedAgent('atomicGrantor', 1, 'active')
    // Force the auto_demotion audit INSERT to abort inside the transaction.
    getDB().exec(`CREATE TRIGGER block_auto_demotion BEFORE INSERT ON root_designations WHEN NEW.action = 'auto_demotion' BEGIN SELECT RAISE(ABORT, 'blocked for atomicity test'); END`)
    try {
      const before = delCount('atomicRoot')
      const r = await post('/delegations', { parent_agent_id: 'atomicGrantor', child_agent_id: 'atomicRoot', scope: 'commerce:checkout', spend_limit: 1 })
      assert.notEqual(r.status, 201, 'the grant must not succeed if its demotion audit fails')
      assert.equal(delCount('atomicRoot'), before, 'the delegation insert rolled back with the audit failure')
      assert.equal(isRootOf('atomicRoot'), 1, 'is_root unchanged on rollback')
    } finally {
      getDB().exec(`DROP TRIGGER block_auto_demotion`)
    }
  })
})
