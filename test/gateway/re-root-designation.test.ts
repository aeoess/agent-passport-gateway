// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R3-1 (round-2 Consilium): R2 (DEAD branch) defeated R8 (audited re-rooting).
// In the no-inbound branch of POST /delegations the order was everInbound -> 403
// DEAD, THEN is_root. So an admin-designated ex-child (is_root=1, audit row written)
// still 403'd DEAD: the deliberate, audited override was silently ineffective for
// exactly the re-rooting topology. Fix: check is_root FIRST (a designated root
// originates regardless of history), THEN DEAD, THEN ABSENT.
// Companion in POST /root-designations: refuse a non-active target; if the target
// has EVER had an inbound delegation, require re_root:true + a reason and record
// both in the audit row.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const T = 'tnt_reroot'
let server: Server, baseUrl: string
let role = 'user'
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
function seedAgent(id: string, isRoot = 0, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, ?)`).run(`row-${id}`, T, id, status, isRoot)
}
function seedDelegation(id: string, parent: string, child: string, status = 'active') {
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit) VALUES (?, ?, ?, ?, 'commerce:checkout', ?, 100)`).run(id, T, parent, child, status)
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T, 'ReRoot', 'rr@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: T, role, plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('R3-1 gate order: designated root originates before the DEAD branch', () => {
  it('[BUG] a designated ex-child (is_root=1 + a revoked inbound) CAN originate', async () => {
    seedAgent('exchild', 1, 'active'); seedAgent('newchild', 0)
    seedDelegation('d-ex', 'someRoot', 'exchild', 'revoked') // ever a child, now DEAD
    const r = await post('/delegations', { parent_agent_id: 'exchild', child_agent_id: 'newchild', scope: 'commerce:checkout', spend_limit: 10 })
    assert.equal(r.status, 201, `designation must override the DEAD path: ${await r.text()}`)
  })

  it('an ex-child WITHOUT designation still 403s DEAD (unchanged)', async () => {
    seedAgent('exchild2', 0, 'active'); seedAgent('nc2', 0)
    seedDelegation('d-ex2', 'someRoot', 'exchild2', 'revoked')
    const r = await post('/delegations', { parent_agent_id: 'exchild2', child_agent_id: 'nc2', scope: 'commerce:checkout', spend_limit: 10 })
    assert.equal(r.status, 403, await r.text())
    assert.match((await (await post('/delegations', { parent_agent_id: 'exchild2', child_agent_id: 'nc2', scope: 'x', spend_limit: 1 })).json() as any).error, /revoked or expired|severed|no longer active/i)
  })
})

describe('R3-1 root-designations companion: status + re_root semantics', () => {
  it('[ATTACK] designating a REVOKED agent is refused', async () => {
    role = 'admin'
    seedAgent('rvk', 0, 'revoked')
    const r = await post('/root-designations', { agent_id: 'rvk' })
    assert.ok(r.status === 400 || r.status === 403, `revoked target must be refused, got ${r.status}`)
    role = 'user'
  })

  it('[ATTACK] designating an EVER-INBOUND agent without re_root:true is refused', async () => {
    role = 'admin'
    seedAgent('everin', 0, 'active')
    seedDelegation('d-everin', 'root', 'everin', 'revoked')
    const r = await post('/root-designations', { agent_id: 'everin' })
    assert.equal(r.status, 400, await r.text())
    assert.match((await (await post('/root-designations', { agent_id: 'everin' })).json() as any).error, /re_root|reason/i)
    role = 'user'
  })

  it('an EVER-INBOUND agent WITH re_root:true + reason is designated and the audit row carries both', async () => {
    role = 'admin'
    seedAgent('everin2', 0, 'active')
    seedDelegation('d-everin2', 'root', 'everin2', 'revoked')
    const r = await post('/root-designations', { agent_id: 'everin2', re_root: true, reason: 'ownership transfer to new operator' })
    assert.equal(r.status, 200, await r.text())
    const agent = getDB().prepare(`SELECT is_root FROM agents WHERE tenant_id = ? AND agent_id = 'everin2'`).get(T) as any
    assert.equal(agent.is_root, 1)
    const audit = getDB().prepare(`SELECT re_root, reason FROM root_designations WHERE tenant_id = ? AND agent_id = 'everin2'`).get(T) as any
    assert.equal(audit.re_root, 1, 're_root recorded')
    assert.match(audit.reason, /ownership transfer/, 'reason recorded')
    role = 'user'
  })

  it('a never-inbound active agent designates normally (no re_root needed)', async () => {
    role = 'admin'
    seedAgent('fresh', 0, 'active')
    const r = await post('/root-designations', { agent_id: 'fresh' })
    assert.equal(r.status, 200, await r.text())
    const audit = getDB().prepare(`SELECT re_root FROM root_designations WHERE tenant_id = ? AND agent_id = 'fresh'`).get(T) as any
    assert.equal(audit.re_root, 0, 'a fresh designation is not a re-root')
    role = 'user'
  })
})
