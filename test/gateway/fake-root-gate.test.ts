// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Audit item 3 (HIGH, money): fake-root spend/depth reset.
// A parent with no inbound delegation was treated as a free-granting root
// (spend_used=0, current_depth=0). Any no-inbound agent could be named a
// fresh-budget root and reset an exhausted child's spend and chain depth.
// Fix: only a DESIGNATED root (agents.is_root=1) may grant with no inbound
// delegation. A one-time backfill promotes existing de-facto roots.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import Database from 'better-sqlite3'
import { initDB, getDB, backfillAgentRoots } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_fakeroot'
let server: Server
let baseUrl: string

function post(path: string, body: unknown) {
  return fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
}
function seedAgent(agentId: string, isRoot = 0) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`)
    .run(`row-${agentId}`, TENANT, agentId, isRoot)
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'FakeRoot Test', 'fr@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() })
  })
})
after(() => { server?.close() })

describe('fake-root gate (audit item 3)', () => {
  it('[BUG REPRO] a non-root parent with no inbound delegation cannot mint a fresh-budget delegation', async () => {
    seedAgent('nonroot', 0); seedAgent('child-a', 0)
    const r = await post('/delegations', { parent_agent_id: 'nonroot', child_agent_id: 'child-a', scope: 'commerce:checkout', spend_limit: 500 })
    assert.equal(r.status, 403, await r.text())
    assert.match((await (await post('/delegations', { parent_agent_id: 'nonroot', child_agent_id: 'child-a', scope: 'x', spend_limit: 1 })).json() as any).error, /designated root/i)
  })

  it('a DESIGNATED root (is_root=1) still grants freely', async () => {
    seedAgent('root-1', 1); seedAgent('child-b', 0)
    const r = await post('/delegations', { parent_agent_id: 'root-1', child_agent_id: 'child-b', scope: 'commerce:checkout', spend_limit: 500 })
    const body = await r.json() as any
    assert.equal(r.status, 201, JSON.stringify(body))
    assert.equal(body.status, 'active')
  })

  it('depth cannot be reset to 0 via a non-root no-inbound parent (item-2 coupling closed)', async () => {
    // The only way to get current_depth=0 is a no-inbound parent. A non-root no-inbound parent is
    // now rejected, so an exhausted-depth child cannot be handed a fresh depth-0 delegation.
    seedAgent('sneaky-depth', 0); seedAgent('deep-child', 0)
    const r = await post('/delegations', { parent_agent_id: 'sneaky-depth', child_agent_id: 'deep-child', scope: 'commerce:checkout', spend_limit: 10, max_depth: 3 })
    assert.equal(r.status, 403)
  })

  it('an unknown parent agent is rejected (fail closed) in the root branch', async () => {
    seedAgent('child-c', 0)
    const r = await post('/delegations', { parent_agent_id: 'ghost-parent', child_agent_id: 'child-c', scope: 'x', spend_limit: 1 })
    assert.equal(r.status, 404)
  })

  it('POST /agents IGNORES a client-supplied is_root (Consilium policy: no self-service root)', async () => {
    const rr = await post('/agents', { agent_id: 'reg-root', public_key: 'pk-root', is_root: true })
    assert.equal(rr.status, 201, await rr.text())
    seedAgent('child-d', 0)
    // is_root was ignored -> reg-root is is_root=0 -> cannot originate with no inbound.
    assert.equal((await post('/delegations', { parent_agent_id: 'reg-root', child_agent_id: 'child-d', scope: 'x', spend_limit: 5 })).status, 403)
  })

  it('[BACKFILL unit] promotes exactly the active grantors with no inbound delegation', () => {
    const tdb = new Database(':memory:')
    tdb.exec(`CREATE TABLE agents (id TEXT, tenant_id TEXT, agent_id TEXT, is_root INTEGER NOT NULL DEFAULT 0);
              CREATE TABLE delegations (tenant_id TEXT, parent_agent_id TEXT, child_agent_id TEXT, status TEXT)`)
    const ins = tdb.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES (?, 't', ?, 0)`)
    for (const a of ['trueRoot', 'mid', 'leaf', 'orphan']) ins.run('r' + a, a)
    const del = tdb.prepare(`INSERT INTO delegations (tenant_id, parent_agent_id, child_agent_id, status) VALUES ('t', ?, ?, 'active')`)
    del.run('trueRoot', 'mid')  // trueRoot grants (no inbound) -> a root
    del.run('mid', 'leaf')      // mid grants but HAS inbound -> not a root
    const promoted = backfillAgentRoots(tdb)
    const rootOf = (a: string) => (tdb.prepare(`SELECT is_root FROM agents WHERE agent_id = ?`).get(a) as any).is_root
    // B1 origin rule: is_root iff NEVER appeared as child_agent_id. trueRoot and orphan (never
    // children) are roots; mid/leaf (ever a child) are not. Superseded the prior active-edges rule.
    assert.equal(promoted, 2)
    assert.equal(rootOf('trueRoot'), 1)
    assert.equal(rootOf('mid'), 0)   // has inbound -> ever a child
    assert.equal(rootOf('leaf'), 0)  // only receives -> ever a child
    assert.equal(rootOf('orphan'), 1) // never a child -> origin root
    // idempotent: a second run promotes nobody
    assert.equal(backfillAgentRoots(tdb), 0)
    tdb.close()
  })

  it('[BACKFILL end-to-end] leaves an existing valid root working after promotion', async () => {
    // A legacy de-facto root: an active grantor with no inbound, but is_root=0 (pre-migration state).
    seedAgent('legacyRoot', 0); seedAgent('legChild', 0); seedAgent('newChild', 0)
    getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, max_depth, current_depth) VALUES (?, ?, 'legacyRoot', 'legChild', 'commerce:checkout', 'active', 3, 0)`).run('d-legacy', TENANT)
    // Before backfill: the gate correctly blocks the un-promoted legacy root.
    assert.equal((await post('/delegations', { parent_agent_id: 'legacyRoot', child_agent_id: 'newChild', scope: 'commerce:checkout', spend_limit: 5 })).status, 403)
    // Run the migration backfill on the live DB.
    const n = backfillAgentRoots(getDB())
    assert.ok(n >= 1)
    // After backfill: the existing valid root works again.
    assert.equal((await post('/delegations', { parent_agent_id: 'legacyRoot', child_agent_id: 'newChild', scope: 'commerce:checkout', spend_limit: 5 })).status, 201)
  })
})
