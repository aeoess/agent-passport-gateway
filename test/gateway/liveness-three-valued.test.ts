// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B2 (Consilium): three-valued liveness in the grant gate. A dead (revoked/
// expired) inbound must NOT read identically to an absent one. The prior code
// keyed only on status='active', so a DEAD inbound -> parentDel null -> fell to
// the is_root/root branch (composed exploit: revoke the inbound to reset budget
// and depth via the fresh-budget root path).
//   LIVE inbound   -> narrow
//   DEAD inbound   -> deny, distinct error (a severed delegatee is not a root)
//   ABSENT inbound -> may originate only if is_root=1
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_liveness'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

function seedAgent(id: string, isRoot = 0) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${id}`, TENANT, id, isRoot)
}
function seedDelegation(parent: string, child: string, status: string) {
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, max_depth, current_depth, spend_limit) VALUES (?, ?, ?, ?, 'commerce:checkout', ?, 3, ?, 100)`)
    .run(`d-${parent}-${child}-${status}`, TENANT, parent, child, status, status === 'active' ? 1 : 0)
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Liveness', 'lv@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('B2 three-valued liveness in the grant gate', () => {
  it('a parent with a REVOKED inbound is DEAD (distinct deny), not treated as an absent root', async () => {
    seedAgent('revParent', 0); seedAgent('rc', 0)
    seedDelegation('someRoot', 'revParent', 'revoked')  // revParent was delegated to, then revoked
    const r = await post('/delegations', { parent_agent_id: 'revParent', child_agent_id: 'rc', scope: 'commerce:checkout', spend_limit: 10 })
    assert.equal(r.status, 403)
    assert.match((await r.json() as any).error, /revoked or expired|severed|no longer active/i, 'must be the DEAD error, not the is_root error')
  })

  it('a parent with an EXPIRED inbound is DEAD, denied', async () => {
    seedAgent('expParent', 0); seedAgent('ec', 0)
    seedDelegation('someRoot', 'expParent', 'expired')
    const r = await post('/delegations', { parent_agent_id: 'expParent', child_agent_id: 'ec', scope: 'commerce:checkout', spend_limit: 10 })
    assert.equal(r.status, 403)
    assert.match((await r.json() as any).error, /revoked or expired|severed|no longer active/i)
  })

  it('an ABSENT-inbound non-root is denied with the is_root error (not the dead error)', async () => {
    seedAgent('absPlain', 0); seedAgent('ac', 0)
    const r = await post('/delegations', { parent_agent_id: 'absPlain', child_agent_id: 'ac', scope: 'x', spend_limit: 5 })
    assert.equal(r.status, 403)
    assert.match((await r.json() as any).error, /designated root/i)
  })

  it('an ABSENT-inbound designated root originates freely', async () => {
    seedAgent('absRoot', 1); seedAgent('arc', 0)
    const r = await post('/delegations', { parent_agent_id: 'absRoot', child_agent_id: 'arc', scope: 'commerce:checkout', spend_limit: 10 })
    assert.equal(r.status, 201, await r.text())
  })

  it('a LIVE inbound narrows normally (control)', async () => {
    seedAgent('liveRoot', 1); seedAgent('mid', 0); seedAgent('leaf', 0)
    assert.equal((await post('/delegations', { parent_agent_id: 'liveRoot', child_agent_id: 'mid', scope: 'commerce:checkout', spend_limit: 50 })).status, 201)
    // mid now has a LIVE inbound -> it may narrow, not originate
    const r = await post('/delegations', { parent_agent_id: 'mid', child_agent_id: 'leaf', scope: 'commerce:checkout', spend_limit: 20 })
    assert.equal(r.status, 201, await r.text())
  })

  it('a cyclic A->B->A cannot originate authority without an is_root anchor', async () => {
    // B was delegated to (revoked), so B is is_root=0 and B has an ever-inbound -> B cannot originate.
    seedAgent('cycA', 0); seedAgent('cycB', 0)
    seedDelegation('cycB', 'cycA', 'revoked')  // A was delegated to by B (revoked)
    seedDelegation('cycA', 'cycB', 'revoked')  // B was delegated to by A (revoked)
    // Neither is a root, both have (dead) inbound -> neither can originate a fresh delegation.
    assert.equal((await post('/delegations', { parent_agent_id: 'cycA', child_agent_id: 'cycB', scope: 'x', spend_limit: 5 })).status, 403)
    assert.equal((await post('/delegations', { parent_agent_id: 'cycB', child_agent_id: 'cycA', scope: 'x', spend_limit: 5 })).status, 403)
  })
})
