// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R3-5 (round-2 Consilium): delegations and agents are APPEND-ONLY. The B1 origin
// rule (is_root iff the agent has NEVER been a child_agent_id under ANY status)
// depends on revoked/expired rows PERSISTING: a hard DELETE of a delegation would
// erase the history that proves an agent was once a delegatee, silently re-rooting
// it. /revoke must be a status UPDATE, never a DELETE. This guards that invariant.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const T = 'tnt_append'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
function seedAgent(id: string) { getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, 'pk', 'active')`).run(`row-${id}`, T, id) }
function seedDelegation(id: string, parent: string, child: string) {
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit) VALUES (?, ?, ?, ?, 'commerce:checkout', 'active', 100)`).run(id, T, parent, child)
}
const rows = (sql: string, ...a: unknown[]) => getDB().prepare(sql).all(...a) as any[]

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T, 'Append', 'ap@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: T, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('R3-5 append-only: /revoke is a status update, rows persist', () => {
  it('revoking an agent flips status but PRESERVES the agent and delegation rows (history intact)', async () => {
    seedAgent('root'); seedAgent('mid')
    seedDelegation('d-1', 'root', 'mid') // mid was delegated to -> it is forever a child
    const r = await post('/revoke', { target_type: 'agent', target_id: 'mid' })
    assert.equal(r.status, 200, await r.text())

    const agentRows = rows(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = 'mid'`, T)
    assert.equal(agentRows.length, 1, 'the agent row must still exist (not deleted)')
    assert.equal(agentRows[0].status, 'revoked', 'status flipped to revoked')

    const delRows = rows(`SELECT status FROM delegations WHERE tenant_id = ? AND id = 'd-1'`, T)
    assert.equal(delRows.length, 1, 'the delegation row must still exist (not deleted)')
    assert.equal(delRows[0].status, 'revoked', 'delegation flipped to revoked')

    // The B1 history dependency: mid still appears as a child_agent_id under a (now revoked) row,
    // so it can never be silently re-rooted by the origin backfill.
    const everChild = rows(`SELECT 1 FROM delegations WHERE tenant_id = ? AND child_agent_id = 'mid'`, T)
    assert.equal(everChild.length, 1, 'the ever-a-child history survives revocation')
  })

  it('revoking a specific delegation preserves its row', async () => {
    seedAgent('p2'); seedAgent('c2'); seedDelegation('d-2', 'p2', 'c2')
    await post('/revoke', { target_type: 'delegation', target_id: 'd-2' })
    const delRows = rows(`SELECT status FROM delegations WHERE tenant_id = ? AND id = 'd-2'`, T)
    assert.equal(delRows.length, 1)
    assert.equal(delRows[0].status, 'revoked')
  })
})
