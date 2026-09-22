// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// C1 reproduction (Day 217): ancestor revocation must end descendant authority.
// Candidate finding from code reading at 96eb421: POST /revoke on a delegation
// updates only that row, /evaluate reads only the acting agent's newest active
// inbound row, and the grant path rechecks only the immediate inbound row.
// These tests assert the CORRECT behavior. On 96eb421 they are expected to fail;
// that failure is the reproduction. No fix in this file.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_c1repro'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

function seedAgent(id: string, isRoot = 0) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${id}`, TENANT, id, isRoot)
}
async function grant(parent: string, child: string, spend: number) {
  const r = await post('/delegations', { parent_agent_id: parent, child_agent_id: child, scope: 'data:read', spend_limit: spend })
  assert.equal(r.status, 201, `setup grant ${parent}->${child}: ${await r.text()}`)
}
function delegationId(parent: string, child: string): string {
  const row = getDB().prepare(`SELECT id FROM delegations WHERE tenant_id = ? AND parent_agent_id = ? AND child_agent_id = ?`).get(TENANT, parent, child) as any
  assert.ok(row, `no row ${parent}->${child}`)
  return row.id
}
async function verdict(agent: string): Promise<string> {
  const body = await (await post('/evaluate', { agent_id: agent, action_type: 'data:read', scope_required: 'data:read', estimated_cost: 1 })).json() as any
  return body.verdict
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'C1Repro', 'c1@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('C1 repro: revoking A->B in A->B->C->D', () => {
  it('controls before revocation, then C and D lose authority and C cannot grant', async () => {
    seedAgent('A', 1); seedAgent('B'); seedAgent('C'); seedAgent('D'); seedAgent('E')
    await grant('A', 'B', 100); await grant('B', 'C', 50); await grant('C', 'D', 20)
    assert.equal(await verdict('C'), 'permit', 'control: C permitted before revocation')
    assert.equal(await verdict('D'), 'permit', 'control: D permitted before revocation')

    const rv = await post('/revoke', { target_type: 'delegation', target_id: delegationId('A', 'B'), revoked_by: 'A' })
    assert.equal(rv.status, 200, await rv.text())

    const observed = {
      B: await verdict('B'),
      C: await verdict('C'),
      D: await verdict('D'),
      grantCtoE: (await post('/delegations', { parent_agent_id: 'C', child_agent_id: 'E', scope: 'data:read', spend_limit: 5 })).status,
    }
    assert.deepEqual(observed, { B: 'deny', C: 'deny', D: 'deny', grantCtoE: 403 }, 'after revoking A->B, everything below it must lose authority')
  })
})

describe('C1 repro: revoking agent B2 in A2->B2->C2->D2', () => {
  it('D2 loses authority two hops below the revoked agent', async () => {
    seedAgent('A2', 1); seedAgent('B2'); seedAgent('C2'); seedAgent('D2')
    await grant('A2', 'B2', 100); await grant('B2', 'C2', 50); await grant('C2', 'D2', 20)
    assert.equal(await verdict('D2'), 'permit', 'control: D2 permitted before revocation')
    const rv = await post('/revoke', { target_type: 'agent', target_id: 'B2', revoked_by: 'A2' })
    assert.equal(rv.status, 200, await rv.text())
    assert.equal(await verdict('C2'), 'deny', 'C2 denied, its inbound row B2->C2 was revoked by the one-hop update')
    assert.equal(await verdict('D2'), 'deny', 'D2 must be denied: its chain passes through revoked agent B2')
  })
})
