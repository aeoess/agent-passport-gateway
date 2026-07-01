// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Consilium hostile panel B6 Finding 1 (HIGH DoS, introduced by the B6 CHECK):
// the app overspend guard uses float `remaining = spend_limit - spend_used` and
// PERMITS a spend-to-exactly-the-limit, but the UPDATE `spend_used + estimated_cost`
// can land a hair ABOVE spend_limit by IEEE-754 rounding (2.14 + 5.07 =
// 7.210000000000001), tripping the exact `CHECK (spend_used <= spend_limit)` and
// aborting the transaction -> HTTP 500 on a LEGITIMATE spend. A spend_limit of 0
// (falsy) also fell through the guard and 500'd the same way.
// Fix: guard on `spend_limit != null` (so a 0 limit denies, not falls through) and
// give the ceiling CHECK a sub-cent tolerance so float noise can't abort a real spend.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_straddle'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
function seedAgent(id: string) { getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, 'pk', 'active')`).run(`row-${id}`, TENANT, id) }
function seedDelegation(id: string, child: string, spendLimit: number, spendUsed: number): string {
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used) VALUES (?, ?, 'root', ?, 'data:read', 'active', ?, ?)`).run(id, TENANT, child, spendLimit, spendUsed)
  return id
}
const spendUsedOf = (id: string) => (getDB().prepare(`SELECT spend_used FROM delegations WHERE id = ?`).get(id) as any).spend_used

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Straddle', 'st@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('B6 panel F1: float-straddle DoS on the billable path', () => {
  it('[DoS] a legitimate spend to EXACTLY the remaining budget commits (no 500)', async () => {
    seedAgent('sA'); const del = seedDelegation('d-sA', 'sA', 7.21, 2.14) // remaining 5.07
    const r = await post('/evaluate', { agent_id: 'sA', action_type: 'data:read', scope_required: 'data:read', estimated_cost: 5.07 })
    const body = await r.json() as any
    assert.notEqual(r.status, 500, `an at-limit spend must not 500: ${JSON.stringify(body)}`)
    assert.equal(body.verdict, 'permit', 'spending exactly the remaining budget is permitted')
    assert.ok(spendUsedOf(del) <= 7.21 + 0.005, 'spend_used lands within a sub-cent of the limit')
    assert.ok(spendUsedOf(del) >= 7.20, 'and the spend was actually recorded')
  })

  it('[DoS] a positive cost against a ZERO spend_limit denies (not 500), leaving spend_used at 0', async () => {
    seedAgent('sZ'); const del = seedDelegation('d-sZ', 'sZ', 0, 0)
    const r = await post('/evaluate', { agent_id: 'sZ', action_type: 'data:read', scope_required: 'data:read', estimated_cost: 1 })
    const body = await r.json() as any
    assert.notEqual(r.status, 500, `a zero-budget spend must deny cleanly, not 500: ${JSON.stringify(body)}`)
    assert.equal(body.verdict, 'deny', 'a zero budget denies any positive cost')
    assert.equal(spendUsedOf(del), 0, 'no spend recorded on a denied request')
  })

  it('a plain overspend still denies (control)', async () => {
    seedAgent('sO'); const del = seedDelegation('d-sO', 'sO', 10, 0)
    const body = await (await post('/evaluate', { agent_id: 'sO', action_type: 'data:read', scope_required: 'data:read', estimated_cost: 15 })).json() as any
    assert.equal(body.verdict, 'deny')
    assert.equal(spendUsedOf(del), 0)
  })
})
