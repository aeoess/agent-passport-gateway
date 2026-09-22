// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B6 (Consilium) end-to-end: prove the negative-cost REFUND on the wire, not
// just in a unit. A negative estimated_cost at POST /evaluate must DENY and must
// NOT move spend_used (a refund). This file imports only the router + db, so it
// runs UNCHANGED against the pre-fix commit (e3672c0^), where it FAILS: the old
// code permits the request and adds the negative to spend_used, refunding the
// budget. On current code it PASSES. That fail->pass delta is the evidence the
// Consilium asked for.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_negcost'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

// Seed WITHOUT is_root so the row shape is valid on the pre-fix schema too (portability).
function seedAgent(id: string) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, 'pk', 'active')`).run(`row-${id}`, TENANT, id)
}
// A live delegation the agent can spend against: spend_limit 100, already spent 50 -> 50 remaining.
// Only columns present at BOTH the pre-fix commit and current are used (max_depth/current_depth
// were introduced by the fix commit e3672c0 itself, and the /evaluate cost path never reads them).
// C1 (Day 217): parent_agent_id='root' with no parent_delegation_id is an origination row;
// checkBoundAuthorityChain requires the terminal grantor to exist, so 'root' is seeded in before().
function seedDelegation(child: string, spendUsed = 50): string {
  const id = `d-${child}`
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used) VALUES (?, ?, 'root', ?, 'data:read', 'active', 100, ?)`)
    .run(id, TENANT, child, spendUsed)
  return id
}
const spendUsedOf = (id: string) => (getDB().prepare(`SELECT spend_used FROM delegations WHERE id = ?`).get(id) as any).spend_used

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'NegCost', 'nc@test.local')
  seedAgent('root')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('B6 e2e: a negative estimated_cost cannot refund the budget', () => {
  it('[BUG REPRO] a negative cost DENIES and leaves spend_used untouched (no refund)', async () => {
    seedAgent('neg'); const del = seedDelegation('neg', 50)
    const r = await post('/evaluate', { agent_id: 'neg', action_type: 'data:read', scope_required: 'data:read', estimated_cost: -1000 })
    const body = await r.json() as any
    assert.equal(body.verdict, 'deny', `negative cost must deny, got ${JSON.stringify(body)}`)
    assert.equal(spendUsedOf(del), 50, 'spend_used MUST be unchanged; a negative cost must never refund the budget')
  })

  it('a coercing string cost ("-5") also denies and does not move spend_used', async () => {
    seedAgent('str'); const del = seedDelegation('str', 50)
    const r = await post('/evaluate', { agent_id: 'str', action_type: 'data:read', scope_required: 'data:read', estimated_cost: '-5' })
    const body = await r.json() as any
    assert.equal(body.verdict, 'deny', `string cost must deny, got ${JSON.stringify(body)}`)
    assert.equal(spendUsedOf(del), 50, 'spend_used unchanged for a non-numeric cost')
  })

  it('a valid positive within-budget cost permits and ADDS to spend_used (path is live, control)', async () => {
    seedAgent('pos'); const del = seedDelegation('pos', 50)
    const r = await post('/evaluate', { agent_id: 'pos', action_type: 'data:read', scope_required: 'data:read', estimated_cost: 10 })
    const body = await r.json() as any
    assert.equal(body.verdict, 'permit', `a $10 cost within a $50 remaining budget must permit, got ${JSON.stringify(body)}`)
    assert.equal(spendUsedOf(del), 60, 'a real positive cost increases spend_used')
  })
})
