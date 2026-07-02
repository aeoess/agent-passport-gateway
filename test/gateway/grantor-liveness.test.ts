// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Consilium hostile panel B1/B2 Finding 1 (HIGH): the GRANTOR's own liveness.
// The grant gate keyed on is_root + inbound-delegation liveness but NEVER checked
// the granting agent's own agents.status. A REVOKED designated root (or a revoked/
// suspended agent with a live inbound) could still originate/narrow fresh money
// authority. /evaluate blocks non-active ACTING agents; the grant path must apply
// the same posture to the GRANTOR principal.
//   Panel F2 (MED): the authoritative inbound was picked by `created_at DESC LIMIT 1`
//   with 1s resolution and no secondary key -> nondeterministic which delegation
//   bounds/charges the child. Fixed with a deterministic `id DESC` tie-break.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_grantor'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

function seedAgent(id: string, isRoot = 0, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, ?)`).run(`row-${id}`, TENANT, id, status, isRoot)
}
function seedDelegation(id: string, parent: string, child: string, opts: { scope?: string; status?: string; spend?: number; createdAt?: string } = {}) {
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, max_depth, current_depth, spend_limit, created_at) VALUES (?, ?, ?, ?, ?, ?, 5, 1, ?, ?)`)
    .run(id, TENANT, parent, child, opts.scope ?? 'commerce:checkout', opts.status ?? 'active', opts.spend ?? 100, opts.createdAt ?? '2026-06-01T00:00:00.000Z')
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Grantor', 'gr@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('B1/B2 panel F1: grantor agent liveness in POST /delegations', () => {
  it('[ATTACK] a REVOKED designated root cannot originate fresh authority', async () => {
    seedAgent('revRoot', 1, 'revoked'); seedAgent('rc', 0)
    const r = await post('/delegations', { parent_agent_id: 'revRoot', child_agent_id: 'rc', scope: 'commerce:send', spend_limit: 5000 })
    assert.equal(r.status, 403, await r.text())
    assert.match((await (await post('/delegations', { parent_agent_id: 'revRoot', child_agent_id: 'rc', scope: 'x', spend_limit: 1 })).json() as any).error, /not active|revoked|suspended/i)
  })

  it('[ATTACK] a SUSPENDED designated root cannot originate', async () => {
    seedAgent('suspRoot', 1, 'suspended'); seedAgent('sc', 0)
    assert.equal((await post('/delegations', { parent_agent_id: 'suspRoot', child_agent_id: 'sc', scope: 'commerce:checkout', spend_limit: 10 })).status, 403)
  })

  it('[ATTACK] a REVOKED grantor with a live inbound cannot narrow/sub-delegate', async () => {
    seedAgent('liveRoot', 1); seedAgent('midRevoked', 0); seedAgent('leaf', 0)
    seedDelegation('d-mid', 'liveRoot', 'midRevoked', { scope: 'commerce:checkout', spend: 100 }) // mid has a LIVE inbound
    getDB().prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = 'midRevoked'`).run(TENANT)
    const r = await post('/delegations', { parent_agent_id: 'midRevoked', child_agent_id: 'leaf', scope: 'commerce:checkout', spend_limit: 20 })
    assert.equal(r.status, 403, await r.text())
  })

  it('an ACTIVE designated root still grants (control)', async () => {
    seedAgent('okRoot', 1); seedAgent('okc', 0)
    assert.equal((await post('/delegations', { parent_agent_id: 'okRoot', child_agent_id: 'okc', scope: 'commerce:checkout', spend_limit: 10 })).status, 201)
  })

  it('an unknown parent agent is 404 (fail closed, both branches)', async () => {
    seedAgent('lonelyChild', 0)
    assert.equal((await post('/delegations', { parent_agent_id: 'ghostP', child_agent_id: 'lonelyChild', scope: 'x', spend_limit: 1 })).status, 404)
  })
})

describe('B1/B2 panel F2: deterministic tie-break among same-instant inbounds', () => {
  it('the authoritative inbound is chosen by id DESC when created_at ties (deterministic, stable)', async () => {
    seedAgent('rootA', 1); seedAgent('rootB', 1); seedAgent('multi', 0); seedAgent('mleaf', 0)
    // Two active inbounds to `multi`, SAME created_at, different ids: 'zzz' (broad, big budget) vs 'aaa' (narrow).
    seedDelegation('zzz', 'rootA', 'multi', { scope: 'commerce:checkout,data:read', spend: 9999, createdAt: '2026-06-02T00:00:00.000Z' })
    seedDelegation('aaa', 'rootB', 'multi', { scope: 'data:read', spend: 5, createdAt: '2026-06-02T00:00:00.000Z' })
    // With `ORDER BY created_at DESC, id DESC`, the picked inbound is 'zzz' (broad). A commerce grant
    // within the broad budget must succeed (proving 'zzz' was picked, not the narrow 'aaa' which lacks
    // the commerce scope and the budget). Repeated calls are stable.
    seedAgent('mleafX', 0); seedAgent('mleafY', 0)
    assert.equal((await post('/delegations', { parent_agent_id: 'multi', child_agent_id: 'mleafX', scope: 'commerce:checkout', spend_limit: 50 })).status, 201)
    assert.equal((await post('/delegations', { parent_agent_id: 'multi', child_agent_id: 'mleafY', scope: 'commerce:checkout', spend_limit: 50 })).status, 201)
  })
})
