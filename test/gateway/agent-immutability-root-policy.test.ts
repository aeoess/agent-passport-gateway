// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B8 + POLICY (Consilium): agent immutability and audited root designation.
//   B8:     POST /agents on a duplicate agent_id is 409 (no upsert); public_key
//           cannot be swapped by re-registration (authority rebinding).
//   Policy: is_root is NEVER self-service. A client-supplied is_root at POST
//           /agents is ignored. Root designation is admin-only + audited.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_immut'
let server: Server, baseUrl: string
let role = 'user'
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Immut', 'im@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role, plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('B8 agent immutability', () => {
  it('a duplicate agent_id is 409, not an upsert', async () => {
    assert.equal((await post('/agents', { agent_id: 'dup', public_key: 'pk-1' })).status, 201)
    const r = await post('/agents', { agent_id: 'dup', public_key: 'pk-1' })
    assert.equal(r.status, 409)
  })

  it('public_key cannot be swapped by re-registering the same agent_id', async () => {
    assert.equal((await post('/agents', { agent_id: 'keyed', public_key: 'pk-original' })).status, 201)
    const r = await post('/agents', { agent_id: 'keyed', public_key: 'pk-ATTACKER' })
    assert.equal(r.status, 409, 'must reject; authority is bound to the original key')
    const stored = getDB().prepare(`SELECT public_key FROM agents WHERE tenant_id = ? AND agent_id = 'keyed'`).get(TENANT) as any
    assert.equal(stored.public_key, 'pk-original', 'public_key unchanged')
  })
})

describe('POLICY: root designation is not self-service', () => {
  it('a client-supplied is_root at POST /agents is IGNORED (agent is is_root=0)', async () => {
    assert.equal((await post('/agents', { agent_id: 'sneaky-root', public_key: 'pk', is_root: true })).status, 201)
    const row = getDB().prepare(`SELECT is_root FROM agents WHERE tenant_id = ? AND agent_id = 'sneaky-root'`).get(TENANT) as any
    assert.equal(row.is_root, 0, 'client is_root must be ignored')
  })

  it('a NON-admin cannot designate a root', async () => {
    role = 'user'
    await post('/agents', { agent_id: 'want-root', public_key: 'pk' })
    const r = await post('/root-designations', { agent_id: 'want-root' })
    assert.equal(r.status, 403)
  })

  it('an ADMIN designates a root, atomically writing an audit row', async () => {
    role = 'admin'
    await post('/agents', { agent_id: 'admin-root', public_key: 'pk' })
    const r = await post('/root-designations', { agent_id: 'admin-root' })
    assert.equal(r.status, 200, await r.text())
    const agent = getDB().prepare(`SELECT is_root FROM agents WHERE tenant_id = ? AND agent_id = 'admin-root'`).get(TENANT) as any
    assert.equal(agent.is_root, 1, 'agent promoted')
    const audit = getDB().prepare(`SELECT * FROM root_designations WHERE tenant_id = ? AND agent_id = 'admin-root'`).get(TENANT) as any
    assert.ok(audit, 'audit row written')
    assert.equal(audit.designated_by, TENANT)
    assert.ok(audit.designated_at, 'timestamp recorded')
    role = 'user'
  })

  it('designating an unknown agent is 404', async () => {
    role = 'admin'
    const r = await post('/root-designations', { agent_id: 'ghost' })
    assert.equal(r.status, 404)
    role = 'user'
  })
})
