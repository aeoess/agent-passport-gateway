// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R3-0 (round-2 Consilium): POST /receipts/bilateral is OFF by default. The signed
// BilateralReceipt body has no audience/tenant field, so a valid receipt from
// tenant A replays into tenant B (cross-tenant F2). The route stays dark (404)
// until BILATERAL_RECEIPTS_ENABLED=1, which should only be set once the SDK binds
// an audience inside the signed body and an independent RFC 8785 vector exists.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const T = 'tnt_flag'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

before(async () => {
  delete process.env.BILATERAL_RECEIPTS_ENABLED // default state: OFF
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T, 'Flag', 'fl@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: T, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => { server?.close(); delete process.env.BILATERAL_RECEIPTS_ENABLED })

describe('R3-0 bilateral endpoint feature flag', () => {
  it('[default OFF] the route returns 404 when the flag is unset', async () => {
    delete process.env.BILATERAL_RECEIPTS_ENABLED
    const r = await post('/receipts/bilateral', { receipt: { requestingAgentId: 'a', servingAgentId: 'b', receiptId: 'x' } })
    assert.equal(r.status, 404, await r.text())
    assert.match((await (await post('/receipts/bilateral', { receipt: {} })).json() as any).error, /not enabled/i)
  })

  it('flag set: the route is reachable and validates input (400 on a malformed receipt, not 404)', async () => {
    process.env.BILATERAL_RECEIPTS_ENABLED = '1'
    const r = await post('/receipts/bilateral', { receipt: 'not-an-object' })
    assert.equal(r.status, 400, 'enabled route validates the body rather than 404ing')
    delete process.env.BILATERAL_RECEIPTS_ENABLED
  })
})
