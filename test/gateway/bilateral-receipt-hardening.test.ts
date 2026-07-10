// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Consilium hostile panel B3 findings. The bilateral route verified both sigs but
// did not defend against:
//   F1 (HIGH) replay: the same signed receipt stored N 'attested' rows (spend
//       inflation). Fix: UNIQUE(tenant_id, receipt_id) + pre-insert 409.
//   F3/F4 (MED/HIGH) self/one-key attestation: a single agent (or two ids sharing
//       one key) signs BOTH sides -> 'attested', defeating the two-party premise.
//       Fix: reject requestingAgentId===servingAgentId and reqKey===srvKey.
//   F5 (MED) revoked key attests: key lookup had no status filter, so a revoked
//       agent kept minting attestations. Fix: require status='active' for both.
//   F6 (LOW/MED) impossible timing: completedAt before requestedAt stored
//       'attested'. Fix: reject !timingValid.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { generateKeyPair, createBilateralReceipt } from 'agent-passport-system'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const GOLDEN = JSON.parse(readFileSync(join(__dir, 'fixtures', 'bilateral-receipt.golden.json'), 'utf8'))

const TENANT = 'tnt_blr_h'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
function reg(agentId: string, publicKey: string, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, ?, ?)`).run(`row-${agentId}`, TENANT, agentId, publicKey, status)
}
const goodOutcome = { toolName: 'commerce:checkout', requestHash: 'rq', responseHash: 'rs', status: 'success', summary: 'ok' }

before(async () => {
  process.env.BILATERAL_RECEIPTS_ENABLED = '1' // R3-0: route is OFF by default; enable it for these tests
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'BLRH', 'blrh@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('B3 panel hardening', () => {
  it('[ATTACK F1] replaying the same signed receipt is 409, not a second attested row', async () => {
    reg(GOLDEN.requestingAgentId, GOLDEN.requestingPublicKey)
    reg(GOLDEN.servingAgentId, GOLDEN.servingPublicKey)
    assert.equal((await post('/receipts/bilateral', { receipt: GOLDEN.receipt })).status, 201)
    const r2 = await post('/receipts/bilateral', { receipt: GOLDEN.receipt })
    assert.equal(r2.status, 409, await r2.text())
    const n = (getDB().prepare(`SELECT COUNT(*) c FROM bilateral_receipts WHERE receipt_id = ?`).get(GOLDEN.receipt.receiptId) as any).c
    assert.equal(n, 1, 'a replayed receipt must not create a second row')
  })

  it('[ATTACK F3] one agent signing BOTH sides (requester===server) is rejected', async () => {
    const k = generateKeyPair()
    reg('solo', k.publicKey)
    const receipt = createBilateralReceipt({ requestingAgentId: 'solo', servingAgentId: 'solo', outcome: goodOutcome, requestedAt: '2026-06-01T00:00:00.000Z', completedAt: '2026-06-01T00:00:01.000Z', requestingAgentPrivateKey: k.privateKey, servingAgentPrivateKey: k.privateKey })
    assert.equal((await post('/receipts/bilateral', { receipt })).status, 400, 'self-interaction is not a bilateral attestation')
  })

  it('[ATTACK F4] two distinct ids sharing ONE key is rejected (single-party masquerade)', async () => {
    const k = generateKeyPair()
    reg('ax', k.publicKey); reg('bx', k.publicKey)
    const receipt = createBilateralReceipt({ requestingAgentId: 'ax', servingAgentId: 'bx', outcome: goodOutcome, requestedAt: '2026-06-01T00:00:00.000Z', completedAt: '2026-06-01T00:00:01.000Z', requestingAgentPrivateKey: k.privateKey, servingAgentPrivateKey: k.privateKey })
    assert.equal((await post('/receipts/bilateral', { receipt })).status, 400, 'two agents cannot share one key for a bilateral attestation')
  })

  it('[ATTACK F5] a revoked agent key cannot attest', async () => {
    const rq = generateKeyPair(), sv = generateKeyPair()
    reg('rvq', rq.publicKey, 'revoked'); reg('rvs', sv.publicKey)
    const receipt = createBilateralReceipt({ requestingAgentId: 'rvq', servingAgentId: 'rvs', outcome: goodOutcome, requestedAt: '2026-06-01T00:00:00.000Z', completedAt: '2026-06-01T00:00:01.000Z', requestingAgentPrivateKey: rq.privateKey, servingAgentPrivateKey: sv.privateKey })
    assert.equal((await post('/receipts/bilateral', { receipt })).status, 403, 'a revoked agent must not mint attestations')
  })

  it('[ATTACK F6] a temporally-impossible receipt (completed before requested) is rejected', async () => {
    const rq = generateKeyPair(), sv = generateKeyPair()
    reg('tq', rq.publicKey); reg('ts', sv.publicKey)
    const receipt = createBilateralReceipt({ requestingAgentId: 'tq', servingAgentId: 'ts', outcome: goodOutcome, requestedAt: '2026-06-01T12:00:05.000Z', completedAt: '2026-06-01T12:00:00.000Z', requestingAgentPrivateKey: rq.privateKey, servingAgentPrivateKey: sv.privateKey })
    assert.equal((await post('/receipts/bilateral', { receipt })).status, 400, 'completed-before-requested is not a valid attested outcome')
  })

  it('a fresh, valid, distinct-party receipt still attests (control)', async () => {
    const rq = generateKeyPair(), sv = generateKeyPair()
    reg('cq', rq.publicKey); reg('cs', sv.publicKey)
    const receipt = createBilateralReceipt({ requestingAgentId: 'cq', servingAgentId: 'cs', outcome: goodOutcome, requestedAt: '2026-06-01T00:00:00.000Z', completedAt: '2026-06-01T00:00:01.000Z', requestingAgentPrivateKey: rq.privateKey, servingAgentPrivateKey: sv.privateKey, aud: { profile: 'aps:audience-binding:v1', recipients: [`aps-tenant:${TENANT}`] } })
    const r = await post('/receipts/bilateral', { receipt })
    const body = await r.json() as any
    assert.equal(r.status, 201, JSON.stringify(body))
    assert.equal(body.status, 'attested')
  })
})
