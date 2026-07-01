// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B3 (Consilium): bilateral receipt verification. The gateway's only receipt
// path (POST /receipt) verified a SINGLE signature against a SINGLE agent key.
// An APS interaction receipt is BILATERAL: a requesting agent and a serving
// agent BOTH sign the same canonical body. Storing such a receipt as "attested"
// requires BOTH signatures to verify against BOTH agents' REGISTERED keys, and
// both agents must belong to THIS tenant.
//
// Properties proven here:
//   * a golden receipt from the real SDK signer verifies and stores 'attested'
//   * a forged/mismatched counter-signature is rejected, never stored
//   * an agent not registered in this tenant is rejected (agent_id + tenant bound)
//   * a signature that does not match the REGISTERED key is rejected
//   * a legitimately one-sided receipt stores 'partial_attestation', not full
//   * a receipt with no valid signature is rejected
//
// The golden vector (test/gateway/fixtures/bilateral-receipt.golden.json) was
// produced by agent-passport-system createBilateralReceipt (real Ed25519 signer)
// and self-checked valid before commit. The gateway consumes verifyBilateralReceipt
// from the SDK; it does not reimplement the protocol primitive.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createBilateralReceipt } from 'agent-passport-system'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const GOLDEN = JSON.parse(readFileSync(join(__dir, 'fixtures', 'bilateral-receipt.golden.json'), 'utf8'))

const TENANT = 'tnt_blr'
const OTHER = 'tnt_blr_other'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

function registerAgent(tenant: string, agentId: string, publicKey: string) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, ?, 'active')`)
    .run(`row-${tenant}-${agentId}`, tenant, agentId, publicKey)
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  for (const t of [TENANT, OTHER]) getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(t, t, `${t}@test.local`)
  // Both counterparties registered in THIS tenant with their golden keys.
  registerAgent(TENANT, GOLDEN.requestingAgentId, GOLDEN.requestingPublicKey)
  registerAgent(TENANT, GOLDEN.servingAgentId, GOLDEN.servingPublicKey)
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

const countRows = () => (getDB().prepare(`SELECT COUNT(*) c FROM bilateral_receipts`).get() as any).c

describe('B3 bilateral receipt verification', () => {
  it('a golden bilateral receipt (real SDK signer) verifies BOTH sides and stores attested', async () => {
    const before = countRows()
    const r = await post('/receipts/bilateral', { receipt: GOLDEN.receipt })
    const body = await r.json() as any
    assert.equal(r.status, 201, JSON.stringify(body))
    assert.equal(body.status, 'attested', 'both signatures valid -> full bilateral attestation')
    assert.equal(body.requesting_signature_valid, true)
    assert.equal(body.serving_signature_valid, true)
    assert.equal(countRows(), before + 1, 'stored exactly one row')
  })

  it('[ATTACK] a forged serving countersignature is rejected and NOT stored', async () => {
    const before = countRows()
    const forged = { ...GOLDEN.receipt, servingAgentSignature: GOLDEN.receipt.requestingAgentSignature }
    const r = await post('/receipts/bilateral', { receipt: forged })
    assert.equal(r.status, 400, await r.text())
    assert.match((await (await post('/receipts/bilateral', { receipt: forged })).json() as any).error, /serving|signature|invalid/i)
    assert.equal(countRows(), before, 'a forged receipt must never be stored')
  })

  it('[ATTACK] a serving agent not registered in this tenant is rejected (agent_id + tenant bound)', async () => {
    // Register the serving agent ONLY in another tenant. This tenant does not know it.
    registerAgent(OTHER, 'cross-tenant-server', GOLDEN.servingPublicKey)
    const receipt = { ...GOLDEN.receipt, servingAgentId: 'cross-tenant-server' }
    const r = await post('/receipts/bilateral', { receipt })
    assert.equal(r.status, 404, await r.text())
    assert.match((await (await post('/receipts/bilateral', { receipt })).json() as any).error, /not registered|cross-tenant-server/i)
  })

  it('[ATTACK] a signature that does not match the REGISTERED key is rejected', async () => {
    // A tenant registers the serving agent under a DIFFERENT (attacker) key than the one that signed.
    registerAgent(TENANT, 'wrongkey-server', GOLDEN.requestingPublicKey) // wrong key on file
    const receipt = { ...GOLDEN.receipt, servingAgentId: 'wrongkey-server' }
    const r = await post('/receipts/bilateral', { receipt })
    assert.equal(r.status, 400, await r.text())
  })

  it('a legitimately one-sided receipt stores partial_attestation (not full)', async () => {
    // Freshly signed by the golden keys so it has a DISTINCT receiptId (the golden receiptId was
    // already stored by the first test; replay dedup would otherwise 409). Blank the serving sig.
    const fresh = createBilateralReceipt({
      requestingAgentId: GOLDEN.requestingAgentId, servingAgentId: GOLDEN.servingAgentId,
      outcome: { toolName: 't', requestHash: 'rq', responseHash: 'rs', status: 'success', summary: 'ok' },
      requestedAt: '2026-06-01T00:00:00.000Z', completedAt: '2026-06-01T00:00:01.000Z',
      requestingAgentPrivateKey: GOLDEN.requestingPrivateKey, servingAgentPrivateKey: GOLDEN.servingPrivateKey,
    })
    const oneSided = { ...fresh, servingAgentSignature: '' }
    const r = await post('/receipts/bilateral', { receipt: oneSided })
    const body = await r.json() as any
    assert.equal(r.status, 201, JSON.stringify(body))
    assert.equal(body.status, 'partial_attestation', 'one valid signature -> partial, never full attestation')
    assert.equal(body.requesting_signature_valid, true)
    assert.equal(body.serving_signature_valid, false)
  })

  it('[ATTACK] a receipt with no valid signature is rejected', async () => {
    const dead = { ...GOLDEN.receipt, requestingAgentSignature: '', servingAgentSignature: '' }
    const r = await post('/receipts/bilateral', { receipt: dead })
    assert.equal(r.status, 400, await r.text())
  })

  it('rejects a missing or malformed receipt body', async () => {
    assert.equal((await post('/receipts/bilateral', {})).status, 400)
    assert.equal((await post('/receipts/bilateral', { receipt: 'not-an-object' })).status, 400)
  })
})
