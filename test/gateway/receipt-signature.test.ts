// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Audit item 6 (HIGH, money/audit): POST /api/v1/receipt must verify the
// receipt signature against the signer's registered public key BEFORE storing.
// Previously it stored any receipt unverified, so a forged or tampered receipt
// under any agent_id would be accepted into the audit trail.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_receipt_sig'
const AGENT = 'agent-signer'
const kp = generateKeyPair()

let server: Server
let baseUrl: string

function post(path: string, body: unknown) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function signedReceipt(over: Record<string, unknown> = {}) {
  const receipt = {
    receiptId: 'rcpt_' + Math.random().toString(36).slice(2, 10),
    version: '1.1',
    agentId: AGENT,
    action: { type: 'payment', target: 'vendor', scopeUsed: 'payment:charge', spend: { amount: 42, currency: 'USD' } },
    result: { status: 'success', summary: 'ok' },
    delegationChain: [kp.publicKey],
    ...over,
  }
  const signature = sign(canonicalize(receipt), kp.privateKey)
  return { receipt, signature }
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'ReceiptSig Test', 'rs@test.local')
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, ?, 'active')`)
    .run('row-' + AGENT, TENANT, AGENT, kp.publicKey)

  const app = express()
  app.use(express.json({ limit: '2mb' }))
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'free' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const a = server.address()
      baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`
      resolve()
    })
  })
})

after(() => { server?.close() })

describe('POST /api/v1/receipt signature verification (audit item 6)', () => {
  it('stores a validly signed receipt', async () => {
    const { receipt, signature } = signedReceipt()
    const r = await post('/receipt', { agent_id: AGENT, signature, payload: receipt })
    const body = await r.json() as any
    assert.equal(r.status, 201, JSON.stringify(body))
    assert.equal(body.stored, true)
  })

  it('rejects a tampered body (payload mutated after signing)', async () => {
    const { receipt, signature } = signedReceipt()
    const tampered = { ...receipt, action: { ...receipt.action, spend: { amount: 999999, currency: 'USD' } } }
    const r = await post('/receipt', { agent_id: AGENT, signature, payload: tampered })
    assert.equal(r.status, 400)
    assert.match((await r.json() as any).error, /verification failed/i)
  })

  it('rejects a bad signature', async () => {
    const { receipt } = signedReceipt()
    const r = await post('/receipt', { agent_id: AGENT, signature: 'deadbeef'.repeat(16), payload: receipt })
    assert.equal(r.status, 400)
  })

  it('rejects a missing signature (fail closed)', async () => {
    const { receipt } = signedReceipt()
    const r = await post('/receipt', { agent_id: AGENT, payload: receipt })
    assert.equal(r.status, 400)
  })

  it('rejects a receipt for an unregistered agent (fail closed, cannot verify)', async () => {
    const { receipt, signature } = signedReceipt({ agentId: 'ghost' })
    const r = await post('/receipt', { agent_id: 'ghost', signature, payload: receipt })
    assert.equal(r.status, 404)
  })

  it('rejects a receipt signed by a different key than the agent registered', async () => {
    const other = generateKeyPair()
    const receipt = {
      receiptId: 'rcpt_x', version: '1.1', agentId: AGENT,
      action: { type: 'payment', target: 'v', scopeUsed: 'payment:charge', spend: { amount: 1, currency: 'USD' } },
      result: { status: 'success', summary: 'ok' }, delegationChain: [AGENT],
    }
    const signature = sign(canonicalize(receipt), other.privateKey)
    const r = await post('/receipt', { agent_id: AGENT, signature, payload: receipt })
    assert.equal(r.status, 400)
  })
})
