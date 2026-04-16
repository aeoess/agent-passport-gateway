// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for Build D2 — JWS signing of /api/v1/public/trust/:agentId.
//
// The gateway's public trust profile is now accompanied by an Ed25519
// compact JWS in the X-APS-JWS response header. The JSON body shape is
// unchanged. Verifiers fetch /.well-known/jwks.json for the signing key
// (kid: gateway-v1) and verify the JWS independently.
//
// These tests spin up a self-contained Express app that mounts the two
// endpoints under test, initializes a real gateway identity against an
// in-memory DB, and verifies the JWS cross-engine using the jose library
// resolving to the JWKS endpoint output.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { compactVerify, createLocalJWKSet, importJWK } from 'jose'
import { buildAgentTrustProfile, publicizeProfile } from '../src/gateway/trust-profile.js'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity, getGatewayIdentity, getJwks } from '../src/gateway/identity.js'

const TENANT_ID = 'tenant-jws-test'
const AGENT_ID = 'jws-test-agent'

function seedFixture() {
  const db = getDB()
  db.prepare(
    `INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`
  ).run(TENANT_ID, 'JWS Test Tenant', 'jws-test@example.com')
  db.prepare(
    `INSERT OR IGNORE INTO agents (id, tenant_id, agent_id, public_key, did, name, status)
     VALUES (?, ?, ?, ?, ?, ?, 'active')`
  ).run(
    'uuid-jws-test', TENANT_ID, AGENT_ID,
    '1ef065d8717910ffaba4416a134ad3ff93acc85e541450c461bd0c4a632befde',
    `did:aps:${AGENT_ID}`, 'JWS Test Agent',
  )
}

function stubContinuity() {
  return { score: 100, context_break: false, signals: [] }
}

// Mirror of server.ts's attachTrustProfileJws. Signs with the gateway
// identity's Ed25519 key and attaches the compact JWS + kid + JWKS url
// as response headers. Kept in sync with the server implementation.
function attachJws(res: express.Response, profile: Record<string, unknown>): void {
  const identity = getGatewayIdentity()
  res.setHeader('X-APS-JWS', identity.sign(profile))
  res.setHeader('X-APS-JWS-KID', identity.kid)
  res.setHeader('X-APS-JWS-JWKS', 'https://gateway.aeoess.com/.well-known/jwks.json')
}

function makeApp() {
  const app = express()
  app.get('/.well-known/jwks.json', (_req, res) => {
    res.json(getJwks())
  })
  app.get('/api/v1/public/trust/:agentId', (req, res) => {
    const db = getDB()
    const agent = db.prepare(
      `SELECT * FROM agents WHERE agent_id = ? AND status = 'active' LIMIT 1`
    ).get(req.params.agentId) as any
    if (!agent) {
      return res.json({
        agent_id: req.params.agentId,
        grade: 0,
        grade_label: 'unknown',
        found: false,
        queried_at: new Date().toISOString(),
      })
    }
    const profile = buildAgentTrustProfile({
      db, agent, agentId: req.params.agentId,
      computeContinuityScore: stubContinuity,
    })
    const publicProfile = publicizeProfile(profile)
    attachJws(res, publicProfile)
    return res.json(publicProfile)
  })
  return app
}

let server: Server
let baseUrl: string

before(async () => {
  initDB(':memory:')
  seedFixture()
  initGatewayIdentity()

  const app = makeApp()
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const addr = server.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      baseUrl = `http://127.0.0.1:${port}`
      resolve()
    })
  })
})

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('GET /api/v1/public/trust/:agentId — JWS signing (Build D2)', () => {
  it('attaches X-APS-JWS, X-APS-JWS-KID, X-APS-JWS-JWKS response headers', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${AGENT_ID}`)
    assert.equal(r.status, 200)
    const jws = r.headers.get('x-aps-jws')
    const kid = r.headers.get('x-aps-jws-kid')
    const jwksUrl = r.headers.get('x-aps-jws-jwks')
    assert.ok(jws, 'X-APS-JWS header must be set')
    assert.equal(jws!.split('.').length, 3, 'compact JWS has exactly 3 dot-separated parts')
    assert.equal(kid, 'gateway-v1')
    assert.equal(jwksUrl, 'https://gateway.aeoess.com/.well-known/jwks.json')
  })

  it('JWS header kid matches the kid published at /.well-known/jwks.json', async () => {
    const jwksResp = await fetch(`${baseUrl}/.well-known/jwks.json`)
    const jwks = await jwksResp.json() as any
    assert.ok(Array.isArray(jwks.keys) && jwks.keys.length === 1, 'JWKS has exactly one key')
    const publishedKid = jwks.keys[0].kid

    const r = await fetch(`${baseUrl}/api/v1/public/trust/${AGENT_ID}`)
    const jws = r.headers.get('x-aps-jws')!
    const header = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url').toString())
    assert.equal(header.kid, publishedKid, 'JWS header kid must match JWKS entry kid')
    assert.equal(header.alg, 'EdDSA')
  })

  it('body is unchanged JSON — does not contain signature fields', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${AGENT_ID}`)
    const body = await r.json() as any
    assert.equal(body.agent_id, AGENT_ID)
    assert.equal(body.found, true)
    // Body must not carry the signature inline — that's what X-APS-JWS is for.
    assert.equal(body.jws, undefined)
    assert.equal(body.signed, undefined)
    assert.equal(body.signature, undefined)
  })

  it('JWS payload integrity: jose.compactVerify using JWKS round-trips to the body profile', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${AGENT_ID}`)
    const body = await r.json() as any
    const jws = r.headers.get('x-aps-jws')!

    // Build the JWKS from the endpoint output and verify cross-engine via jose.
    const jwksResp = await fetch(`${baseUrl}/.well-known/jwks.json`)
    const jwks = await jwksResp.json() as any
    const getKey = createLocalJWKSet(jwks)

    const { payload, protectedHeader } = await compactVerify(jws, getKey)
    assert.equal(protectedHeader.alg, 'EdDSA')
    assert.equal(protectedHeader.kid, 'gateway-v1')

    const decoded = JSON.parse(Buffer.from(payload).toString('utf8'))
    // Core identity + grade fields must match the body exactly.
    assert.equal(decoded.agent_id, body.agent_id)
    assert.equal(decoded.grade, body.grade)
    assert.equal(decoded.grade_label, body.grade_label)
    assert.equal(decoded.found, body.found)
    assert.equal(decoded.queried_at, body.queried_at)
  })

  it('tampering with the payload causes verification to fail', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${AGENT_ID}`)
    const jws = r.headers.get('x-aps-jws')!

    const jwksResp = await fetch(`${baseUrl}/.well-known/jwks.json`)
    const jwks = await jwksResp.json() as any
    const getKey = createLocalJWKSet(jwks)

    // Flip a field in the payload segment of the compact JWS.
    const [h, p, s] = jws.split('.')
    const decoded = JSON.parse(Buffer.from(p, 'base64url').toString())
    decoded.grade = 999
    const tampered = [h, Buffer.from(JSON.stringify(decoded)).toString('base64url'), s].join('.')

    await assert.rejects(() => compactVerify(tampered, getKey))
  })

  it('direct JWK import path also verifies (no JWKS resolver)', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${AGENT_ID}`)
    const jws = r.headers.get('x-aps-jws')!
    const jwksResp = await fetch(`${baseUrl}/.well-known/jwks.json`)
    const jwks = await jwksResp.json() as any

    const key = await importJWK({ ...jwks.keys[0], alg: 'EdDSA' }, 'EdDSA')
    const { payload } = await compactVerify(jws, key as any)
    const decoded = JSON.parse(Buffer.from(payload).toString('utf8'))
    assert.equal(decoded.agent_id, AGENT_ID)
  })
})
