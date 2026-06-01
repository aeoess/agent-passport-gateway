// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D3 classification + destinations routers - integration tests
// ══════════════════════════════════════════════════════════════════
// Boots an in-memory DB + gateway identity and mounts the two routers
// behind a stub auth middleware that injects req.tenant. Proves the
// full path end to end:
//   - PUT /data-sources/:id/classification attaches a class FROM A LABEL
//     and persists class + confidence + verifier-derived grade on the
//     existing data_sources row (no parallel table)
//   - the recorded class drives POST /destinations/:id/check
//   - destination policy is enforced (permit / deny)
//   - the classification is signed with the EXISTING gateway identity
//   - a malformed (payload-like) body is rejected, so there is no
//     payload-scanning path into classification
// ══════════════════════════════════════════════════════════════════

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { dataClassificationRouter } from '../src/gateway/data-classification/router.js'
import { destinationsRouter } from '../src/gateway/destinations/router.js'

const TENANT_ID = 'tenant-d3-test'

function seedTenantAndSource() {
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`)
    .run(TENANT_ID, 'D3 Test Tenant', 'd3-test@example.com')
  db.prepare(
    `INSERT OR IGNORE INTO data_sources (id, tenant_id, source_id, source_name, data_terms)
     VALUES (?, ?, ?, ?, '{}')`,
  ).run('ds-uuid-1', TENANT_ID, 'src-001', 'Salesforce Contacts')
}

let server: Server
let baseUrl: string

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  seedTenantAndSource()

  const app = express()
  app.use(express.json())
  // Stub auth: inject the test tenant, mirroring authMiddleware's
  // req.tenant contract without the real key check.
  app.use((req: any, _res, next) => {
    req.tenant = { id: TENANT_ID, name: 'D3 Test Tenant', plan: 'enterprise' }
    next()
  })
  app.use('/api/v1', dataClassificationRouter)
  app.use('/api/v1', destinationsRouter)

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

async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  return { status: res.status, json: json as any }
}

describe('PUT /data-sources/:id/classification - label is honored, no scanning', () => {
  it('attaches class + confidence + verifier-derived grade from a connector label', async () => {
    const { status, json } = await api('PUT', '/api/v1/data-sources/src-001/classification', {
      connectorId: 'salesforce',
      sourceId: 'src-001',
      declaredClass: 'pii',
      confidence: 'declared',
      recordType: 'Contact',
      fieldRef: 'Contact.Email',
    })
    assert.equal(status, 200)
    assert.equal(json.data_class, 'pii')
    assert.equal(json.confidence, 'declared')
    assert.equal(typeof json.grade, 'number')
    // The class is a SIGNED, graded claim (JWS compact: header.payload.sig).
    assert.match(json.attestation, /^[\w-]+\.[\w-]+\.[\w-]+$/)
  })

  it('persists the class on the EXISTING data_sources row, not a parallel table', () => {
    const row = getDB()
      .prepare(`SELECT data_class, class_confidence, class_grade FROM data_sources WHERE tenant_id = ? AND source_id = ?`)
      .get(TENANT_ID, 'src-001') as any
    assert.equal(row.data_class, 'pii')
    assert.equal(row.class_confidence, 'declared')
    assert.equal(typeof row.class_grade, 'number')
  })

  it('rejects a malformed body (no payload-scanning fallback)', async () => {
    // A raw "payload" with no label shape must be rejected, not scanned.
    const { status } = await api('PUT', '/api/v1/data-sources/src-001/classification', {
      text: 'John Doe, SSN 123-45-6789, lives at...',
    })
    assert.equal(status, 400)
  })

  it('rejects a label whose sourceId disagrees with the path', async () => {
    const { status } = await api('PUT', '/api/v1/data-sources/src-001/classification', {
      connectorId: 'salesforce', sourceId: 'other', declaredClass: 'pii', confidence: 'declared',
    })
    assert.equal(status, 400)
  })

  it('404s for an unknown source', async () => {
    const { status } = await api('PUT', '/api/v1/data-sources/nope/classification', {
      connectorId: 'salesforce', sourceId: 'nope', declaredClass: 'pii', confidence: 'declared',
    })
    assert.equal(status, 404)
  })

  it('GET returns the recorded classification', async () => {
    const { status, json } = await api('GET', '/api/v1/data-sources/src-001/classification')
    assert.equal(status, 200)
    assert.equal(json.classified, true)
    assert.equal(json.data_class, 'pii')
    assert.equal(json.confidence, 'declared')
  })
})

describe('destinations + before-the-fact check uses the recorded class', () => {
  it('registers a destination policy', async () => {
    const { status, json } = await api('POST', '/api/v1/destinations', {
      destination_id: 'dst-warehouse',
      destination_name: 'External Warehouse',
      placement: 'external',
      allowed_data_classes: ['public', 'internal'],
      sink_confirmation_support: 'supported',
      risk_tier: 'medium',
    })
    assert.equal(status, 201)
    assert.equal(json.destination_id, 'dst-warehouse')
  })

  it('denies sending a pii-classified source to a destination that does not allow pii', async () => {
    const { status, json } = await api('POST', '/api/v1/destinations/dst-warehouse/check', {
      source_id: 'src-001',
    })
    assert.equal(status, 200)
    assert.equal(json.decision, 'deny')
    assert.equal(json.reason, 'class_not_allowed')
    assert.equal(json.source_class, 'pii')
    // Sink confirmation support is recorded on the verdict; the gateway
    // does not itself confirm.
    assert.equal(json.sink_confirmation_support, 'supported')
  })

  it('permits sending when the destination allows the class', async () => {
    await api('POST', '/api/v1/destinations', {
      destination_id: 'dst-internal',
      destination_name: 'Internal CRM',
      placement: 'internal',
      allowed_data_classes: ['pii', 'confidential'],
      sink_confirmation_support: 'attested',
      risk_tier: 'low',
    })
    const { status, json } = await api('POST', '/api/v1/destinations/dst-internal/check', {
      source_id: 'src-001',
    })
    assert.equal(status, 200)
    assert.equal(json.decision, 'permit')
    assert.equal(json.sink_confirmation_support, 'attested')
  })

  it('409s when checking with an unclassified source', async () => {
    getDB().prepare(
      `INSERT OR IGNORE INTO data_sources (id, tenant_id, source_id, source_name, data_terms)
       VALUES (?, ?, ?, ?, '{}')`,
    ).run('ds-uuid-2', TENANT_ID, 'src-unclassified', 'Raw Source')
    const { status } = await api('POST', '/api/v1/destinations/dst-internal/check', {
      source_id: 'src-unclassified',
    })
    assert.equal(status, 409)
  })

  it('accepts a directly-supplied source_class for sources not in this gateway', async () => {
    const { status, json } = await api('POST', '/api/v1/destinations/dst-internal/check', {
      source_class: 'public',
    })
    assert.equal(status, 200)
    assert.equal(json.decision, 'permit')
  })
})
