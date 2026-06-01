// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-D4 - tenant-isolation router + in-tenant deployment boot hook. Confirms:
//   - the router exposes the isolation switch, opt-in, trust-root, and
//     air-gap bundle endpoints under the standard authMiddleware pattern;
//   - lifecycle events are recorded in onboarding_events (hash-and-pointer);
//   - the boot hook applies the deployment isolation default (tighten-only):
//     ISOLATION_MODE=hard forces every tenant hard and clears opt-in.

import { describe, it, before, beforeEach, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import {
  tenantIsolationRouter,
  applyDeploymentIsolationDefault,
  readDeploymentConfig,
  setIsolationMode,
  setCohortOptIn,
  getTenantIsolationState,
} from '../../src/gateway/tenant-isolation/index.js'

const TENANT = 'router-tenant'

// Mount the router behind a stub auth that injects req.tenant, mirroring the
// real authMiddleware -> app.use('/api/v1', authMiddleware, router) wiring.
function makeApp() {
  const app = express()
  app.use(express.json())
  app.use('/api/v1', (req: any, _res, next) => {
    req.tenant = { id: TENANT, name: 'Router Tenant', email: 'router@example.com' }
    next()
  }, tenantIsolationRouter)
  return app
}

let server: Server
let baseUrl: string

before(async () => {
  initDB(':memory:')
  // The air-gap bundle route reads the gateway JWKS; the real server inits
  // identity before mounting routers, so mirror that here.
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`)
    .run(TENANT, 'Router Tenant', 'router@example.com')
  await new Promise<void>((resolve) => {
    server = makeApp().listen(0, () => {
      const addr = server.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      baseUrl = `http://127.0.0.1:${port}`
      resolve()
    })
  })
})

after(() => {
  server?.close()
})

describe('tenant-isolation router', () => {
  beforeEach(() => {
    // Reset the tenant to the default hard, not opted in.
    getDB().prepare(
      `UPDATE tenants SET isolation_mode='hard', cohort_opt_in=0, trust_root_source='gateway', trust_root_key_ref=NULL WHERE id=?`,
    ).run(TENANT)
    getDB().prepare(`DELETE FROM onboarding_events`).run()
  })

  it('GET /state returns the isolation state', async () => {
    const res = await fetch(`${baseUrl}/api/v1/tenant-isolation/state`)
    assert.equal(res.status, 200)
    const body = await res.json() as any
    assert.equal(body.isolationMode, 'hard')
    assert.equal(body.cohortOptIn, false)
  })

  it('POST /mode standard records an onboarding event and emits', async () => {
    const res = await fetch(`${baseUrl}/api/v1/tenant-isolation/mode`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mode: 'standard' }),
    })
    assert.equal(res.status, 200)
    const body = await res.json() as any
    assert.equal(body.changed, true)
    assert.equal(body.to, 'standard')
    const events = getDB().prepare(
      `SELECT * FROM onboarding_events WHERE tenant_id=? AND event_type='tenant_isolation_set'`,
    ).all(TENANT) as any[]
    assert.equal(events.length, 1)
    assert.equal(events[0].detail_pointer, 'hard->standard')
  })

  it('POST /mode rejects an invalid mode', async () => {
    const res = await fetch(`${baseUrl}/api/v1/tenant-isolation/mode`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mode: 'banana' }),
    })
    assert.equal(res.status, 400)
  })

  it('POST /cohort-opt-in is refused (409) while hard isolated', async () => {
    const res = await fetch(`${baseUrl}/api/v1/tenant-isolation/cohort-opt-in`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ opt_in: true }),
    })
    assert.equal(res.status, 409)
  })

  it('POST /trust-root binds a customer KMS reference, stores fingerprint not key', async () => {
    const res = await fetch(`${baseUrl}/api/v1/tenant-isolation/trust-root`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        source: 'kms',
        key_ref: 'arn:aws:kms:us-east-1:111122223333:key/abcd',
        anchor_material: 'customer-anchor-public',
      }),
    })
    assert.equal(res.status, 200)
    const body = await res.json() as any
    assert.match(body.anchor_fingerprint, /^[0-9a-f]{64}$/)
    const row = getDB().prepare(`SELECT trust_root_source, trust_root_key_ref FROM tenants WHERE id=?`)
      .get(TENANT) as any
    assert.equal(row.trust_root_source, 'kms')
    assert.equal(row.trust_root_key_ref, 'arn:aws:kms:us-east-1:111122223333:key/abcd')
  })

  it('POST /trust-root refuses a body that smells like raw key material / PHI', async () => {
    const res = await fetch(`${baseUrl}/api/v1/tenant-isolation/trust-root`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ source: 'hsm', key_ref: 'ref', phi: 'leak' }),
    })
    assert.equal(res.status, 400)
  })

  it('GET /airgap-bundle returns an attachment bundle', async () => {
    const res = await fetch(
      `${baseUrl}/api/v1/tenant-isolation/airgap-bundle?from=2026-05-01T00:00:00Z&to=2026-06-01T00:00:00Z`,
    )
    assert.equal(res.status, 200)
    assert.match(res.headers.get('content-disposition') || '', /attachment/)
    const body = await res.json() as any
    assert.equal(body.offline_verifiable, true)
    assert.equal(body.tenant_id, TENANT)
  })
})

describe('in-tenant deployment boot hook - tighten-only', () => {
  beforeEach(() => {
    // Clear FK-dependent rows before tenants so the delete is not blocked.
    getDB().prepare(`DELETE FROM onboarding_events`).run()
    getDB().prepare(`DELETE FROM tenants`).run()
  })

  it('readDeploymentConfig defaults to hard / gateway', () => {
    const cfg = readDeploymentConfig({})
    assert.equal(cfg.isolationMode, 'hard')
    assert.equal(cfg.trustRootSource, 'gateway')
    assert.equal(cfg.airGapped, false)
  })

  it('ISOLATION_MODE=hard forces every tenant hard and clears opt-in', () => {
    getDB().prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`)
      .run('boot-1', 'boot-1', 'b1@example.com')
    setIsolationMode('boot-1', 'standard')
    setCohortOptIn('boot-1', true)
    assert.equal(getTenantIsolationState('boot-1')!.cohortOptIn, true)

    const summary = applyDeploymentIsolationDefault({
      isolationMode: 'hard',
      trustRootSource: 'gateway',
      trustRootKeyRef: null,
      airGapped: false,
    })
    assert.ok(summary.tenantsForcedHard >= 1)
    const state = getTenantIsolationState('boot-1')!
    assert.equal(state.isolationMode, 'hard')
    assert.equal(state.cohortOptIn, false)
  })

  it('AIR_GAPPED config marks tenants air-gapped', () => {
    getDB().prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`)
      .run('boot-air', 'boot-air', 'bair@example.com')
    applyDeploymentIsolationDefault({
      isolationMode: 'hard',
      trustRootSource: 'hsm',
      trustRootKeyRef: 'pkcs11:slot=0',
      airGapped: true,
    })
    const state = getTenantIsolationState('boot-air')!
    assert.equal(state.airGapped, true)
    assert.equal(state.trustRootSource, 'hsm')
  })

  it('standard ISOLATION_MODE does NOT loosen existing hard tenants', () => {
    getDB().prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`)
      .run('boot-keep', 'boot-keep', 'bk@example.com') // defaults hard
    applyDeploymentIsolationDefault({
      isolationMode: 'standard',
      trustRootSource: 'gateway',
      trustRootKeyRef: null,
      airGapped: false,
    })
    // Tighten-only: a 'standard' deployment default must not auto-loosen a
    // tenant that is currently hard. It stays hard until explicit opt-in.
    assert.equal(getTenantIsolationState('boot-keep')!.isolationMode, 'hard')
  })
})
