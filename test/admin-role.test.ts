// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Security triage 2026-04-11 fix 1: admin authorization must be keyed on
// tenant.role, not tenant.plan. This test confirms that the plan field is
// no longer sufficient to access admin routes: a tenant with plan=enterprise
// but role=user must receive 403, and only a tenant with role=admin passes.
// Reference: CODE-AUDIT-2026-04-11.md §2.9.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { requireAdmin } from '../src/auth/api-keys.js'
import type { Tenant } from '../src/auth/api-keys.js'

// Minimal Express-style stub for middleware testing. The real Express
// req/res objects are not needed to exercise requireAdmin since the
// middleware only reads req.tenant and writes status/json on failure.
function makeRes() {
  const captured: { status: number; body: any } = { status: 200, body: null }
  return {
    captured,
    status(code: number) { captured.status = code; return this },
    json(body: any) { captured.body = body; return this },
  }
}

function tenantWith(role: 'admin' | 'user', plan: 'free' | 'pro' | 'enterprise'): Tenant {
  return {
    id: 'test-tenant-id',
    name: 'Test Tenant',
    email: 'test@example.com',
    plan,
    stripe_customer_id: null,
    status: 'active',
    role,
  }
}

describe('requireAdmin middleware — fix 1 of security triage 2026-04-11', () => {
  it('rejects a tenant with plan=enterprise but role=user (the regression guard)', () => {
    // This is THE case the audit flagged: prior implementation gated
    // admin routes on plan === 'enterprise'. Any enterprise-plan customer
    // would have inherited platform-operator capabilities. Confirm the
    // plan field is no longer sufficient.
    const req: any = { tenant: tenantWith('user', 'enterprise') }
    const res = makeRes()
    let nextCalled = false
    requireAdmin(req, res as any, () => { nextCalled = true })
    assert.equal(nextCalled, false, 'next() must not be called for non-admin tenant')
    assert.equal(res.captured.status, 403)
    assert.match(res.captured.body.error, /Admin role required/i)
  })

  it('rejects a tenant with role=user on a free plan', () => {
    const req: any = { tenant: tenantWith('user', 'free') }
    const res = makeRes()
    let nextCalled = false
    requireAdmin(req, res as any, () => { nextCalled = true })
    assert.equal(nextCalled, false)
    assert.equal(res.captured.status, 403)
  })

  it('rejects a tenant with role=user on a pro plan', () => {
    const req: any = { tenant: tenantWith('user', 'pro') }
    const res = makeRes()
    let nextCalled = false
    requireAdmin(req, res as any, () => { nextCalled = true })
    assert.equal(nextCalled, false)
    assert.equal(res.captured.status, 403)
  })

  it('accepts a tenant with role=admin regardless of plan', () => {
    const plans: Array<'free' | 'pro' | 'enterprise'> = ['free', 'pro', 'enterprise']
    for (const plan of plans) {
      const req: any = { tenant: tenantWith('admin', plan) }
      const res = makeRes()
      let nextCalled = false
      requireAdmin(req, res as any, () => { nextCalled = true })
      assert.equal(nextCalled, true, `next() must be called for role=admin on plan=${plan}`)
      assert.equal(res.captured.status, 200, `no error status set for role=admin on plan=${plan}`)
    }
  })

  it('returns 401 when req.tenant is missing (defensive — should not happen if chained after authMiddleware)', () => {
    const req: any = {}
    const res = makeRes()
    let nextCalled = false
    requireAdmin(req, res as any, () => { nextCalled = true })
    assert.equal(nextCalled, false)
    assert.equal(res.captured.status, 401)
  })
})
