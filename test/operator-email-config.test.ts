// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for the GATEWAY_OPERATOR_EMAIL / GATEWAY_OPERATOR_EMAIL_ALIASES
// migrations in src/db/schema.ts (role elevation + identity reconcile).
//   - unset: no tenant is elevated or renamed by email
//   - set: the configured email is reconciled onto the admin tenant
//   - aliases set: alias emails resolve to the same admin tenant

import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { initDB, getDB, resolveTenantByEmail } from '../src/db/schema.js'
import { createTenant } from '../src/auth/api-keys.js'

let dbPath: string
const savedEmail = process.env.GATEWAY_OPERATOR_EMAIL
const savedAliases = process.env.GATEWAY_OPERATOR_EMAIL_ALIASES

function reopen() {
  try { getDB().close() } catch {}
  initDB(dbPath)
}

function tenantRow(email: string): { id: string; role: string; email: string } | undefined {
  return getDB().prepare(`SELECT id, role, email FROM tenants WHERE email = ?`).get(email) as any
}

beforeEach(() => {
  dbPath = join(tmpdir(), `aeoess-operator-email-test-${randomUUID()}.db`)
  delete process.env.GATEWAY_OPERATOR_EMAIL
  delete process.env.GATEWAY_OPERATOR_EMAIL_ALIASES
  initDB(dbPath)
})

afterEach(() => {
  try { getDB().close() } catch {}
  try {
    const fs = require('node:fs')
    fs.unlinkSync(dbPath)
    fs.unlinkSync(dbPath + '-wal')
    fs.unlinkSync(dbPath + '-shm')
  } catch {}
  if (savedEmail === undefined) delete process.env.GATEWAY_OPERATOR_EMAIL
  else process.env.GATEWAY_OPERATOR_EMAIL = savedEmail
  if (savedAliases === undefined) delete process.env.GATEWAY_OPERATOR_EMAIL_ALIASES
  else process.env.GATEWAY_OPERATOR_EMAIL_ALIASES = savedAliases
})

describe('operator email config — unset', () => {
  it('elevates nobody and renames nobody when GATEWAY_OPERATOR_EMAIL is unset', () => {
    const { tenant } = createTenant({ name: 'Someone', email: 'someone@example.com', plan: 'free' })
    reopen() // re-run migrations against the now-populated DB
    const row = tenantRow('someone@example.com')
    assert.ok(row, 'tenant should still exist under its original email')
    assert.equal(row!.role, 'user')
    assert.equal(row!.id, tenant.id)
    const admin = getDB().prepare(`SELECT id FROM tenants WHERE role = 'admin'`).get()
    assert.equal(admin, undefined, 'no tenant should be admin')
  })
})

describe('operator email config — GATEWAY_OPERATOR_EMAIL set', () => {
  it('elevates the matching tenant to admin and reconciles its email', () => {
    createTenant({ name: 'Operator', email: 'operator@example.com', plan: 'free' })
    process.env.GATEWAY_OPERATOR_EMAIL = 'operator@example.com'
    reopen()
    const row = tenantRow('operator@example.com')
    assert.ok(row)
    assert.equal(row!.role, 'admin')
    const resolved = resolveTenantByEmail('operator@example.com')
    assert.ok(resolved, 'configured operator email should resolve via tenant_aliases')
    assert.equal(resolved!.tenant_id, row!.id)
  })

  it('does not elevate an unconfigured tenant', () => {
    createTenant({ name: 'Bystander', email: 'bystander@example.com', plan: 'free' })
    process.env.GATEWAY_OPERATOR_EMAIL = 'operator@example.com'
    reopen()
    const row = tenantRow('bystander@example.com')
    assert.ok(row)
    assert.equal(row!.role, 'user')
  })
})

describe('operator email config — GATEWAY_OPERATOR_EMAIL_ALIASES set', () => {
  it('aliases resolve to the operator tenant', () => {
    createTenant({ name: 'Operator', email: 'operator@example.com', plan: 'free' })
    process.env.GATEWAY_OPERATOR_EMAIL = 'operator@example.com'
    process.env.GATEWAY_OPERATOR_EMAIL_ALIASES = 'support@example.com, ops@example.com'
    reopen()
    const admin = tenantRow('operator@example.com')
    assert.ok(admin)
    for (const alias of ['support@example.com', 'ops@example.com']) {
      const resolved = resolveTenantByEmail(alias)
      assert.ok(resolved, `${alias} should resolve via tenant_aliases`)
      assert.equal(resolved!.tenant_id, admin!.id)
    }
  })

  it('merges a stray tenant holding an alias email into the admin tenant', () => {
    createTenant({ name: 'Operator', email: 'operator@example.com', plan: 'free' })
    createTenant({ name: 'Stray', email: 'support@example.com', plan: 'free' })
    process.env.GATEWAY_OPERATOR_EMAIL = 'operator@example.com'
    process.env.GATEWAY_OPERATOR_EMAIL_ALIASES = 'support@example.com'
    reopen()
    const admin = tenantRow('operator@example.com')
    assert.ok(admin)
    assert.equal(admin!.role, 'admin')
    const stray = getDB().prepare(
      `SELECT status FROM tenants WHERE email LIKE 'tombstone-operator-alias-stray-%'`
    ).get() as { status: string } | undefined
    assert.ok(stray, 'the stray tenant should be tombstoned')
    assert.equal(stray!.status, 'deleted')
  })
})
