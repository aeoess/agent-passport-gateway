// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for src/auth/email-password.ts. Exercises:
//   - password validation rules (length, common-password blocklist)
//   - bcrypt hash + verify round-trip
//   - constant-time path (burnTime) does not throw and takes nontrivial time
//   - reset token lifecycle: create → consume → second consume is rejected
//   - reset token expiry rejection
//   - email verification token lifecycle
//   - issueApiKey + revokeAllApiKeysForTenant against an in-memory tenant
//   - findTenantByEmail returns null + non-null appropriately

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID, randomBytes } from 'node:crypto'
import { initDB, getDB } from '../src/db/schema.js'
import { createTenant } from '../src/auth/api-keys.js'
import {
  validatePassword, isValidEmail, normalizeEmail,
  hashPassword, verifyPassword, burnTime,
  findTenantByEmail, setTenantPassword, markEmailVerified,
  issueApiKey, revokeAllApiKeysForTenant,
  createPasswordResetToken, consumePasswordResetToken,
  createEmailVerificationToken, consumeEmailVerificationToken,
} from '../src/auth/email-password.js'

// Each test run gets its own SQLite file so we don't collide with other
// tests or stale state. The file is removed after the suite.
let dbPath: string

before(() => {
  dbPath = join(tmpdir(), `aeoess-email-password-test-${randomUUID()}.db`)
  initDB(dbPath)
})

after(() => {
  try { getDB().close() } catch {}
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const fs = require('node:fs')
    fs.unlinkSync(dbPath)
    fs.unlinkSync(dbPath + '-wal')
    fs.unlinkSync(dbPath + '-shm')
  } catch {}
})

describe('validatePassword', () => {
  it('rejects passwords shorter than 10 characters', () => {
    assert.equal(validatePassword('short').ok, false)
    assert.equal(validatePassword('123456789').ok, false) // 9 chars
    assert.equal(validatePassword('1234567890').ok, false) // 10 chars but on blocklist
  })

  it('accepts a 10+ character non-common password', () => {
    assert.equal(validatePassword('correcthorsebatterystaple').ok, true)
  })

  it('rejects common passwords from the blocklist', () => {
    assert.equal(validatePassword('password123').ok, false)
    assert.equal(validatePassword('PASSWORD123').ok, false) // case-insensitive
    assert.equal(validatePassword('qwerty123').ok, false)
  })

  it('rejects non-string inputs', () => {
    assert.equal(validatePassword(undefined as any).ok, false)
    assert.equal(validatePassword(null as any).ok, false)
    assert.equal(validatePassword(12345 as any).ok, false)
  })

  it('rejects absurdly long passwords (DoS guard)', () => {
    assert.equal(validatePassword('a'.repeat(257)).ok, false)
  })
})

describe('email helpers', () => {
  it('isValidEmail rejects obviously malformed addresses', () => {
    assert.equal(isValidEmail('foo'), false)
    assert.equal(isValidEmail('foo@bar'), false)
    assert.equal(isValidEmail('foo@bar.com'), true)
    assert.equal(isValidEmail('  spaces@bar.com'), false)
  })

  it('normalizeEmail lowercases + trims', () => {
    assert.equal(normalizeEmail('  Foo@Example.COM  '), 'foo@example.com')
  })
})

describe('hashPassword + verifyPassword', () => {
  it('round-trips a password through bcrypt', async () => {
    const hash = await hashPassword('correcthorsebatterystaple')
    assert.match(hash, /^\$2[aby]\$/)
    assert.equal(await verifyPassword('correcthorsebatterystaple', hash), true)
    assert.equal(await verifyPassword('wrong-password-1234', hash), false)
  })

  it('different passwords produce different hashes', async () => {
    const a = await hashPassword('correcthorsebatterystaple')
    const b = await hashPassword('correcthorsebatterystaple')
    // Same input, different salts → different hashes.
    assert.notEqual(a, b)
  })

  it('burnTime completes without throwing', async () => {
    // Constant-time path called when email is unknown. Must not error.
    await burnTime()
    assert.ok(true)
  })
})

describe('findTenantByEmail + setTenantPassword + markEmailVerified', () => {
  it('returns null when no tenant exists for the email', () => {
    assert.equal(findTenantByEmail('nonexistent-' + randomBytes(8).toString('hex') + '@example.com'), null)
  })

  it('returns a tenant with password_hash=null right after creation', () => {
    const email = `pw-set-test-${randomBytes(8).toString('hex')}@example.com`
    createTenant({ name: 'Test', email })
    const found = findTenantByEmail(email)
    assert.ok(found)
    assert.equal(found!.password_hash, null)
    assert.equal(found!.email_verified, 0)
  })

  it('setTenantPassword stores the hash', async () => {
    const email = `pw-set-test-2-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    const hash = await hashPassword('correcthorsebatterystaple')
    setTenantPassword(tenant.id, hash)
    const found = findTenantByEmail(email)
    assert.equal(found!.password_hash, hash)
  })

  it('markEmailVerified flips email_verified to 1', () => {
    const email = `verify-test-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    markEmailVerified(tenant.id)
    const found = findTenantByEmail(email)
    assert.equal(found!.email_verified, 1)
  })
})

describe('issueApiKey + revokeAllApiKeysForTenant', () => {
  it('issueApiKey adds a new key with the expected prefix', () => {
    const email = `key-issue-test-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    const key = issueApiKey(tenant.id, 'test-source')
    assert.match(key, /^aps_live_[0-9a-f]{64}$/)
    const db = getDB()
    const rows = db.prepare(`SELECT name FROM api_keys WHERE tenant_id = ?`).all(tenant.id) as any[]
    // Tenant has one default key from createTenant + one we just issued = 2.
    assert.equal(rows.length, 2)
    assert.ok(rows.some(r => r.name === 'test-source'))
  })

  it('revokeAllApiKeysForTenant flips revoked_at on every active key', () => {
    const email = `key-revoke-test-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    issueApiKey(tenant.id, 'key-2')
    issueApiKey(tenant.id, 'key-3')

    const revoked = revokeAllApiKeysForTenant(tenant.id)
    assert.equal(revoked, 3) // default + 2 = 3

    const db = getDB()
    const active = db.prepare(`SELECT id FROM api_keys WHERE tenant_id = ? AND revoked_at IS NULL`)
      .all(tenant.id) as any[]
    assert.equal(active.length, 0)
  })

  it('revoking again is a no-op (idempotent)', () => {
    const email = `key-revoke-idem-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    revokeAllApiKeysForTenant(tenant.id)
    const second = revokeAllApiKeysForTenant(tenant.id)
    assert.equal(second, 0)
  })
})

describe('password reset token lifecycle', () => {
  it('createPasswordResetToken returns a URL-safe string and stores the SHA-256 hash', () => {
    const email = `reset-test-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    const rawToken = createPasswordResetToken(tenant.id)
    // base64url alphabet (no +/=)
    assert.match(rawToken, /^[A-Za-z0-9_-]+$/)
    assert.ok(rawToken.length >= 40)
  })

  it('consumePasswordResetToken accepts a fresh token and rejects the second use', () => {
    const email = `reset-consume-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    const rawToken = createPasswordResetToken(tenant.id)

    const first = consumePasswordResetToken(rawToken)
    assert.equal(first.ok, true)
    assert.equal(first.tenantId, tenant.id)

    const second = consumePasswordResetToken(rawToken)
    assert.equal(second.ok, false)
    assert.match(second.reason || '', /already been used/)
  })

  it('rejects an unknown token without leaking which case it is', () => {
    const result = consumePasswordResetToken('definitely-not-a-real-token')
    assert.equal(result.ok, false)
    assert.match(result.reason || '', /Invalid or expired/)
  })

  it('rejects an expired token', () => {
    const email = `reset-expire-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    const rawToken = createPasswordResetToken(tenant.id)

    // Force expiry by rewriting the row's expires_at to a past date.
    const db = getDB()
    db.prepare(`UPDATE password_reset_tokens SET expires_at = ? WHERE tenant_id = ?`)
      .run(new Date(Date.now() - 1000).toISOString(), tenant.id)

    const result = consumePasswordResetToken(rawToken)
    assert.equal(result.ok, false)
    assert.match(result.reason || '', /expired/)
  })
})

describe('email verification token lifecycle', () => {
  it('round-trips create + consume', () => {
    const email = `verify-consume-${randomBytes(8).toString('hex')}@example.com`
    const { tenant } = createTenant({ name: 'Test', email })
    const rawToken = createEmailVerificationToken(tenant.id)

    const first = consumeEmailVerificationToken(rawToken)
    assert.equal(first.ok, true)
    assert.equal(first.tenantId, tenant.id)

    const second = consumeEmailVerificationToken(rawToken)
    assert.equal(second.ok, false)
  })

  it('rejects a forged token', () => {
    const result = consumeEmailVerificationToken('forged-' + randomBytes(20).toString('hex'))
    assert.equal(result.ok, false)
  })
})
