// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * API Key Authentication — multi-tenant isolation
 *
 * Keys: aps_live_<32 random hex> (displayed once at creation)
 * Stored: SHA-256 hash only (key itself not stored)
 * Auth: Bearer token in Authorization header
 */

import { createHash, randomBytes } from 'node:crypto'
import { randomUUID } from 'node:crypto'
import { getDB } from '../db/schema.js'
import type { Plan } from '../db/schema.js'

export interface Tenant {
  id: string
  name: string
  email: string
  plan: Plan
  stripe_customer_id: string | null
  status: string
}

function hashKey(key: string): string {
  return createHash('sha256').update(key).digest('hex')
}

/**
 * Create a new tenant + API key. Returns the raw key (only shown once).
 */
export function createTenant(opts: {
  name: string; email: string; plan?: Plan
}): { tenant: Tenant; apiKey: string } {
  const db = getDB()
  const tenantId = randomUUID()
  const rawKey = `aps_live_${randomBytes(32).toString('hex')}`
  const keyHash = hashKey(rawKey)
  const keyPrefix = rawKey.slice(0, 12)

  const plan = opts.plan || 'free'
  db.prepare(`INSERT INTO tenants (id, name, email, plan) VALUES (?, ?, ?, ?)`)
    .run(tenantId, opts.name, opts.email, plan)
  db.prepare(`INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name) VALUES (?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenantId, keyHash, keyPrefix, 'default')

  const tenant: Tenant = {
    id: tenantId, name: opts.name, email: opts.email,
    plan: plan as Plan, stripe_customer_id: null, status: 'active',
  }
  return { tenant, apiKey: rawKey }
}

/**
 * Authenticate a request by API key. Returns tenant or null.
 */
export function authenticateKey(rawKey: string): Tenant | null {
  const db = getDB()
  const keyHash = hashKey(rawKey)
  const row = db.prepare(`
    SELECT t.* FROM tenants t
    JOIN api_keys k ON k.tenant_id = t.id
    WHERE k.key_hash = ? AND k.revoked_at IS NULL AND t.status = 'active'
  `).get(keyHash) as Tenant | undefined

  if (!row) return null
  // Update last_used_at
  db.prepare(`UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?`).run(keyHash)
  return row
}

/**
 * Express middleware: authenticate and attach tenant to req
 */
export function authMiddleware(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing API key. Use: Authorization: Bearer aps_live_...' })
  }
  const key = authHeader.slice(7)
  const tenant = authenticateKey(key)
  if (!tenant) {
    return res.status(401).json({ error: 'Invalid or revoked API key' })
  }
  req.tenant = tenant
  next()
}
