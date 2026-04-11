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

/** Tenant authorization role. Distinct from `plan` (a billing concept).
 *  `admin` = platform operator with access to /api/v1/admin/* routes.
 *  `user`  = regular tenant (default). Added by security triage fix 1
 *  on 2026-04-11 to stop conflating enterprise-plan billing with admin
 *  authority. See CODE-AUDIT-2026-04-11.md §2.9 for context. */
export type TenantRole = 'admin' | 'user'

export interface Tenant {
  id: string
  name: string
  email: string
  plan: Plan
  stripe_customer_id: string | null
  status: string
  role: TenantRole
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
    role: 'user',
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
  `).get(keyHash) as (Tenant & { role?: string }) | undefined

  if (!row) return null
  // Update last_used_at
  db.prepare(`UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?`).run(keyHash)
  // Normalize role: the column is added by an idempotent ALTER TABLE in
  // schema.ts, but defensively default to 'user' if the migration has not
  // run on a stale DB connection.
  const role: TenantRole = row.role === 'admin' ? 'admin' : 'user'
  return { ...row, role }
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

/**
 * Express middleware: require platform-operator role. Must be chained
 * AFTER authMiddleware so req.tenant is populated.
 *
 * Checks tenant.role === 'admin', NOT tenant.plan. The `plan` column is
 * a billing concept (free/pro/enterprise) and must not be used for
 * authorization. Before this middleware existed, the three /api/v1/admin/*
 * routes gated on `plan === 'enterprise'`, which meant any paying
 * enterprise customer would have inherited platform-operator capabilities
 * including listing and soft-deleting other tenants.
 *
 * The AEOESS operator tenant (email signal@aeoess.com) is elevated to
 * role='admin' by the idempotent migration in src/db/schema.ts. All other
 * tenants default to role='user' regardless of plan.
 *
 * Reference: CODE-AUDIT-2026-04-11.md §2.9, security triage fix 1.
 */
export function requireAdmin(req: any, res: any, next: any) {
  const tenant: Tenant | undefined = req.tenant
  if (!tenant) {
    // Defensive: should never reach here if authMiddleware ran first.
    return res.status(401).json({ error: 'Authentication required' })
  }
  if (tenant.role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required for this endpoint' })
  }
  next()
}
