// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - HTTP surface
// ══════════════════════════════════════════════════════════════════
// One authenticated router for connector management (register / list / delete
// signed-webhook endpoints, list + redeliver dead letters) mounted once in
// server.ts, plus the inbound identity-bridge express.raw routes for Okta /
// Entra offboard (mounted before express.json, mirroring the Stripe webhook
// precedent at server.ts line 128).
//
// Thin gateway: management mutates only the tenant's own endpoint registry;
// the inbound bridge verifies at the edge then calls the SAME cascade revoke
// the enforce.ts route runs. No new authority is concentrated here.
//
// Connector lifecycle event-type literals (connector_delivered, connector_retry,
// connector_dead_lettered, identity_offboard) are emitted via getEventBus().emit
// against the BASE void contract. They are net-new literals; when G-A1's events.ts
// (which widens the GatewayEvent union) merges, these literals are appended to
// that union so the two branches merge cleanly. Until then the dispatcher widens
// the type at the emit call site rather than redefining the shared EventBus.
// ══════════════════════════════════════════════════════════════════

import { Router, type Request, type Response } from 'express'
import express from 'express'
import { randomUUID } from 'node:crypto'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { getDB } from '../../db/schema.js'
import { getEventBus } from '../../gateway/events.js'
import type { Tenant } from '../../auth/api-keys.js'
import {
  registerEndpoint,
  listEndpoints,
  getEndpoint,
  deleteEndpoint,
} from './subscription-store.js'
import { listDeadLetters, deadLetterCount } from './dispatcher.js'
import {
  verifyInboundOffboard,
  applyOffboard,
  type IdentityProvider,
  type NormalizedOffboard,
} from './identity-bridge.js'

export const connectorsRouter = Router()

// Per-tenant rate limit on endpoint registration. Mirrors the enforce.ts revoke
// limiter posture: a leaked key should not be able to register a flood of
// exfiltration endpoints in one session.
const registerLimiter = new RateLimiterMemory({ points: 20, duration: 60, keyPrefix: 'connector_register' })

// ── Endpoint management ───────────────────────────────────────────

connectorsRouter.post('/connectors/endpoints', async (req: any, res: Response) => {
  const tenant: Tenant = req.tenant
  try {
    await registerLimiter.consume(tenant.id)
  } catch {
    return res.status(429).json({ error: 'Endpoint registration rate limit exceeded (20/min/tenant)' })
  }
  const { target_url, event_types, secret } = req.body ?? {}
  if (!target_url || typeof target_url !== 'string') {
    return res.status(400).json({ error: 'Required: target_url (https)' })
  }
  const result = registerEndpoint({
    tenantId: tenant.id,
    targetUrl: target_url,
    eventTypes: Array.isArray(event_types) ? event_types : '*',
    secret: typeof secret === 'string' ? secret : undefined,
  })
  if (!result.ok || !result.endpoint) {
    return res.status(400).json({ error: result.error ?? 'registration failed' })
  }
  return res.status(201).json({
    id: result.endpoint.id,
    target_url: result.endpoint.targetUrl,
    event_types: result.endpoint.eventTypes,
    // Secret returned once at creation so the customer can configure their
    // verifier; it is not echoed on later reads.
    secret: result.endpoint.secret,
    status: result.endpoint.status,
  })
})

connectorsRouter.get('/connectors/endpoints', (req: any, res: Response) => {
  const tenant: Tenant = req.tenant
  const endpoints = listEndpoints(tenant.id).map((e) => ({
    id: e.id,
    target_url: e.targetUrl,
    event_types: e.eventTypes,
    status: e.status,
    created_at: e.createdAt,
  }))
  return res.json({ endpoints })
})

connectorsRouter.delete('/connectors/endpoints/:id', (req: any, res: Response) => {
  const tenant: Tenant = req.tenant
  const existing = getEndpoint(tenant.id, req.params.id)
  if (!existing) return res.status(404).json({ error: 'endpoint not found' })
  deleteEndpoint(tenant.id, req.params.id)
  return res.json({ deleted: true, id: req.params.id })
})

// ── Dead-letter drain ─────────────────────────────────────────────

connectorsRouter.get('/connectors/dead-letters', (req: any, res: Response) => {
  const tenant: Tenant = req.tenant
  return res.json({ count: deadLetterCount(tenant.id), dead_letters: listDeadLetters(tenant.id) })
})

// ══════════════════════════════════════════════════════════════════
// Inbound identity bridge (Okta / Entra offboard -> gateway revoke)
// ══════════════════════════════════════════════════════════════════
// These routes need the RAW request body for HMAC verification, so they are
// mounted with express.raw, exactly like the Stripe webhook. They are exported
// separately and wired in server.ts BEFORE express.json (see mountInboundIdentityBridge).
// They authenticate via the per-provider shared secret, NOT the tenant API key,
// because the caller is an IdP, not the tenant's own client.

/** The cascade-revoke thunk. Runs the SAME DB cascade the enforce.ts POST
 *  /api/v1/revoke route runs, in-process, so the bridge does not duplicate the
 *  revoke logic or hold a second revoke path. */
async function cascadeRevokeAgent(
  tenantId: string,
  agentId: string,
  revokedBy: string,
): Promise<{ cascadeCount: number }> {
  const db = getDB()
  db.prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`).run(tenantId, agentId)
  const result = db
    .prepare(
      `UPDATE delegations SET status = 'revoked', revoked_at = datetime('now')
         WHERE tenant_id = ? AND (child_agent_id = ? OR parent_agent_id = ?)`,
    )
    .run(tenantId, agentId, agentId)
  db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`).run(
    tenantId,
    agentId,
  )
  const cascadeCount = (result.changes as number) || 0
  const revocationId = randomUUID()
  db.prepare(
    `INSERT INTO revocations (id, tenant_id, target_type, target_id, cascade_count, revoked_by) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(revocationId, tenantId, 'agent', agentId, cascadeCount, revokedBy)
  db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`).run(
    randomUUID(),
    tenantId,
    'revocation',
    'critical',
    `agent "${agentId}" revoked via identity offboard (${revokedBy}). ${cascadeCount} downstream items affected.`,
  )
  try {
    getEventBus().emit(tenantId, {
      type: 'revocation',
      data: { revocationId, target_type: 'agent', target_id: agentId, cascade_count: cascadeCount, revoked_by: revokedBy },
    })
  } catch {
    /* bus failure must not break the revoke */
  }
  return { cascadeCount }
}

/**
 * Parse a provider request into a NormalizedOffboard. GATE (Tima): the real
 * Okta event-hook / Entra lifecycle payload shapes are Tima's to finalize. This
 * default reads a small normalized JSON the customer's IdP integration posts;
 * Tima swaps in the provider-native parsers behind this same return type.
 */
function parseOffboard(provider: IdentityProvider, raw: any): NormalizedOffboard | null {
  if (!raw || typeof raw !== 'object') return null
  const externalUserId = String(raw.external_user_id ?? raw.objectId ?? raw.userId ?? '')
  if (!externalUserId) return null
  const action = (raw.action as NormalizedOffboard['action']) ?? 'deprovision'
  return {
    provider,
    externalUserId,
    userName: raw.user_name ?? raw.userName ?? raw.userPrincipalName,
    action,
  }
}

/** Shared handler for both providers. */
async function handleInboundOffboard(provider: IdentityProvider, req: Request, res: Response): Promise<Response> {
  const tenantId = String(req.header('x-aeoess-tenant') ?? '')
  if (!tenantId) return res.status(400).json({ error: 'missing x-aeoess-tenant header' })

  // Per-provider, per-tenant shared secret. The customer configures this when
  // they set up the IdP integration. Held in env keyed by provider+tenant so the
  // gateway holds no single global IdP credential.
  const secret = process.env[`IDP_${provider.toUpperCase()}_SECRET_${tenantId}`] || process.env[`IDP_${provider.toUpperCase()}_SECRET`]
  if (!secret) return res.status(401).json({ error: 'identity bridge not configured for this tenant' })

  const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : typeof req.body === 'string' ? req.body : ''
  const signature = String(req.header('x-idp-signature') ?? '')
  const nonce = String(req.header('x-idp-nonce') ?? '')
  const timestampMs = Number(req.header('x-idp-timestamp') ?? '0')

  const verified = verifyInboundOffboard({
    provider,
    rawBody,
    secret,
    signature,
    nonce,
    timestampMs,
    tenantId,
  })
  if (!verified.ok) return res.status(401).json({ error: `inbound verification failed: ${verified.reason}` })

  let parsed: any
  try {
    parsed = JSON.parse(rawBody || '{}')
  } catch {
    return res.status(400).json({ error: 'inbound body is not valid JSON' })
  }
  const offboard = parseOffboard(provider, parsed)
  if (!offboard) return res.status(400).json({ error: 'could not parse offboard event' })

  const outcome = await applyOffboard({
    tenantId,
    offboard,
    revoke: ({ targetId, revokedBy }) => cascadeRevokeAgent(tenantId, targetId, revokedBy),
  })

  return res.json({
    received: true,
    provider,
    mapped: outcome.mapped,
    target_type: outcome.targetType ?? null,
    target_id: outcome.targetId ?? null,
    event_id: outcome.event.event_id,
  })
}

/**
 * Mount the inbound identity-bridge routes on the app with express.raw, before
 * express.json. Called from server.ts alongside the Stripe webhook precedent.
 */
export function mountInboundIdentityBridge(app: express.Express): void {
  app.post('/api/v1/connectors/identity/okta', express.raw({ type: '*/*', limit: '256kb' }), (req, res) => {
    void handleInboundOffboard('okta', req, res)
  })
  app.post('/api/v1/connectors/identity/entra', express.raw({ type: '*/*', limit: '256kb' }), (req, res) => {
    void handleInboundOffboard('entra', req, res)
  })
}
