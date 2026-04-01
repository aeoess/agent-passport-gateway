// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway — Server Entry Point
 *
 * The revenue product. Hosted enforcement for AI agent governance.
 *
 * Endpoints:
 *   POST /api/v1/evaluate      — policy evaluation (billable)
 *   POST /api/v1/receipt        — store signed receipt
 *   POST /api/v1/revoke         — cascade revocation
 *   POST /api/v1/agents         — register agent
 *   GET  /api/v1/agents         — list agents
 *   POST /api/v1/delegations    — create delegation
 *   GET  /api/v1/delegations    — list delegations
 *   GET  /api/v1/audit          — audit trail
 *   GET  /api/v1/dashboard      — dashboard summary
 *   GET  /api/v1/usage          — usage history
 *   POST /api/v1/alerts/:id/ack — acknowledge alert
 *   POST /api/v1/data-sources   — register data source (Pixel)
 *   GET  /api/v1/data-sources   — list data sources
 *   POST /api/v1/access-receipts — record data access
 *   GET  /api/v1/attribution    — attribution dashboard
 *   POST /api/v1/settlements    — generate settlement
 *   GET  /api/v1/settlements    — list settlements
 *   GET  /api/v1/my-consumption — agent self-service (what did I consume?)
 *   POST /api/v1/pay/nano/invoice    — create Nano payment request
 *   GET  /api/v1/pay/nano/status/:id — check invoice status
 *   POST /api/v1/pay/nano/settle/:id — execute settlement via Nano
 *   GET  /api/v1/pay/nano/balance    — gateway wallet balance
 *   GET  /api/v1/pay/nano/history    — recent Nano transactions
 *   POST /api/v1/pay/nano/verify     — verify on-chain transaction
 *   POST /api/v1/wallets/provision        — create wallet for agent
 *   GET  /api/v1/wallets/:id/balance      — live on-chain balance
 *   POST /api/v1/wallets/send             — delegation-gated send
 *   POST /api/v1/wallets/:id/receive      — pocket pending funds
 *   GET  /api/v1/wallets/:id/txs          — transaction history
 *   POST /api/v1/wallets/:id/freeze       — freeze wallet
 *   POST /api/v1/wallets/:id/unfreeze     — reactivate wallet
 *   GET  /api/v1/wallets                  — list all wallets
 *   GET  /api/v1/wallets/dashboard        — tenant wallet overview
 *   GET  /healthz               — health check
 */

import express from 'express'
import { mkdirSync, existsSync } from 'node:fs'
import { dirname } from 'node:path'

// Ensure DB directory exists (Railway Volumes mount at /data)
const dbPath = process.env.DB_PATH || './gateway.db'
const dbDir = dirname(dbPath)
if (dbDir !== '.' && !existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true })
  console.log('Created DB directory:', dbDir)
}
import cors from 'cors'
import helmet from 'helmet'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { initDB, getDB } from './db/schema.js'
import { authMiddleware, createTenant } from './auth/api-keys.js'
import { gatewayRouter } from './gateway/enforce.js'
import { initLineageTables } from './gateway/lineage.js'
import { initGatewayIdentity, getGatewayIdentity, getJwks } from './gateway/identity.js'
import { paymentRouter } from './payment-rails/routes.js'
import { walletRouter } from './payment-rails/wallet-routes.js'

const PORT = parseInt(process.env.PORT || '3200')
const DB_PATH = dbPath

const app = express()

// Security
app.use(helmet())
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }))
app.use(express.json({ limit: '1mb' }))

// Health check (no auth)
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', service: 'aeoess-gateway', version: '0.3.0' })
})

// JWKS endpoint — public key for verifying gateway-signed attestations
// Used by insumer-examples multi-attestation verifier, OATR, and any
// relying party that needs to verify APS trust attestation JWS.
app.get('/.well-known/jwks.json', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600')
  res.json(getJwks())
})

// Rate limiter for public signup endpoint
const signupLimiter = new RateLimiterMemory({
  points: 5,        // 5 signups
  duration: 3600,   // per hour per IP
  keyPrefix: 'signup',
})

// Public: create tenant (signup)
app.post('/api/v1/signup', async (req, res) => {
  // Rate limit by IP
  try {
    await signupLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Signup rate limit exceeded. Try again later.' })
  }

  const { name, email, plan } = req.body
  if (!name || !email) {
    return res.status(400).json({ error: 'Required: name, email' })
  }
  // Validate plan — only 'free' allowed via self-signup
  // 'pro' and 'enterprise' require manual provisioning
  const validPlan = plan === 'free' || !plan ? 'free' : 'free'
  try {
    const { tenant, apiKey } = createTenant({ name, email, plan: validPlan })
    res.status(201).json({
      message: 'Account created. Save your API key — it will not be shown again.',
      tenant_id: tenant.id,
      plan: tenant.plan,
      api_key: apiKey,
    })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already registered' })
    }
    return res.status(500).json({ error: e.message })
  }
})

// ═══════════════════════════════════════
// Public Trust Profile (no auth required)
// Cross-org trust querying: any sandbox, registry, or agent
// can check an agent's grade before interaction.
// From 0xbrainkid on NVIDIA/OpenShell#682.
// ═══════════════════════════════════════
const publicTrustLimiter = new RateLimiterMemory({
  points: 60,       // 60 requests
  duration: 60,     // per minute per IP
  keyPrefix: 'public_trust',
})

const trustProfileCache = new Map<string, { data: any; expires: number }>()
const TRUST_CACHE_TTL = 5 * 60 * 1000 // 5 min

app.get('/api/v1/public/trust/:agentId', async (req, res) => {
  // Rate limit
  try {
    await publicTrustLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' })
  }

  const { agentId } = req.params

  // Cache check
  const cached = trustProfileCache.get(agentId)
  if (cached && cached.expires > Date.now()) {
    return res.json(cached.data)
  }

  const db = getDB()

  // Search across ALL tenants — this is the public lookup
  const agent = db.prepare(
    `SELECT * FROM agents WHERE agent_id = ? AND status = 'active' ORDER BY created_at ASC LIMIT 1`
  ).get(agentId) as any

  if (!agent) {
    const notFound = { agent_id: agentId, grade: 0, grade_label: 'unknown', found: false, queried_at: new Date().toISOString() }
    return res.json(notFound)
  }

  const tenantId = agent.tenant_id

  // Delegation
  const delegation = db.prepare(
    `SELECT 1 FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' LIMIT 1`
  ).get(tenantId, agentId) as any

  // Wallet
  const wallet = db.prepare(
    `SELECT status FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? LIMIT 1`
  ).get(tenantId, agentId) as any

  // Dossier grade (if exists)
  const dossier = db.prepare(
    `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenantId, agentId) as any

  // Grade: dossier if exists, else heuristic
  let grade = 0
  if (dossier) {
    grade = dossier.passport_grade
  } else {
    const evalCount = (db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as any).c
    const receiptCount = (db.prepare(
      `SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as any).c
    if (agent.status === 'active') grade = 1
    if (delegation) grade = 2
    if (delegation && evalCount >= 10 && receiptCount >= 5) grade = 3
  }

  const gradeLabels: Record<number, string> = { 0: 'unknown', 1: 'registered', 2: 'endorsed', 3: 'established' }
  const trustLabels: Record<number, string> = { 0: 'unknown', 1: 'registered', 2: 'endorsed', 3: 'established' }

  // Risk — simple denial rate only (no internal metrics)
  const deniedCount = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND verdict = 'DENY'`
  ).get(tenantId, agentId) as any).c
  const evalTotal = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenantId, agentId) as any).c
  const denialRate = evalTotal > 0 ? Math.round((deniedCount / evalTotal) * 100) / 100 : 0
  const riskLevel = denialRate > 0.3 ? 'high' : denialRate > 0.1 ? 'medium' : 'low'

  const ageDays = Math.floor((Date.now() - new Date(agent.created_at).getTime()) / (1000 * 60 * 60 * 24))

  // Freshness signals (from 0xbrainkid on NVIDIA/OpenShell#682)
  const lastEval = db.prepare(
    `SELECT created_at FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenantId, agentId) as any
  const lastActivityAt = lastEval ? lastEval.created_at : agent.created_at
  const gradeComputedAt = dossier ? dossier.created_at : agent.created_at

  const profile = {
    agent_id: agentId,
    grade,
    grade_label: gradeLabels[grade] || 'unknown',
    trust: trustLabels[grade] || 'unknown',
    age_days: ageDays,
    risk_level: riskLevel,
    has_delegation: !!delegation,
    has_wallet: !!wallet,
    grade_computed_at: gradeComputedAt,
    last_activity_at: lastActivityAt,
    attestation_bundle_hash: dossier ? dossier.attestation_bundle_hash : null,
    found: true,
    queried_at: new Date().toISOString(),
  }

  // Cache
  trustProfileCache.set(agentId, { data: profile, expires: Date.now() + TRUST_CACHE_TTL })

  res.json(profile)
})

// Signed trust attestation — JWS compact format for multi-attestation verifiers
// Returns the same trust profile but Ed25519-signed by the gateway.
// Verifiable via /.well-known/jwks.json
app.get('/api/v1/public/trust/:agentId/attestation', async (req, res) => {
  // Same rate limit as trust profile
  try {
    await publicTrustLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' })
  }

  const { agentId } = req.params

  // Reuse the trust profile logic — fetch from cache or compute
  const cached = trustProfileCache.get(agentId)
  let profile: any
  if (cached && cached.expires > Date.now()) {
    profile = cached.data
  } else {
    // Profile not cached — consumer should query trust profile first
    return res.status(404).json({
      error: 'Trust profile not cached. Query /api/v1/public/trust/' + agentId + ' first.',
      hint: 'The attestation endpoint signs a cached trust profile. Fetch the profile first, then request the signed attestation.',
    })
  }

  const identity = getGatewayIdentity()
  const jws = identity.sign({
    ...profile,
    iss: 'https://gateway.aeoess.com',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 min validity
  })

  res.json({
    issuer: 'https://gateway.aeoess.com',
    type: 'passport_grade',
    kid: identity.kid,
    alg: 'EdDSA',
    jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
    signed: profile,
    jws,
  })
})

// Authenticated routes
app.use('/api/v1', authMiddleware, gatewayRouter)
app.use('/api/v1', authMiddleware, paymentRouter)
app.use('/api/v1', authMiddleware, walletRouter)

// 404
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found. See docs at aeoess.com/docs' })
})

// Init and start
const db = initDB(DB_PATH)
initLineageTables()
initGatewayIdentity()
console.log(`
═══════════════════════════════════════
  AEOESS Gateway v0.3.0 (Railway)
  Port: ${PORT}
  Database: ${DB_PATH}
  Endpoints: 33 API routes
═══════════════════════════════════════
`)
app.listen(PORT, () => {
  console.log(`  ✅ Listening on http://localhost:${PORT}`)
  console.log(`  Health: http://localhost:${PORT}/healthz`)
  console.log(`  Signup: POST http://localhost:${PORT}/api/v1/signup`)
})
