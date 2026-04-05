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
import { rekorRouter, initAnchorTable } from './gateway/rekor.js'

const PORT = parseInt(process.env.PORT || '3200')
const DB_PATH = dbPath

const app = express()

// Security
app.use(helmet())
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }))
app.use(express.json({ limit: '1mb' }))

// Health check (no auth)
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', service: 'aeoess-gateway', version: '0.3.4' })
})

// ═══════════════════════════════════════
// Receipt Resolution (WG interop, no auth)
// GET /.well-known/receipts/:id
// Cross-system lineage traversal: any WG member can resolve
// a proof reference to its full receipt + signature + JWKS.
// From desiorac on A2A#1672 + MCP#1763.
// ═══════════════════════════════════════
const receiptResolutionLimiter = new RateLimiterMemory({
  points: 120,      // 120 requests
  duration: 60,     // per minute per IP
  keyPrefix: 'receipt_resolve',
})

const receiptResolutionCache = new Map<string, { data: any; expires: number }>()
const RECEIPT_CACHE_TTL = 10 * 60 * 1000 // 10 min (receipts are immutable)

app.get('/.well-known/receipts/:receiptId', async (req, res) => {
  try {
    await receiptResolutionLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 120 req/min.' })
  }

  const { receiptId } = req.params

  // Cache check (receipts are immutable — long cache is safe)
  const cached = receiptResolutionCache.get(receiptId)
  if (cached && cached.expires > Date.now()) {
    res.setHeader('Cache-Control', 'public, max-age=600')
    return res.json(cached.data)
  }

  const db = getDB()

  // Search across receipt tables — receipts are identified by prefix or universal lookup
  // Tables: receipts (policy), access_receipts (data), derivations (lineage), settlements
  const tables = [
    { table: 'receipts', type: 'policy_receipt', payloadField: 'payload', signatureField: 'signature' },
    { table: 'access_receipts', type: 'access_receipt', payloadField: null, signatureField: 'signature' },
    { table: 'derivations', type: 'derivation_receipt', payloadField: 'derivation_json', signatureField: 'signature' },
    { table: 'settlements', type: 'settlement', payloadField: 'merkle_root', signatureField: 'signature' },
  ]

  for (const { table, type, payloadField, signatureField } of tables) {
    try {
      const row = db.prepare(`SELECT * FROM ${table} WHERE id = ? LIMIT 1`).get(receiptId) as any
      if (row) {
        let body: any
        if (payloadField && row[payloadField]) {
          try { body = JSON.parse(row[payloadField]) } catch { body = row[payloadField] }
        } else {
          // Reconstruct body from row fields (strip internal fields)
          const { tenant_id, ...publicFields } = row
          body = publicFields
        }

        const result = {
          proofId: `aps:${receiptId}`,
          proofType: type,
          issuer: 'https://gateway.aeoess.com',
          issuedAt: row.created_at,
          agentId: row.agent_id,
          signature: row[signatureField] || null,
          body,
          jwksUrl: 'https://gateway.aeoess.com/.well-known/jwks.json',
          resolvedAt: new Date().toISOString(),
        }

        receiptResolutionCache.set(receiptId, { data: result, expires: Date.now() + RECEIPT_CACHE_TTL })
        res.setHeader('Cache-Control', 'public, max-age=600')
        return res.json(result)
      }
    } catch {
      // Table might not have the right columns — skip
      continue
    }
  }

  res.status(404).json({
    proofId: `aps:${receiptId}`,
    error: 'Receipt not found',
    hint: 'This endpoint resolves APS receipt IDs. Try the trust profile at /api/v1/public/trust/:agentId for agent lookups.',
    resolvedAt: new Date().toISOString(),
  })
})

// JWKS endpoint — public key for verifying gateway-signed attestations
// Used by insumer-examples multi-attestation verifier, OATR, and any
// relying party that needs to verify APS trust attestation JWS.
app.get('/.well-known/jwks.json', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600, stale-if-error=86400')
  res.setHeader('CDN-Cache-Control', 'public, max-age=3600, stale-if-error=86400')
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

/**
 * Context Continuity Score (0-100)
 * Measures behavioral consistency for an agent. Higher = more consistent.
 * Three dimensions: activity regularity, behavioral consistency, identity maturity.
 * Context break detected when activity gap + behavioral shift co-occur.
 */
function computeContinuityScore(db: any, tenantId: string, agentId: string, ageDays: number) {
  // Fetch last 50 evaluation timestamps and verdicts
  const evals = db.prepare(
    `SELECT created_at, verdict FROM policy_evaluations
     WHERE tenant_id = ? AND agent_id = ?
     ORDER BY created_at DESC LIMIT 50`
  ).all(tenantId, agentId) as { created_at: string, verdict: string }[]

  if (evals.length < 2) {
    return { score: ageDays > 7 ? 30 : 10, context_break: false, signals: ['insufficient_data'] }
  }

  // 1. Activity Regularity (0-40): std dev of time gaps between evals
  const timestamps = evals.map(e => new Date(e.created_at).getTime()).reverse()
  const gaps: number[] = []
  for (let i = 1; i < timestamps.length; i++) {
    gaps.push(timestamps[i] - timestamps[i - 1])
  }
  const meanGap = gaps.reduce((a, b) => a + b, 0) / gaps.length
  const variance = gaps.reduce((a, g) => a + Math.pow(g - meanGap, 2), 0) / gaps.length
  const stdDev = Math.sqrt(variance)
  const cv = meanGap > 0 ? stdDev / meanGap : 0 // coefficient of variation
  // cv < 0.5 = very regular, cv > 2 = erratic
  const activityScore = Math.round(Math.max(0, Math.min(40, 40 * (1 - Math.min(cv, 2) / 2))))

  // 2. Behavioral Consistency (0-30): recent denial rate vs historical
  const totalDenials = evals.filter(e => e.verdict === 'DENY').length
  const historicalDenialRate = totalDenials / evals.length
  const recentEvals = evals.slice(0, Math.min(10, evals.length))
  const recentDenials = recentEvals.filter(e => e.verdict === 'DENY').length
  const recentDenialRate = recentDenials / recentEvals.length
  const denialDrift = Math.abs(recentDenialRate - historicalDenialRate)
  // drift < 0.1 = consistent, drift > 0.3 = behavioral shift
  const behaviorScore = Math.round(Math.max(0, Math.min(30, 30 * (1 - Math.min(denialDrift, 0.5) / 0.5))))

  // 3. Identity Maturity (0-30): age + evaluation volume
  const ageScore = Math.min(15, ageDays)  // max 15 from age
  const volumeScore = Math.min(15, Math.round(evals.length / 50 * 15)) // max 15 from volume
  const maturityScore = ageScore + volumeScore

  const score = activityScore + behaviorScore + maturityScore

  // Context break detection: large gap + behavioral shift
  const signals: string[] = []
  const maxGap = Math.max(...gaps)
  const maxGapHours = maxGap / (1000 * 60 * 60)
  let contextBreak = false

  if (maxGapHours > 24) signals.push('activity_gap_' + Math.round(maxGapHours) + 'h')
  if (denialDrift > 0.2) signals.push('denial_drift_' + Math.round(denialDrift * 100) + 'pct')
  if (cv > 1.5) signals.push('erratic_timing')
  if (maxGapHours > 24 && denialDrift > 0.15) {
    contextBreak = true
    signals.push('context_break')
  }

  return { score: Math.max(0, Math.min(100, score)), context_break: contextBreak, signals }
}

app.get('/api/v1/public/trust/:agentId', async (req, res) => {
  // Rate limit
  try {
    await publicTrustLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' })
  }

  const { agentId } = req.params

  // CDN caching: serve stale responses during deploys
  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')
  res.setHeader('CDN-Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')

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
    `SELECT scope, spend_limit, spend_used FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
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

  // Context continuity scoring
  const continuity = computeContinuityScore(db, tenantId, agentId, ageDays)

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
    active_constraints: delegation ? {
      scopes: delegation.scope ? delegation.scope.split(',').map((s: string) => s.trim()) : [],
      spend_limit: delegation.spend_limit || null,
      spend_used: delegation.spend_used || 0,
    } : null,
    grade_computed_at: gradeComputedAt,
    last_activity_at: lastActivityAt,
    attestation_bundle_hash: dossier ? dossier.attestation_bundle_hash : null,
    context_continuity: {
      score: continuity.score,
      context_break: continuity.context_break,
      signals: continuity.signals,
    },
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

  // CDN caching: attestations valid for 60s, serve stale during deploys
  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')
  res.setHeader('CDN-Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')

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

// ═══════════════════════════════════════
// MCP Stats Persistence
// POST /api/v1/mcp-stats — authenticated heartbeat from MCP server
// GET  /api/v1/mcp-stats/cumulative — public cumulative totals (powers /stats page)
// ═══════════════════════════════════════

// Public cumulative totals — no auth, powers mcp.aeoess.com/stats page
app.get('/api/v1/mcp-stats/cumulative', (_req, res) => {
  try {
    const db = getDB()
    // Cumulative = sum of the MAX counter per session_id (each session's peak
    // value across all its snapshots). Counters are monotonic within a session.
    const perSession = db.prepare(`
      SELECT session_id,
             MAX(uptime_seconds)      AS uptime_seconds,
             MAX(passports_issued)    AS passports_issued,
             MAX(sessions_total)      AS sessions_total,
             MAX(tool_calls_total)    AS tool_calls_total,
             MAX(evaluations_total)   AS evaluations_total,
             MAX(delegations_created) AS delegations_created,
             MAX(receipts_stored)     AS receipts_stored
      FROM mcp_stats_snapshots
      GROUP BY session_id
    `).all() as Array<{
      session_id: string
      uptime_seconds: number
      passports_issued: number
      sessions_total: number
      tool_calls_total: number
      evaluations_total: number
      delegations_created: number
      receipts_stored: number
    }>

    let passports_issued = 0, sessions_total = 0, tool_calls_total = 0
    let evaluations_total = 0, delegations_created = 0, receipts_stored = 0
    let total_uptime_seconds = 0
    for (const r of perSession) {
      passports_issued    += r.passports_issued    || 0
      sessions_total      += r.sessions_total      || 0
      tool_calls_total    += r.tool_calls_total    || 0
      evaluations_total   += r.evaluations_total   || 0
      delegations_created += r.delegations_created || 0
      receipts_stored     += r.receipts_stored     || 0
      total_uptime_seconds += r.uptime_seconds     || 0
    }

    const meta = db.prepare(`
      SELECT COUNT(*) AS snapshot_count,
             MIN(snapshot_at) AS first_snapshot_at,
             MAX(snapshot_at) AS last_snapshot_at
      FROM mcp_stats_snapshots
    `).get() as { snapshot_count: number; first_snapshot_at: string | null; last_snapshot_at: string | null }

    // Current session = most recent snapshot
    const latest = db.prepare(`
      SELECT session_id, uptime_seconds, sessions_active
      FROM mcp_stats_snapshots
      ORDER BY snapshot_at DESC
      LIMIT 1
    `).get() as { session_id: string; uptime_seconds: number; sessions_active: number } | undefined

    res.setHeader('Cache-Control', 'public, max-age=30, stale-while-revalidate=120')
    res.json({
      cumulative: {
        passports_issued,
        sessions_total,
        tool_calls_total,
        evaluations_total,
        delegations_created,
        receipts_stored,
        total_uptime_hours: Math.round((total_uptime_seconds / 3600) * 10) / 10,
      },
      current_session: latest ? {
        session_id: latest.session_id,
        uptime_seconds: latest.uptime_seconds,
        sessions_active: latest.sessions_active,
      } : null,
      snapshot_count: meta.snapshot_count,
      first_snapshot_at: meta.first_snapshot_at,
      last_snapshot_at: meta.last_snapshot_at,
    })
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch cumulative stats' })
  }
})

// Authenticated heartbeat — MCP posts its counters every ~5min + on SIGTERM
app.post('/api/v1/mcp-stats', authMiddleware, (req: any, res) => {
  try {
    const b = req.body || {}
    if (typeof b.session_id !== 'string' || !b.session_id) {
      return res.status(400).json({ error: 'session_id required' })
    }
    const db = getDB()
    const snapshotAt = new Date().toISOString()
    // Upsert window: if a snapshot for this session exists within the last 5 min,
    // update it (monotonic counters overwrite). Otherwise insert a new row.
    const existing = db.prepare(`
      SELECT id FROM mcp_stats_snapshots
      WHERE session_id = ?
        AND snapshot_at >= datetime('now', '-5 minutes')
      ORDER BY snapshot_at DESC LIMIT 1
    `).get(b.session_id) as { id: number } | undefined

    const values = {
      snapshot_at: snapshotAt,
      uptime_seconds: Number(b.uptime_seconds) || 0,
      passports_issued: Number(b.passports_issued) || 0,
      sessions_total: Number(b.sessions_total) || 0,
      sessions_active: Number(b.sessions_active) || 0,
      tool_calls_total: Number(b.tool_calls_total) || 0,
      evaluations_total: Number(b.evaluations_total) || 0,
      delegations_created: Number(b.delegations_created) || 0,
      receipts_stored: Number(b.receipts_stored) || 0,
      version: typeof b.version === 'string' ? b.version : null,
      tenant_id: req.tenant?.id ?? null,
    }

    if (existing) {
      db.prepare(`
        UPDATE mcp_stats_snapshots SET
          snapshot_at = ?, uptime_seconds = ?, passports_issued = ?,
          sessions_total = ?, sessions_active = ?, tool_calls_total = ?,
          evaluations_total = ?, delegations_created = ?, receipts_stored = ?,
          version = ?, tenant_id = ?
        WHERE id = ?
      `).run(
        values.snapshot_at, values.uptime_seconds, values.passports_issued,
        values.sessions_total, values.sessions_active, values.tool_calls_total,
        values.evaluations_total, values.delegations_created, values.receipts_stored,
        values.version, values.tenant_id, existing.id,
      )
      return res.json({ ok: true, action: 'updated', snapshot_id: existing.id })
    }

    const info = db.prepare(`
      INSERT INTO mcp_stats_snapshots (
        session_id, snapshot_at, uptime_seconds, passports_issued,
        sessions_total, sessions_active, tool_calls_total, evaluations_total,
        delegations_created, receipts_stored, version, tenant_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      b.session_id, values.snapshot_at, values.uptime_seconds, values.passports_issued,
      values.sessions_total, values.sessions_active, values.tool_calls_total,
      values.evaluations_total, values.delegations_created, values.receipts_stored,
      values.version, values.tenant_id,
    )
    res.json({ ok: true, action: 'inserted', snapshot_id: info.lastInsertRowid })
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to record snapshot' })
  }
})

// Authenticated routes
app.use('/api/v1', authMiddleware, gatewayRouter)
app.use('/api/v1', authMiddleware, paymentRouter)
app.use('/api/v1', authMiddleware, walletRouter)
app.use('/api/v1', authMiddleware, rekorRouter)

// 404
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found. See docs at aeoess.com/docs' })
})

// Init and start
const db = initDB(DB_PATH)
initLineageTables()
initGatewayIdentity()
initAnchorTable()
console.log(`
═══════════════════════════════════════
  AEOESS Gateway v0.3.3 (Railway)
  Port: ${PORT}
  Database: ${DB_PATH}
  Endpoints: 36 API routes + 2 public (.well-known)
═══════════════════════════════════════
`)
app.listen(PORT, () => {
  console.log(`  ✅ Listening on http://localhost:${PORT}`)
  console.log(`  Health: http://localhost:${PORT}/healthz`)
  console.log(`  Signup: POST http://localhost:${PORT}/api/v1/signup`)
})
