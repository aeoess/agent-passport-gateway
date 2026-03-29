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
import { initDB } from './db/schema.js'
import { authMiddleware, createTenant } from './auth/api-keys.js'
import { gatewayRouter } from './gateway/enforce.js'

const PORT = parseInt(process.env.PORT || '3200')
const DB_PATH = dbPath

const app = express()

// Security
app.use(helmet())
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }))
app.use(express.json({ limit: '1mb' }))

// Health check (no auth)
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', service: 'aeoess-gateway', version: '0.1.0' })
})

// Public: create tenant (signup)
app.post('/api/v1/signup', (req, res) => {
  const { name, email, plan } = req.body
  if (!name || !email) {
    return res.status(400).json({ error: 'Required: name, email' })
  }
  try {
    const { tenant, apiKey } = createTenant({ name, email, plan })
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

// Authenticated routes
app.use('/api/v1', authMiddleware, gatewayRouter)

// 404
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found. See docs at aeoess.com/docs' })
})

// Init and start
const db = initDB(DB_PATH)
console.log(`
═══════════════════════════════════════
  AEOESS Gateway v0.1.0 (Railway)
  Port: ${PORT}
  Database: ${DB_PATH}
  Endpoints: 17 API routes
═══════════════════════════════════════
`)
app.listen(PORT, () => {
  console.log(`  ✅ Listening on http://localhost:${PORT}`)
  console.log(`  Health: http://localhost:${PORT}/healthz`)
  console.log(`  Signup: POST http://localhost:${PORT}/api/v1/signup`)
})
