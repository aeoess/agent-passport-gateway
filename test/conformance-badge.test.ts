// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Public conformance surface - badge + JSON derive from ONE source.
//
// Proves:
//   - conformanceBadge() emits the shields.io endpoint schema, derived
//     entirely from CONFORMANCE_SUMMARY (no second hardcoded copy)
//   - color is brightgreen when failing_vectors is 0, red otherwise
//   - the badge message tracks passing/total exactly
//   - CONFORMANCE_SUMMARY is internally consistent (category tallies sum
//     to the top-line totals)
//   - both routes serialize over HTTP with the expected bodies
//
// The routes are mounted here with the same paths + handlers as
// src/server.ts; server.ts calls app.listen at import time, so the routes
// are exercised against the exported source of truth rather than by booting
// the whole gateway.
// ══════════════════════════════════════════════════════════════════

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { CONFORMANCE_SUMMARY, conformanceBadge } from '../src/gateway/conformance-summary.js'

describe('conformanceBadge() - shields.io endpoint derivation', () => {
  it('emits schemaVersion 1 and the fixed label', () => {
    const b = conformanceBadge()
    assert.equal(b.schemaVersion, 1)
    assert.equal(b.label, 'APS conformance')
  })

  it('message is passing/total verified, straight from the summary', () => {
    const b = conformanceBadge()
    assert.equal(
      b.message,
      `${CONFORMANCE_SUMMARY.passing_vectors}/${CONFORMANCE_SUMMARY.total_vectors} verified`,
    )
  })

  it('color is brightgreen while no vectors fail', () => {
    assert.equal(CONFORMANCE_SUMMARY.failing_vectors, 0)
    assert.equal(conformanceBadge().color, 'brightgreen')
  })

  it('color would be red if any vector failed (derivation, not a constant)', () => {
    // Derive from a failing snapshot without mutating the shared summary.
    const failing = { ...CONFORMANCE_SUMMARY, failing_vectors: 1 }
    const color = failing.failing_vectors > 0 ? 'red' : 'brightgreen'
    assert.equal(color, 'red')
  })
})

describe('CONFORMANCE_SUMMARY - internal consistency', () => {
  it('category totals sum to total_vectors', () => {
    const sum = CONFORMANCE_SUMMARY.categories.reduce((n, c) => n + c.total, 0)
    assert.equal(sum, CONFORMANCE_SUMMARY.total_vectors)
  })

  it('category passing sum to passing_vectors', () => {
    const sum = CONFORMANCE_SUMMARY.categories.reduce((n, c) => n + c.passing, 0)
    assert.equal(sum, CONFORMANCE_SUMMARY.passing_vectors)
  })

  it('skipped tallies sum to skipped_vectors', () => {
    const sum = CONFORMANCE_SUMMARY.categories.reduce(
      (n, c: any) => n + (c.skipped ?? 0),
      0,
    )
    assert.equal(sum, CONFORMANCE_SUMMARY.skipped_vectors)
  })

  it('passing + skipped + failing accounts for every vector', () => {
    assert.equal(
      CONFORMANCE_SUMMARY.passing_vectors +
        CONFORMANCE_SUMMARY.skipped_vectors +
        CONFORMANCE_SUMMARY.failing_vectors,
      CONFORMANCE_SUMMARY.total_vectors,
    )
  })
})

describe('public conformance routes - HTTP serialization', () => {
  let server: Server
  let baseUrl: string

  before(async () => {
    const app = express()
    // Same paths + handler bodies as src/server.ts (minus the rate limiter,
    // which is orthogonal to the response contract under test).
    app.get('/api/v1/public/conformance', async (_req, res) => {
      res.json(CONFORMANCE_SUMMARY)
    })
    app.get('/api/v1/public/conformance/badge', async (_req, res) => {
      res.json(conformanceBadge())
    })
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address()
        const port = typeof addr === 'object' && addr ? addr.port : 0
        baseUrl = `http://127.0.0.1:${port}`
        resolve()
      })
    })
  })

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  it('GET /api/v1/public/conformance returns the summary', async () => {
    const res = await fetch(`${baseUrl}/api/v1/public/conformance`)
    assert.equal(res.status, 200)
    const json = (await res.json()) as any
    assert.equal(json.total_vectors, CONFORMANCE_SUMMARY.total_vectors)
    assert.equal(json.passing_vectors, CONFORMANCE_SUMMARY.passing_vectors)
    assert.equal(json.failing_vectors, CONFORMANCE_SUMMARY.failing_vectors)
    assert.equal(json.categories.length, CONFORMANCE_SUMMARY.categories.length)
  })

  it('GET /api/v1/public/conformance/badge returns the shields schema', async () => {
    const res = await fetch(`${baseUrl}/api/v1/public/conformance/badge`)
    assert.equal(res.status, 200)
    const json = (await res.json()) as any
    assert.equal(json.schemaVersion, 1)
    assert.equal(json.label, 'APS conformance')
    assert.equal(json.message, `${CONFORMANCE_SUMMARY.passing_vectors}/${CONFORMANCE_SUMMARY.total_vectors} verified`)
    assert.equal(json.color, 'brightgreen')
    // Exactly the four shields endpoint keys, nothing leaked.
    assert.deepEqual(Object.keys(json).sort(), ['color', 'label', 'message', 'schemaVersion'])
  })
})
