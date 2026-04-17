// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Tests migrated from agent-passport-system/tests/gateway-reporter.test.ts
 * (2026-04-17). The reporter is product-integration glue; integration tests
 * for the old adapter `gateway` field are dropped, since that coupling was
 * removed when the SDK adapters were reduced to primitives.
 */

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { reportReceipt, reportEvaluation } from '../../src/sdk-migrated/gateway-reporter.js'
import type { GatewayReporterConfig } from '../../src/sdk-migrated/gateway-reporter.js'
import type { ActionReceipt } from 'agent-passport-system'

let fetchCalls: Array<{ url: string; body: string; headers: Record<string, string> }> = []
const originalFetch = globalThis.fetch

function mockFetch(status = 201) {
  fetchCalls = []
  globalThis.fetch = async (url: any, opts: any) => {
    fetchCalls.push({ url: String(url), body: opts?.body || '', headers: opts?.headers || {} })
    return { ok: status < 400, status, text: async () => 'ok', json: async () => ({}) } as Response
  }
}

function restoreFetch() { globalThis.fetch = originalFetch }

const gwConfig: GatewayReporterConfig = { gatewayUrl: 'https://gateway.test', apiKey: 'aps_live_test123' }

describe('Gateway Receipt Reporter (migrated)', () => {
  beforeEach(() => mockFetch())
  afterEach(() => restoreFetch())

  it('reportReceipt builds correct request body', async () => {
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_test', version: '1.1', timestamp: new Date().toISOString(),
      agentId: 'agent-001', delegationId: 'del-001',
      action: { type: 'test', target: 'tool', scopeUsed: 'tools:test' },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [], signature: 'sig123',
    }
    const r = await reportReceipt(receipt, gwConfig)
    assert.equal(r.ok, true)
    assert.equal(fetchCalls.length, 1)
    const body = JSON.parse(fetchCalls[0].body)
    assert.equal(body.agent_id, 'agent-001')
    assert.equal(body.verdict, 'permit')
    assert.equal(body.signature, 'sig123')
  })

  it('reportReceipt handles network error gracefully', async () => {
    globalThis.fetch = async () => { throw new Error('ECONNREFUSED') }
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_fail', version: '1.1', timestamp: new Date().toISOString(),
      agentId: 'agent-001', delegationId: 'del-001',
      action: { type: 'test', target: 'tool', scopeUsed: 'x' },
      result: { status: 'failure', summary: 'denied' },
      delegationChain: [], signature: 'sig',
    }
    const r = await reportReceipt(receipt, gwConfig)
    assert.equal(r.ok, false)
    assert.ok(r.error?.includes('ECONNREFUSED'))
  })

  it('reportReceipt includes Authorization header', async () => {
    const receipt: ActionReceipt = {
      receiptId: 'rcpt_auth', version: '1.1', timestamp: new Date().toISOString(),
      agentId: 'a', delegationId: 'd',
      action: { type: 't', target: 't', scopeUsed: 's' },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [], signature: 's',
    }
    await reportReceipt(receipt, gwConfig)
    assert.equal(fetchCalls[0].headers['Authorization'], 'Bearer aps_live_test123')
  })

  it('reportEvaluation sends correct payload', async () => {
    const r = await reportEvaluation('agent-001', 'tool_call', 'tools:read', 'permit', 'ok', gwConfig)
    assert.equal(r.ok, true)
    assert.equal(fetchCalls.length, 1)
    assert.ok(fetchCalls[0].url.includes('/api/v1/evaluate'))
    const body = JSON.parse(fetchCalls[0].body)
    assert.equal(body.agent_id, 'agent-001')
    assert.equal(body.scope_required, 'tools:read')
  })
})
