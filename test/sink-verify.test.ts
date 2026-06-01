// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Sink-side APS verifier - two-sided enforcement tests
// ══════════════════════════════════════════════════════════════════
// Mandatory cases (with negatives):
//   1. an unauthorized action is DROPPED at the sink
//   2. an authorized action PASSES
//   3. a bypass attempt is LOGGED
//   4. the verifier works fully OFFLINE (no network)
//
// Receipts are built with the SDK (createDelegation + createReceipt +
// generateKeyPair), so the signature the sink verifies is a real
// Ed25519 signature, not a fixture string.

import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  generateKeyPair,
  createDelegation,
  createReceipt,
} from 'agent-passport-system'
import type { ActionReceipt, Delegation } from 'agent-passport-system'

import {
  verifySinkOffline,
  type SinkTrustSet,
} from '../src/gateway/sink-verify/verifier.js'
import {
  MemoryBypassSink,
} from '../src/gateway/sink-verify/bypass-log.js'
import {
  expressSinkVerifier,
  installBypassGuard,
} from '../src/gateway/sink-verify/middleware-express.js'
import {
  createInternalSinkVerifier,
} from '../src/gateway/sink-verify/internal-http-sink.js'

// ── Fixture builders ──────────────────────────────────────────────

interface Fixture {
  agentKey: { publicKey: string; privateKey: string }
  principalKey: { publicKey: string; privateKey: string }
  delegation: Delegation
  receipt: ActionReceipt
}

function buildFixture(opts?: {
  scope?: string[]
  scopeUsed?: string
  actionType?: string
  spendAmount?: number
}): Fixture {
  const principalKey = generateKeyPair()
  const agentKey = generateKeyPair()
  const scope = opts?.scope ?? ['data:read', 'tool:search:query']
  const scopeUsed = opts?.scopeUsed ?? 'data:read'
  const actionType = opts?.actionType ?? 'data:read'

  const delegation = createDelegation({
    delegatedTo: agentKey.publicKey,
    delegatedBy: principalKey.publicKey,
    scope,
    spendLimit: 100,
    expiresInHours: 24,
    privateKey: principalKey.privateKey,
  })

  const receipt = createReceipt({
    agentId: agentKey.publicKey,
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: actionType,
      target: 'db://customers',
      scopeUsed,
      spend: { amount: opts?.spendAmount ?? 5, currency: 'USD' },
    },
    result: { status: 'success', summary: 'ok' },
    delegationChain: [delegation.delegationId],
    privateKey: agentKey.privateKey,
  })

  return { agentKey, principalKey, delegation, receipt }
}

// Minimal Express req/res doubles for middleware tests (no server, no net).
function makeReq(opts: { body?: any; headers?: Record<string, any>; method?: string; path?: string }): any {
  return {
    body: opts.body,
    headers: opts.headers ?? {},
    method: opts.method ?? 'POST',
    path: opts.path ?? '/protected',
  }
}
function makeRes(): any {
  const res: any = {
    statusCode: 200,
    body: undefined,
    locals: {},
    status(code: number) { this.statusCode = code; return this },
    json(payload: any) { this.body = payload; return this },
  }
  return res
}

// ── 1. Unauthorized action is dropped at the sink ─────────────────

describe('sink verifier - unauthorized actions are dropped', () => {
  it('drops a forged receipt (signature does not match the agent key)', async () => {
    const f = buildFixture()
    // The sink trusts a DIFFERENT key than the one that signed the receipt.
    const wrongKey = generateKeyPair().publicKey
    const trust: SinkTrustSet = { agentPublicKey: wrongKey, grantedScopes: f.delegation.scope }

    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'reject')
    assert.equal(verdict.signature_valid, false)
    assert.ok(verdict.violations.some(v => v.startsWith('signature')))
  })

  it('drops a receipt whose scope is not in the granted set', async () => {
    // The agent legitimately holds a broad delegation and minted a valid
    // receipt for admin:delete. The SINK independently grants only
    // data:read - this is the two-sided point: the receiving API
    // restricts past what the source-side delegation allowed.
    const f = buildFixture({
      scope: ['data:read', 'admin:delete'],
      scopeUsed: 'admin:delete',
      actionType: 'admin:delete',
    })
    const trust: SinkTrustSet = {
      agentPublicKey: f.agentKey.publicKey,
      grantedScopes: ['data:read'],
    }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'reject')
    // Signature is authentic, so the reject is scope, not forgery.
    assert.equal(verdict.signature_valid, true)
    assert.ok(verdict.violations.some(v => v.startsWith('scope_denied')))
  })

  it('drops a receipt bound to a delegation the sink does not expect', async () => {
    const f = buildFixture()
    const trust: SinkTrustSet = {
      agentPublicKey: f.agentKey.publicKey,
      grantedScopes: f.delegation.scope,
      expectedDelegationId: 'some-other-delegation',
    }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'reject')
    assert.ok(verdict.violations.some(v => v.startsWith('delegation_mismatch')))
  })

  it('drops a receipt whose spend exceeds the remaining budget', async () => {
    const f = buildFixture({ spendAmount: 50 })
    const trust: SinkTrustSet = {
      agentPublicKey: f.agentKey.publicKey,
      grantedScopes: f.delegation.scope,
      remainingSpend: 10,
    }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'reject')
    assert.ok(verdict.violations.some(v => v.startsWith('spend_exceeded')))
  })

  it('rejects (never throws) on a malformed receipt', async () => {
    const trust: SinkTrustSet = { agentPublicKey: generateKeyPair().publicKey }
    const verdict = await verifySinkOffline({} as any, trust)
    assert.equal(verdict.verdict, 'reject')
    assert.deepEqual(verdict.violations, ['malformed_receipt'])
  })
})

// ── 2. Authorized action passes ───────────────────────────────────

describe('sink verifier - authorized actions pass', () => {
  it('accepts an authentic, in-scope, in-budget receipt', async () => {
    const f = buildFixture({ spendAmount: 5 })
    const trust: SinkTrustSet = {
      agentPublicKey: f.agentKey.publicKey,
      grantedScopes: f.delegation.scope,
      expectedDelegationId: f.delegation.delegationId,
      remainingSpend: 100,
    }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'accept', verdict.reason)
    assert.equal(verdict.signature_valid, true)
    assert.equal(verdict.violations.length, 0)
    assert.equal(verdict.agent_id, f.agentKey.publicKey)
  })

  it('accepts a hierarchical tool scope via the SDK-backed matcher', async () => {
    const f = buildFixture({
      scope: ['tool:search:query'],
      scopeUsed: 'tool:search:query',
      actionType: 'tool:search:query',
    })
    const trust: SinkTrustSet = {
      agentPublicKey: f.agentKey.publicKey,
      grantedScopes: ['tool:search:query'],
    }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'accept', verdict.reason)
  })

  it('accepts in signature-only mode when no granted scopes are pinned', async () => {
    const f = buildFixture()
    const trust: SinkTrustSet = { agentPublicKey: f.agentKey.publicKey }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'accept', verdict.reason)
  })
})

// ── 3. Bypass attempts are logged ─────────────────────────────────

describe('sink verifier - bypass attempts are logged', () => {
  it('records a reject event when the Express middleware drops a request', async () => {
    const f = buildFixture({ scope: ['data:read', 'admin:delete'], scopeUsed: 'admin:delete', actionType: 'admin:delete' })
    const bypassSink = new MemoryBypassSink()
    const mw = expressSinkVerifier({
      resolveTrust: () => ({ agentPublicKey: f.agentKey.publicKey, grantedScopes: ['data:read'] }),
      bypassSink,
    })

    const req = makeReq({ body: { receipt: f.receipt } })
    const res = makeRes()
    let nextCalled = false
    await mw(req, res, () => { nextCalled = true })

    assert.equal(nextCalled, false)
    assert.equal(res.statusCode, 403)
    assert.equal(res.body.verdict, 'reject')
    assert.equal(bypassSink.size, 1)
    assert.equal(bypassSink.recent()[0].reason, 'rejected')
    assert.equal(bypassSink.recent()[0].agent_id, f.agentKey.publicKey)
  })

  it('records a no_receipt reject when the request carries no receipt', async () => {
    const bypassSink = new MemoryBypassSink()
    const mw = expressSinkVerifier({
      resolveTrust: () => ({ agentPublicKey: generateKeyPair().publicKey }),
      bypassSink,
    })
    const req = makeReq({ body: {} })
    const res = makeRes()
    await mw(req, res, () => { /* should not run */ })
    assert.equal(res.statusCode, 403)
    assert.equal(bypassSink.size, 1)
    assert.deepEqual(bypassSink.recent()[0].violations, ['no_receipt'])
  })

  it('logs a missing_verdict bypass when the protected handler is reached unverified', async () => {
    const bypassSink = new MemoryBypassSink()
    let handlerRan = false
    const guarded = installBypassGuard(
      (_req: any, res: any) => { handlerRan = true; res.status(200).json({ ok: true }) },
      bypassSink,
    )
    // Reach the handler directly - the verifier middleware never ran, so
    // the request carries no VERIFIED marker. This is the direct-call
    // bypass case.
    const req = makeReq({ body: {} })
    const res = makeRes()
    guarded(req, res, () => {})

    assert.equal(handlerRan, false)
    assert.equal(res.statusCode, 403)
    assert.equal(bypassSink.size, 1)
    assert.equal(bypassSink.recent()[0].reason, 'missing_verdict')
  })

  it('lets a verified request through the bypass guard', async () => {
    const f = buildFixture()
    const bypassSink = new MemoryBypassSink()
    const mw = expressSinkVerifier({
      resolveTrust: () => ({ agentPublicKey: f.agentKey.publicKey, grantedScopes: f.delegation.scope }),
      bypassSink,
    })
    let handlerRan = false
    const guarded = installBypassGuard(
      (_req: any, res: any) => { handlerRan = true; res.status(200).json({ ok: true }) },
      bypassSink,
    )

    const req = makeReq({ body: { receipt: f.receipt } })
    const res = makeRes()
    await mw(req, res, () => { guarded(req, res, () => {}) })

    assert.equal(handlerRan, true)
    assert.equal(res.statusCode, 200)
    // Accept path logs nothing.
    assert.equal(bypassSink.size, 0)
  })

  it('bounds the in-memory bypass log (no unbounded growth)', () => {
    const sink = new MemoryBypassSink(3)
    for (let i = 0; i < 10; i++) {
      sink.record({ at: new Date().toISOString(), reason: 'rejected', agent_id: `a${i}`, receipt_id: '', scope_required: '', violations: [] })
    }
    assert.equal(sink.size, 3)
    // Keeps the most recent.
    assert.equal(sink.recent()[2].agent_id, 'a9')
  })
})

// ── 4. The verifier works fully offline (no network) ──────────────

describe('sink verifier - fully offline', () => {
  let originalFetch: typeof globalThis.fetch
  let fetchCalls: number

  beforeEach(() => {
    originalFetch = globalThis.fetch
    fetchCalls = 0
    // Any network call during a verify is a hard failure: replace fetch
    // with a tripwire that throws.
    ;(globalThis as any).fetch = (...args: any[]) => {
      fetchCalls++
      throw new Error('network access during sink verification is forbidden')
    }
  })
  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('verifies an authentic receipt with zero network calls', async () => {
    const f = buildFixture()
    const trust: SinkTrustSet = {
      agentPublicKey: f.agentKey.publicKey,
      grantedScopes: f.delegation.scope,
    }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'accept', verdict.reason)
    assert.equal(fetchCalls, 0)
  })

  it('drops a forged receipt with zero network calls', async () => {
    const f = buildFixture()
    const trust: SinkTrustSet = { agentPublicKey: generateKeyPair().publicKey }
    const verdict = await verifySinkOffline(f.receipt, trust)
    assert.equal(verdict.verdict, 'reject')
    assert.equal(fetchCalls, 0)
  })

  it('internal-HTTP-sink verifier (inline keys) makes no network call', async () => {
    const f = buildFixture()
    const keys = new Map([[f.agentKey.publicKey, f.agentKey.publicKey]])
    const grantedScopes = new Map([[f.agentKey.publicKey, f.delegation.scope]])
    const internal = createInternalSinkVerifier({
      keyStore: { mode: 'inline', keys, grantedScopes },
    })

    const accept = await internal.verify(f.receipt)
    assert.equal(accept.verdict, 'accept', accept.reason)
    assert.equal(fetchCalls, 0)

    // Unknown agent → reject, logged, still no network.
    const stranger = buildFixture()
    const reject = await internal.verify(stranger.receipt)
    assert.equal(reject.verdict, 'reject')
    assert.deepEqual(reject.violations, ['untrusted_agent'])
    assert.equal(internal.bypassSink instanceof MemoryBypassSink, true)
    assert.equal((internal.bypassSink as MemoryBypassSink).size, 1)
    assert.equal(fetchCalls, 0)
  })
})
