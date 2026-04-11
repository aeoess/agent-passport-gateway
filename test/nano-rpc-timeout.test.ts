// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Security triage 2026-04-11 fix 3: nanoRpc must never hang forever.
// Payment rails are load-bearing on request handlers and any open
// DB transaction, so a hanging Nano RPC endpoint cannot be allowed to
// pin the call site indefinitely.
// Reference: CODE-AUDIT-2026-04-11.md §2.10.

import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import { nanoRpc, NANO_RPC_TIMEOUT_MS } from '../src/payment-rails/rpc-client.js'

describe('nanoRpc — timeout enforcement (fix 3 of security triage 2026-04-11)', () => {
  it('exports a sane default timeout constant', () => {
    assert.equal(typeof NANO_RPC_TIMEOUT_MS, 'number')
    assert.ok(NANO_RPC_TIMEOUT_MS > 0)
    assert.ok(NANO_RPC_TIMEOUT_MS <= 10_000, 'default should be bounded at 10 seconds')
  })

  it('throws a clear timeout error when fetch aborts (simulated)', async () => {
    // Mock fetch to simulate an AbortSignal timeout. The real timeout
    // path would fire AbortSignal.timeout() after ~5s; to keep the test
    // fast we directly inject an AbortError-like rejection.
    const originalFetch = globalThis.fetch
    const abortErr = new Error('The operation was aborted due to timeout')
    abortErr.name = 'TimeoutError'
    globalThis.fetch = mock.fn(() => Promise.reject(abortErr)) as any

    try {
      let thrown: any = null
      try {
        await nanoRpc('https://example.invalid/rpc', { action: 'version' })
      } catch (e) {
        thrown = e
      }
      assert.ok(thrown, 'nanoRpc must throw on timeout, not return')
      assert.match((thrown as Error).message, /timeout/i)
      assert.match((thrown as Error).message, /Nano RPC/i)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('throws a clear timeout error for AbortError variant', async () => {
    const originalFetch = globalThis.fetch
    const abortErr = new Error('Aborted')
    abortErr.name = 'AbortError'
    globalThis.fetch = mock.fn(() => Promise.reject(abortErr)) as any

    try {
      let thrown: any = null
      try {
        await nanoRpc('https://example.invalid/rpc', { action: 'version' })
      } catch (e) {
        thrown = e
      }
      assert.ok(thrown)
      assert.match((thrown as Error).message, /timeout/i)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('translates generic network errors into Nano RPC errors (not leaked raw)', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = mock.fn(() => Promise.reject(new Error('ECONNREFUSED 127.0.0.1:7076'))) as any

    try {
      let thrown: any = null
      try {
        await nanoRpc('http://127.0.0.1:7076', { action: 'version' })
      } catch (e) {
        thrown = e
      }
      assert.ok(thrown)
      assert.match((thrown as Error).message, /Nano RPC network error/i)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('honors a caller-supplied timeoutMs override', async () => {
    // Verify the opts.timeoutMs path does not throw at invocation (we
    // cannot actually wait for the timeout to fire in a fast unit test,
    // so we check that the function accepts the parameter and still
    // reaches the fetch call).
    const originalFetch = globalThis.fetch
    const callArgs: any[] = []
    globalThis.fetch = mock.fn((url: any, init: any) => {
      callArgs.push({ url, init })
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ version: 'test' }),
      } as any)
    }) as any

    try {
      const result = await nanoRpc('https://example/rpc', { action: 'version' }, { timeoutMs: 1000 })
      assert.deepEqual(result, { version: 'test' })
      assert.equal(callArgs.length, 1)
      assert.ok(callArgs[0].init.signal, 'fetch must be called with an AbortSignal')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('passes an AbortSignal on the default path (no opts)', async () => {
    const originalFetch = globalThis.fetch
    const callArgs: any[] = []
    globalThis.fetch = mock.fn((url: any, init: any) => {
      callArgs.push({ url, init })
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ ok: true }),
      } as any)
    }) as any

    try {
      await nanoRpc('https://example/rpc', { action: 'version' })
      assert.equal(callArgs.length, 1)
      assert.ok(callArgs[0].init.signal, 'default path must also pass an AbortSignal')
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
