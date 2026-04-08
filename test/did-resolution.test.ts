// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import { resolveDID } from '../src/gateway/did-resolution.js'

// Known Ed25519 key pair for testing
const TEST_PUBLIC_KEY_HEX = '1ef065d8717910ffaba4416a134ad3ff93acc85e541450c461bd0c4a632befde'
const TEST_MULTIBASE = 'z6MkgY2tJzWjzdStMUJfyBtcHpev7v8BoeejhoQ2v5fn2oF3'
const TEST_DID = `did:agentnexus:${TEST_MULTIBASE}`

describe('did:agentnexus resolution', () => {
  it('extracts correct key via local multibase fallback', async () => {
    // Mock fetch to simulate endpoint being down
    const originalFetch = globalThis.fetch
    globalThis.fetch = mock.fn(() => { throw new Error('Network error') }) as any

    try {
      const result = await resolveDID(TEST_DID)
      assert(!('error' in result), `Expected success but got error: ${'error' in result ? result.error : ''}`)
      assert('publicKeyHex' in result)
      assert.equal(result.publicKeyHex, TEST_PUBLIC_KEY_HEX)
      assert.equal(result.method, 'agentnexus')
      assert.equal(result.resolvedVia, 'local-multibase')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('falls back to local extraction when endpoint is unreachable', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = mock.fn(() => Promise.reject(new Error('ECONNREFUSED'))) as any

    try {
      const result = await resolveDID(TEST_DID)
      assert(!('error' in result), `Expected success but got error: ${'error' in result ? result.error : ''}`)
      assert('publicKeyHex' in result)
      assert.equal(result.publicKeyHex, TEST_PUBLIC_KEY_HEX)
      assert.equal(result.resolvedVia, 'local-multibase')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('prefers AgentID endpoint when available', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = mock.fn(() => Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ publicKeyHex: TEST_PUBLIC_KEY_HEX }),
    })) as any

    try {
      const result = await resolveDID(TEST_DID)
      assert(!('error' in result))
      assert('publicKeyHex' in result)
      assert.equal(result.publicKeyHex, TEST_PUBLIC_KEY_HEX)
      assert.equal(result.resolvedVia, 'agentid-endpoint')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles endpoint returning multibase key format', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = mock.fn(() => Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ publicKeyMultibase: TEST_MULTIBASE }),
    })) as any

    try {
      const result = await resolveDID(TEST_DID)
      assert(!('error' in result))
      assert('publicKeyHex' in result)
      assert.equal(result.publicKeyHex, TEST_PUBLIC_KEY_HEX)
      assert.equal(result.resolvedVia, 'agentid-endpoint')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('returns error for unsupported DID method', async () => {
    const result = await resolveDID('did:unknown:abc123')
    assert('error' in result)
    assert.match(result.error, /Unsupported DID method/)
  })

  it('returns error for invalid DID format', async () => {
    const result = await resolveDID('not-a-did')
    assert('error' in result)
    assert.match(result.error, /Invalid DID format/)
  })

  it('returns error when both endpoint and local extraction fail', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = mock.fn(() => Promise.reject(new Error('down'))) as any

    try {
      const result = await resolveDID('did:agentnexus:invalidmultibase')
      assert('error' in result)
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
