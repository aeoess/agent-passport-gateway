// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DID Resolution — multi-method resolver for the gateway.
 *
 * Supported methods:
 *   - did:agentnexus — Harold's AgentID (getagentid.dev).
 *     Primary: POST to AgentID verify endpoint to extract Ed25519 key.
 *     Fallback: local multibase+multicodec extraction (z6Mk prefix, same as did:key).
 */

import { multibaseToHex } from 'agent-passport-system'

// ── Types ──

export interface DIDResolutionResult {
  did: string
  publicKeyHex: string
  method: string
  resolvedVia: 'agentid-endpoint' | 'local-multibase'
  error?: string
}

export interface DIDResolutionError {
  did: string
  error: string
  method: string
}

// ── Constants ──

const AGENTID_VERIFY_URL = 'https://getagentid.dev/api/v1/agents/verify'
const AGENTID_TIMEOUT_MS = 5_000

// ── Public API ──

/**
 * Resolve a DID to its Ed25519 public key (hex).
 * Currently supports: did:agentnexus
 */
export async function resolveDID(did: string): Promise<DIDResolutionResult | DIDResolutionError> {
  if (typeof did !== 'string' || !did.startsWith('did:')) {
    return { did, error: 'Invalid DID format', method: 'unknown' }
  }

  const parts = did.split(':')
  const method = parts[1]

  switch (method) {
    case 'agentnexus':
      return resolveAgentNexus(did, parts)
    default:
      return { did, error: `Unsupported DID method: ${method}`, method }
  }
}

// ── did:agentnexus ──

async function resolveAgentNexus(
  did: string,
  parts: string[]
): Promise<DIDResolutionResult | DIDResolutionError> {
  // Try the AgentID endpoint first
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), AGENTID_TIMEOUT_MS)

    const res = await fetch(AGENTID_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did }),
      signal: controller.signal,
    })
    clearTimeout(timeout)

    if (res.ok) {
      const data = await res.json() as Record<string, any>
      // Extract Ed25519 public key from response
      const publicKeyHex = extractKeyFromAgentIdResponse(data)
      if (publicKeyHex) {
        return { did, publicKeyHex, method: 'agentnexus', resolvedVia: 'agentid-endpoint' }
      }
    }
  } catch {
    // Endpoint unreachable or timed out, fall through to local extraction
  }

  // Fallback: local multibase+multicodec extraction (z6Mk prefix)
  return resolveAgentNexusLocal(did, parts)
}

/**
 * Extract public key hex from the AgentID verify response.
 * Looks for common key field patterns in the response JSON.
 */
function extractKeyFromAgentIdResponse(data: Record<string, any>): string | null {
  // Direct hex key field
  if (data.publicKeyHex && typeof data.publicKeyHex === 'string') {
    return data.publicKeyHex
  }
  // Multibase field (z6Mk... format)
  if (data.publicKeyMultibase && typeof data.publicKeyMultibase === 'string') {
    try {
      return multibaseToHex(data.publicKeyMultibase)
    } catch { return null }
  }
  // Nested in verificationMethod (W3C DID Document style)
  const vm = data.verificationMethod?.[0] || data.didDocument?.verificationMethod?.[0]
  if (vm) {
    if (vm.publicKeyHex) return vm.publicKeyHex
    if (vm.publicKeyMultibase) {
      try {
        return multibaseToHex(vm.publicKeyMultibase)
      } catch { return null }
    }
  }
  // Key in agent object
  if (data.agent?.publicKeyHex) return data.agent.publicKeyHex
  if (data.agent?.publicKeyMultibase) {
    try {
      return multibaseToHex(data.agent.publicKeyMultibase)
    } catch { return null }
  }
  return null
}

/**
 * Local fallback: extract Ed25519 key from the DID identifier using
 * multibase+multicodec (same as did:key with z6Mk prefix).
 */
function resolveAgentNexusLocal(
  did: string,
  parts: string[]
): DIDResolutionResult | DIDResolutionError {
  // did:agentnexus:z6Mk... — identifier is parts[2]
  const identifier = parts.slice(2).join(':')
  if (!identifier) {
    return { did, error: 'Missing identifier in did:agentnexus DID', method: 'agentnexus' }
  }

  if (!identifier.startsWith('z')) {
    return { did, error: 'did:agentnexus identifier must use z-prefix (base58btc) multibase', method: 'agentnexus' }
  }

  try {
    const publicKeyHex = multibaseToHex(identifier)
    return { did, publicKeyHex, method: 'agentnexus', resolvedVia: 'local-multibase' }
  } catch (err: any) {
    return { did, error: `Local multibase extraction failed: ${err.message}`, method: 'agentnexus' }
  }
}
