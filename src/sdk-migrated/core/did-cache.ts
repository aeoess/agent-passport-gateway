// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// DID Resolution Cache — TTL-based wrapper around SDK verifyEntityChain
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). The SDK retains
// verifyEntityChain as a pure live-resolution primitive (and the
// computeSenderId helper). The TTL-based cache plus the cache-with-
// staleness fallback semantics live here.
//
// TTL choice and cross-tenant isolation are operational concerns —
// product policy, not protocol primitives. Each gateway tenant
// instantiates its own DIDCache.
// ══════════════════════════════════════════════════════════════════════

import { verifyEntityChain } from 'agent-passport-system'
import type {
  DIDResolutionCacheEntry, EntityVerificationResult,
  PublicProofSurface,
} from 'agent-passport-system'

const DEFAULT_CACHE_TTL_MS = 3600_000 // 1 hour

export interface DIDCacheOptions {
  /** Default per-entry TTL in ms. Override per call to put(). */
  defaultTtlMs?: number
}

export class DIDCache {
  private readonly entries = new Map<string, DIDResolutionCacheEntry>()
  private readonly defaultTtlMs: number

  constructor(opts: DIDCacheOptions = {}) {
    this.defaultTtlMs = opts.defaultTtlMs ?? DEFAULT_CACHE_TTL_MS
  }

  /** Cache a successful DID resolution. */
  put(did: string, publicKey: string, ttlMs: number = this.defaultTtlMs): DIDResolutionCacheEntry {
    const now = new Date()
    const entry: DIDResolutionCacheEntry = {
      did,
      publicKey,
      resolvedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      status: 'live',
    }
    this.entries.set(did, entry)
    return entry
  }

  /** Look up a cached entry; null if missing or expired. */
  get(did: string): DIDResolutionCacheEntry | null {
    const entry = this.entries.get(did)
    if (!entry) return null
    if (new Date(entry.expiresAt).getTime() < Date.now()) {
      this.entries.delete(did)
      return null
    }
    return { ...entry, status: 'cached' }
  }

  clear(): void {
    this.entries.clear()
  }

  size(): number {
    return this.entries.size
  }
}

// ══════════════════════════════════════════════════════════════════════
// Cached entity-verification wrapper
// ══════════════════════════════════════════════════════════════════════

export interface CachedVerifyEntityChainOptions {
  entityId: string
  /** Cache instance to consult and write to. */
  cache: DIDCache
  /** When live resolution fails, fall back to a (possibly stale) cached
   *  entry. Defaults to true — preserves the original "cache-with-
   *  staleness" semantic from the WG-adopted behavior. */
  allowCachedFallback?: boolean
  /** Per-call TTL override for new cache entries written on success. */
  cacheTtlMs?: number
}

/**
 * Run verifyEntityChain through the cache. On a successful live resolve,
 * we record the (did → publicKey) in the cache. On a failed live resolve,
 * if a cached entry exists and allowCachedFallback is true, we mark the
 * result as cached and continue with the cached public key.
 *
 * The SDK's verifyEntityChain is the canonical ground truth — this
 * wrapper just adds the operational caching policy.
 */
export async function verifyEntityChainCached(
  did: string,
  entityLookup: (entityId: string) => Promise<PublicProofSurface | null>,
  opts: CachedVerifyEntityChainOptions,
): Promise<EntityVerificationResult> {
  const result = await verifyEntityChain(did, entityLookup, { entityId: opts.entityId })

  // Successful live resolve → populate cache for future calls.
  if (result.didResolutionStatus === 'live' && result.resolvedPublicKey) {
    opts.cache.put(did, result.resolvedPublicKey, opts.cacheTtlMs)
    return result
  }

  // Live resolve failed → consider cache fallback.
  if (
    (opts.allowCachedFallback ?? true) &&
    result.didResolutionStatus === 'failed'
  ) {
    const cached = opts.cache.get(did)
    if (cached) {
      // Re-run entity lookup with the cached key; mark status cached.
      let entity: PublicProofSurface | null = null
      const errors: string[] = []
      try {
        entity = await entityLookup(opts.entityId)
      } catch (e: any) {
        errors.push(`Entity lookup failed: ${e.message || e}`)
      }
      const senderId = computeSenderIdFromHex(cached.publicKey)

      if (!entity) {
        errors.push(`Entity "${opts.entityId}" not found or lookup failed`)
        return {
          verified: false,
          didResolutionStatus: 'cached',
          resolvedPublicKey: cached.publicKey,
          entity: null,
          resolvedAt: cached.resolvedAt,
          cachedAt: cached.resolvedAt,
          senderId,
          errors,
        }
      }
      if (entity.status !== 'active') {
        errors.push(`Entity "${opts.entityId}" status is "${entity.status}", not "active"`)
        return {
          verified: false,
          didResolutionStatus: 'cached',
          resolvedPublicKey: cached.publicKey,
          entity,
          resolvedAt: cached.resolvedAt,
          cachedAt: cached.resolvedAt,
          senderId,
          errors,
        }
      }
      return {
        verified: true,
        didResolutionStatus: 'cached',
        resolvedPublicKey: cached.publicKey,
        entity,
        resolvedAt: cached.resolvedAt,
        cachedAt: cached.resolvedAt,
        senderId,
        errors: [],
      }
    }
  }

  return result
}

// Local sender-id derivation to avoid circular import — same algorithm
// as agent-passport-system computeSenderId (Trunc16(SHA-256(pubkey))).
import { createHash } from 'node:crypto'
function computeSenderIdFromHex(publicKeyHex: string): string {
  return createHash('sha256')
    .update(Buffer.from(publicKeyHex, 'hex'))
    .digest().subarray(0, 16).toString('hex')
}
