// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Wallet → Agent Reverse Index
// ══════════════════════════════════════════════════════════════════
//
// SkyeProfile and other wallet-first orchestrators need to start from
// an externally observed wallet address and look up which APS agent
// (if any) has it bound. The forward direction (agent → wallet_ref)
// already exists on /public/trust/{agent_id}. This module provides the
// reverse direction.
//
// Storage: in-memory map keyed by lowercased address. Wallet bindings
// are small (typically O(1) per agent across O(thousands) of agents),
// and rebuilding from agents.metadata on boot is cheap. If wallet count
// grows past ~100k we revisit with a SQLite index.
//
// Multi-tenant: addresses are global namespace (an Ethereum address is
// globally unique). The index records both tenant_id and agent_id so
// the lookup result can resolve back through the existing trust profile
// builder which is tenant-aware.
//
// Source of truth: agents.metadata.bound_wallets in SQLite. The index
// is a derived view, fully rebuildable from the table. recordBoundWallets()
// is called after agent enrollment / metadata updates. rebuildFromDb() is
// called at gateway boot.
// ══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'

export interface BoundWalletEntry {
  chain: string
  address: string
  bound_at?: string
  binding_signature?: string
  binding_sig?: string
}

export interface ReverseIndexHit {
  tenant_id: string
  agent_id: string
  entry: {
    chain: string
    address: string
    bound_at: string
    binding_sig: string
  }
}

// Lowercased address → first matching record. The first wins; later binds
// of the same address by other agents become collisions surfaced separately
// for observability but are ignored for routing (rare in practice).
const indexByAddress: Map<string, ReverseIndexHit> = new Map()
const collisions: Map<string, ReverseIndexHit[]> = new Map()

function normalizeAddress(addr: string): string {
  return (addr || '').trim().toLowerCase()
}

function normalizeEntry(raw: any): BoundWalletEntry | null {
  if (!raw || typeof raw !== 'object') return null
  if (typeof raw.chain !== 'string' || typeof raw.address !== 'string') return null
  if (raw.address.length === 0) return null
  return {
    chain: raw.chain,
    address: raw.address,
    bound_at: typeof raw.bound_at === 'string' ? raw.bound_at : undefined,
    binding_signature: typeof raw.binding_signature === 'string' ? raw.binding_signature : undefined,
    binding_sig: typeof raw.binding_sig === 'string' ? raw.binding_sig : undefined,
  }
}

/**
 * Record an agent's full bound_wallets list. Replaces any prior entries
 * recorded for the same (tenant, agent) pair so updates are idempotent.
 */
export function recordBoundWallets(opts: {
  tenant_id: string
  agent_id: string
  bound_wallets: unknown
}): void {
  if (!Array.isArray(opts.bound_wallets)) return
  // Drop any prior entries owned by this (tenant, agent) before re-adding
  removeAgent(opts.tenant_id, opts.agent_id)

  for (const raw of opts.bound_wallets) {
    const entry = normalizeEntry(raw)
    if (!entry) continue
    const key = normalizeAddress(entry.address)
    if (!key) continue
    const hit: ReverseIndexHit = {
      tenant_id: opts.tenant_id,
      agent_id: opts.agent_id,
      entry: {
        chain: entry.chain,
        address: entry.address,
        bound_at: entry.bound_at || '',
        binding_sig: entry.binding_signature || entry.binding_sig || '',
      },
    }
    const existing = indexByAddress.get(key)
    if (!existing) {
      indexByAddress.set(key, hit)
    } else if (existing.tenant_id !== opts.tenant_id || existing.agent_id !== opts.agent_id) {
      // Same address bound by a different agent — keep the first, record the
      // collision for observability but do not change routing.
      const list = collisions.get(key) || []
      if (!list.some(h => h.tenant_id === hit.tenant_id && h.agent_id === hit.agent_id)) {
        list.push(hit)
        collisions.set(key, list)
      }
    }
  }
}

/**
 * Remove all entries owned by a given (tenant, agent) pair. Used when an
 * agent re-registers, updates metadata, or is deleted. Promotes a
 * collision-tracked alternative if one exists.
 */
export function removeAgent(tenant_id: string, agent_id: string): void {
  for (const [key, hit] of indexByAddress.entries()) {
    if (hit.tenant_id === tenant_id && hit.agent_id === agent_id) {
      indexByAddress.delete(key)
      // If there's a collision-tracked alternative, promote it
      const alts = collisions.get(key)
      if (alts && alts.length > 0) {
        indexByAddress.set(key, alts[0])
        const remaining = alts.slice(1)
        if (remaining.length > 0) collisions.set(key, remaining)
        else collisions.delete(key)
      }
    }
  }
  // Also drop any collision entries owned by the same (tenant, agent)
  for (const [key, alts] of collisions.entries()) {
    const filtered = alts.filter(h => !(h.tenant_id === tenant_id && h.agent_id === agent_id))
    if (filtered.length === 0) collisions.delete(key)
    else if (filtered.length !== alts.length) collisions.set(key, filtered)
  }
}

/** Lookup an address. Case-insensitive. Returns null if not bound. */
export function lookupByAddress(address: string): ReverseIndexHit | null {
  const key = normalizeAddress(address)
  if (!key) return null
  return indexByAddress.get(key) || null
}

/** Test/admin only — number of unique addresses currently indexed. */
export function reverseIndexSize(): number {
  return indexByAddress.size
}

/** Test/admin only — drop all in-memory state. */
export function clearReverseIndex(): void {
  indexByAddress.clear()
  collisions.clear()
}

/**
 * Rebuild the entire index from agents.metadata.bound_wallets in SQLite.
 * Called at gateway boot so the index survives restart, and after any
 * bulk migration that touches metadata directly.
 */
export function rebuildFromDb(db: Database.Database): { agentsScanned: number; addressesIndexed: number } {
  clearReverseIndex()
  let agentsScanned = 0
  try {
    const rows = db.prepare(
      `SELECT tenant_id, agent_id, metadata FROM agents WHERE metadata IS NOT NULL AND status = 'active'`
    ).all() as Array<{ tenant_id: string; agent_id: string; metadata: string }>
    for (const row of rows) {
      agentsScanned++
      let meta: any
      try {
        meta = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata
      } catch {
        continue
      }
      if (!meta || !Array.isArray(meta.bound_wallets)) continue
      recordBoundWallets({
        tenant_id: row.tenant_id,
        agent_id: row.agent_id,
        bound_wallets: meta.bound_wallets,
      })
    }
  } catch {
    // Schema may be missing the column on first deploy. Index stays empty.
  }
  return { agentsScanned, addressesIndexed: indexByAddress.size }
}
