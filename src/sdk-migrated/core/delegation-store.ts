// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// DelegationStore — stateful registries extracted from SDK delegation.ts
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). The SDK retains the pure
// primitives (createDelegation, verifyDelegation, subDelegate, scopeCovers,
// scopeAuthorizes, verifyRevocation, verifyReceipt). The module-scope
// revocation/receipt/chain/spend Maps, cascade revocation, chain validation,
// receipt storage and spend accumulation now live here.
//
// Instantiate one DelegationStore per enforcement context. Each store is
// self-contained — there is no shared global state across stores.
// ══════════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import {
  canonicalize, sign, verify, verifyDelegation, scopeAuthorizes,
} from 'agent-passport-system'
import type {
  Delegation, ActionReceipt, RevocationRecord,
  CascadeRevocationResult, DelegationChainValidation, DelegationChainLink,
  RevocationEvent,
} from 'agent-passport-system'

const DEFAULT_MAX_REGISTRY_SIZE = 100_000

interface ChainEntry {
  delegation: Delegation
  parentId: string | null
  childIds: Set<string>
}

export interface CreateReceiptOptions {
  agentId: string
  delegationId: string
  delegation: Delegation
  action: ActionReceipt['action']
  result: ActionReceipt['result']
  delegationChain: string[]
  privateKey: string
}

export interface DelegationStoreOptions {
  /** Registry size cap. Defaults to 100k entries. Oldest entries evicted on overflow. */
  maxRegistrySize?: number
}

/**
 * Stateful complement to the SDK's pure delegation primitives.
 *
 * Holds four registries that together give the gateway a view of every
 * delegation it has minted or witnessed:
 *   - chainRegistry   — parent/child topology for cascade revocation
 *   - revocationRegistry — active revocations, signed
 *   - receiptStore    — signed action receipts
 *   - spendTracker    — cumulative per-delegation spend
 *
 * Plus a listener registration mechanism for revocation events.
 */
export class DelegationStore {
  private readonly revocationRegistry = new Map<string, RevocationRecord>()
  private readonly receiptStore: ActionReceipt[] = []
  private readonly chainRegistry = new Map<string, ChainEntry>()
  private readonly spendTracker = new Map<string, number>()
  private readonly revocationListeners: ((event: RevocationEvent) => void)[] = []
  private readonly maxRegistrySize: number

  constructor(opts: DelegationStoreOptions = {}) {
    this.maxRegistrySize = opts.maxRegistrySize ?? DEFAULT_MAX_REGISTRY_SIZE
  }

  // ─────────────────────────────────────────────────────────────
  // Chain tracking — call after signing delegations through the SDK
  // ─────────────────────────────────────────────────────────────

  /**
   * Register a root delegation (no parent) in the chain registry.
   * Idempotent — re-registering preserves existing child links.
   */
  registerRoot(delegation: Delegation): void {
    this.evictIfFull()
    const existing = this.chainRegistry.get(delegation.delegationId)
    if (existing) {
      existing.delegation = delegation
      existing.parentId = null
      return
    }
    this.chainRegistry.set(delegation.delegationId, {
      delegation,
      parentId: null,
      childIds: new Set(),
    })
  }

  /**
   * Register a sub-delegation under its parent. Both registries are updated.
   */
  registerSubDelegation(child: Delegation, parent: Delegation): void {
    this.evictIfFull()
    const childEntry: ChainEntry = this.chainRegistry.get(child.delegationId) ?? {
      delegation: child,
      parentId: parent.delegationId,
      childIds: new Set(),
    }
    childEntry.delegation = child
    childEntry.parentId = parent.delegationId
    this.chainRegistry.set(child.delegationId, childEntry)

    const parentEntry = this.chainRegistry.get(parent.delegationId)
    if (parentEntry) {
      parentEntry.childIds.add(child.delegationId)
    } else {
      this.chainRegistry.set(parent.delegationId, {
        delegation: parent,
        parentId: null,
        childIds: new Set([child.delegationId]),
      })
    }
  }

  private evictIfFull(): void {
    if (this.chainRegistry.size >= this.maxRegistrySize) {
      const oldest = this.chainRegistry.keys().next().value
      if (oldest) this.chainRegistry.delete(oldest)
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Revocation listeners
  // ─────────────────────────────────────────────────────────────

  onRevocation(listener: (event: RevocationEvent) => void): () => void {
    this.revocationListeners.push(listener)
    return () => {
      const idx = this.revocationListeners.indexOf(listener)
      if (idx >= 0) this.revocationListeners.splice(idx, 1)
    }
  }

  private emitRevocation(event: RevocationEvent): void {
    for (const listener of this.revocationListeners) {
      try { listener(event) } catch { /* listener errors don't break revocation */ }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Revocation
  // ─────────────────────────────────────────────────────────────

  revokeDelegation(
    delegationId: string,
    revokedBy: string,
    reason: string,
    privateKey: string,
  ): RevocationRecord {
    const entry = this.chainRegistry.get(delegationId)
    if (!entry) {
      // Delegation not in local registry — still record, but cannot verify chain ancestry.
    } else if (entry.delegation.delegatedBy !== revokedBy) {
      let parentId = entry.parentId
      let authorized = false
      while (parentId) {
        const parent = this.chainRegistry.get(parentId)
        if (parent?.delegation.delegatedBy === revokedBy) { authorized = true; break }
        parentId = parent?.parentId ?? null
      }
      if (!authorized) {
        throw new Error(`Revocation denied: "${revokedBy}" is not the delegator or chain ancestor`)
      }
    }

    const record: Omit<RevocationRecord, 'signature'> = {
      revocationId: 'rev_' + uuidv4().slice(0, 12),
      delegationId,
      revokedBy,
      revokedAt: new Date().toISOString(),
      reason,
    }

    const canonical = canonicalize(record)
    const signature = sign(canonical, privateKey)
    const revocation: RevocationRecord = { ...record, signature }

    this.revocationRegistry.set(delegationId, revocation)
    return revocation
  }

  /** Revoke a delegation and ALL its descendants (A→B→C: revoke A cascades to B and C). */
  cascadeRevoke(
    delegationId: string,
    revokedBy: string,
    reason: string,
    privateKey: string,
  ): CascadeRevocationResult {
    const rootRevocation = this.revokeDelegation(delegationId, revokedBy, reason, privateKey)
    this.emitRevocation({ type: 'direct', revocation: rootRevocation })

    const cascaded: RevocationRecord[] = []
    const visited = new Set<string>()

    const revokeDescendants = (parentId: string): void => {
      const entry = this.chainRegistry.get(parentId)
      if (!entry) return
      for (const childId of entry.childIds) {
        if (visited.has(childId)) continue
        visited.add(childId)
        if (!this.revocationRegistry.has(childId)) {
          const childRev = this.revokeDelegation(
            childId, revokedBy,
            `Cascade: parent ${parentId} revoked — ${reason}`,
            privateKey,
          )
          cascaded.push(childRev)
          this.emitRevocation({
            type: 'cascade',
            revocation: childRev,
            parentDelegationId: parentId,
          })
        }
        revokeDescendants(childId)
      }
    }

    revokeDescendants(delegationId)

    return {
      rootRevocation,
      cascadedRevocations: cascaded,
      totalRevoked: 1 + cascaded.length,
      chainDepth: this.getMaxDepth(delegationId),
    }
  }

  /** Revoke ALL delegations granted TO a specific agent. */
  revokeByAgent(
    agentPublicKey: string,
    revokedBy: string,
    reason: string,
    privateKey: string,
  ): RevocationRecord[] {
    const revocations: RevocationRecord[] = []
    for (const [id, entry] of this.chainRegistry) {
      if (entry.delegation.delegatedTo === agentPublicKey) {
        if (!this.revocationRegistry.has(id)) {
          const result = this.cascadeRevoke(id, revokedBy, reason, privateKey)
          revocations.push(result.rootRevocation, ...result.cascadedRevocations)
        }
      }
    }
    for (const rev of revocations) {
      this.emitRevocation({ type: 'agent_batch', revocation: rev, batchAgentId: agentPublicKey })
    }
    return revocations
  }

  private getMaxDepth(delegationId: string): number {
    const entry = this.chainRegistry.get(delegationId)
    if (!entry || entry.childIds.size === 0) return 0
    let max = 0
    for (const childId of entry.childIds) {
      max = Math.max(max, 1 + this.getMaxDepth(childId))
    }
    return max
  }

  // ─────────────────────────────────────────────────────────────
  // Chain validation / inspection
  // ─────────────────────────────────────────────────────────────

  validateChain(delegationIds: string[]): DelegationChainValidation {
    const links: DelegationChainLink[] = []
    let firstFailure: DelegationChainValidation['firstFailure'] | undefined

    for (let i = 0; i < delegationIds.length; i++) {
      const id = delegationIds[i]
      const entry = this.chainRegistry.get(id)

      if (!entry) {
        const link: DelegationChainLink = {
          delegationId: id,
          delegatedBy: 'unknown',
          delegatedTo: 'unknown',
          depth: i,
          status: {
            valid: false, revoked: false, expired: false, notYetValid: false,
            depthExceeded: false, errors: ['Delegation not found in registry'],
          },
        }
        links.push(link)
        if (!firstFailure) {
          firstFailure = { index: i, delegationId: id, reason: 'Delegation not found in registry' }
        }
        continue
      }

      const status = verifyDelegation(entry.delegation, {
        cachedRevocationState: this.revocationRegistry.has(id)
          ? { revoked: true, checkedAt: new Date().toISOString() }
          : undefined,
      })
      if (this.revocationRegistry.has(id) && !status.revoked) {
        status.revoked = true
        status.valid = false
        const rev = this.revocationRegistry.get(id)!
        status.revokedAt = rev.revokedAt
        status.errors.push(`Revoked at ${rev.revokedAt}: ${rev.reason}`)
      }

      const link: DelegationChainLink = {
        delegationId: id,
        delegatedBy: entry.delegation.delegatedBy,
        delegatedTo: entry.delegation.delegatedTo,
        depth: entry.delegation.currentDepth,
        status,
      }
      links.push(link)

      if (!status.valid && !firstFailure) {
        firstFailure = { index: i, delegationId: id, reason: status.errors.join('; ') }
      }

      if (i > 0) {
        const prev = links[i - 1]
        if (prev.delegatedTo !== link.delegatedBy) {
          const reason = `Chain break: ${prev.delegatedTo} → ${link.delegatedBy}`
          link.status.valid = false
          link.status.errors.push(reason)
          if (!firstFailure) {
            firstFailure = { index: i, delegationId: id, reason }
          }
        }
      }
    }

    return { valid: !firstFailure, chainLength: links.length, links, firstFailure }
  }

  getDescendants(delegationId: string): string[] {
    const result: string[] = []
    const entry = this.chainRegistry.get(delegationId)
    if (!entry) return result
    for (const childId of entry.childIds) {
      result.push(childId)
      result.push(...this.getDescendants(childId))
    }
    return result
  }

  getChainEntry(delegationId: string) {
    const entry = this.chainRegistry.get(delegationId)
    if (!entry) return undefined
    return {
      delegation: entry.delegation,
      parentId: entry.parentId,
      childIds: [...entry.childIds],
    }
  }

  getRevocation(delegationId: string): RevocationRecord | undefined {
    return this.revocationRegistry.get(delegationId)
  }

  // ─────────────────────────────────────────────────────────────
  // Receipts + spend accumulation
  // ─────────────────────────────────────────────────────────────

  getSpent(delegation: Delegation): number {
    return this.spendTracker.get(delegation.delegationId) ?? (delegation.spentAmount ?? 0)
  }

  /**
   * Create a signed receipt, enforcing cumulative spend against the store's
   * tracker (not delegation.spentAmount, which is frozen at creation time).
   */
  createReceipt(opts: CreateReceiptOptions): ActionReceipt {
    const status = verifyDelegation(opts.delegation, {
      cachedRevocationState: this.revocationRegistry.has(opts.delegation.delegationId)
        ? { revoked: true, checkedAt: new Date().toISOString() }
        : undefined,
    })
    if (this.revocationRegistry.has(opts.delegation.delegationId)) {
      status.valid = false
      status.revoked = true
      if (!status.errors.some(e => e.toLowerCase().includes('revok'))) {
        status.errors.push('Revoked')
      }
    }
    if (!status.valid) {
      throw new Error(`Cannot create receipt: delegation invalid — ${status.errors.join(', ')}`)
    }

    if (!scopeAuthorizes(opts.delegation.scope, opts.action.scopeUsed)) {
      throw new Error(
        `Scope '${opts.action.scopeUsed}' not in delegation [${opts.delegation.scope}]`,
      )
    }

    if (opts.action.spend) {
      const currentSpent = this.getSpent(opts.delegation)
      const remaining = (opts.delegation.spendLimit ?? Infinity) - currentSpent
      if (opts.action.spend.amount > remaining) {
        throw new Error(`Spend ${opts.action.spend.amount} exceeds remaining ${remaining}`)
      }
      this.spendTracker.set(opts.delegation.delegationId, currentSpent + opts.action.spend.amount)
      if (this.spendTracker.size > this.maxRegistrySize) {
        const oldest = this.spendTracker.keys().next().value
        if (oldest) this.spendTracker.delete(oldest)
      }
    }

    const receipt: Omit<ActionReceipt, 'signature'> = {
      receiptId: 'rcpt_' + uuidv4().slice(0, 12),
      version: '1.1',
      timestamp: new Date().toISOString(),
      agentId: opts.agentId,
      delegationId: opts.delegationId,
      action: opts.action,
      result: opts.result,
      delegationChain: opts.delegationChain,
    }

    const canonical = canonicalize(receipt)
    const signature = sign(canonical, opts.privateKey)
    const signedReceipt: ActionReceipt = { ...receipt, signature }
    this.receiptStore.push(signedReceipt)
    return signedReceipt
  }

  getReceipts(agentId?: string): ActionReceipt[] {
    if (agentId) return this.receiptStore.filter(r => r.agentId === agentId)
    return [...this.receiptStore]
  }

  // ─────────────────────────────────────────────────────────────
  // Housekeeping
  // ─────────────────────────────────────────────────────────────

  clear(): void {
    this.revocationRegistry.clear()
    this.receiptStore.length = 0
    this.chainRegistry.clear()
    this.spendTracker.clear()
    this.revocationListeners.length = 0
  }
}
