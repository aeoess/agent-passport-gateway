// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Delegation Contracts - human-to-machine authority bridge (GEM)
// ══════════════════════════════════════════════════════════════════════
// A signed, multi-owner, versioned authority artifact that wraps an SDK
// Delegation. The machine-enforced scope (delegation.scope) is the single
// source of truth. The human-readable summary is DERIVED from that scope, so
// the readable view can never drift from what is enforced.
//
// What this module is NOT: it does not re-implement any protocol primitive.
// The delegation is minted, narrowed, verified and bound to receipts through
// the SDK (createDelegation / subDelegate / verifyDelegation / createReceipt)
// and the gateway DelegationStore. This module only assembles, signs, and
// renders the customer-owned contract artifact around that delegation.
//
// Thin gateway: the contract is a pre-signed, customer-owned artifact carried
// at the edge. The gateway assembles and checks it; it does not become a
// central registry of authority. Trust lives in the owner signatures and the
// SDK-signed delegation, not in gateway state.

import { createHash } from 'node:crypto'
import {
  canonicalize,
  verifyDelegation,
  verifyReceipt,
  sign as sdkSign,
  verify as sdkVerify,
  publicKeyFromPrivate,
} from 'agent-passport-system'
import type { Delegation, ActionReceipt } from 'agent-passport-system'
import {
  getRenderScopeDimension,
  type ScopeDimension,
} from './scope-registry.js'

/** The three accountable owner roles that countersign an authority contract. */
export type OwnerRole = 'business' | 'security' | 'compliance'

/** The full set of owner roles a complete contract requires. */
export const REQUIRED_OWNER_ROLES: readonly OwnerRole[] = ['business', 'security', 'compliance']

/** A named owner who is asked to countersign the contract. */
export interface ContractOwner {
  role: OwnerRole
  /** Display name of the accountable person. */
  name: string
  /** Owner's Ed25519 public key (hex), used to verify their signature. */
  publicKey: string
}

/** One owner's signature over the contract binding hash at a given version. */
export interface OwnerSignature {
  role: OwnerRole
  name: string
  publicKey: string
  /** Contract version this signature commits to. A signature is bound to one version. */
  version: number
  /** The binding hash that was signed (scope + delegation + version + owners). */
  bindingHash: string
  /** Ed25519 signature (hex) over the binding hash. */
  signature: string
  signedAt: string
}

/** A receipt bound to this contract, recorded by delegationId. */
export interface BoundReceiptRef {
  receiptId: string
  delegationId: string
  /** Hash of the bound receipt for tamper-evidence. */
  receiptHash: string
}

/**
 * The serialized contract artifact. The human summary is NOT stored as an
 * independent editable field - it is recomputed from `delegation.scope` every
 * time the artifact is produced (see toArtifact / humanSummary). Persisting it
 * is for display only and is always re-derived, never authored.
 */
export interface DelegationContractArtifact {
  contractId: string
  version: number
  /** The SDK-signed delegation. Its `scope` is the single source of truth. */
  delegation: Delegation
  owners: ContractOwner[]
  signatures: OwnerSignature[]
  boundReceipts: BoundReceiptRef[]
  /**
   * Display-only projection. ALWAYS derived from delegation.scope at
   * serialization time. Never read back as authority. Present so a stored
   * artifact is human-readable without re-running the renderer, but it is
   * recomputed (not trusted) on every load.
   */
  humanSummary: ScopeDimension[]
  createdAt: string
}

function nowIso(): string {
  return new Date().toISOString()
}

function shortId(prefix: string): string {
  return prefix + createHash('sha256')
    .update(prefix + nowIso() + Math.random().toString())
    .digest('hex')
    .slice(0, 16)
}

/**
 * DelegationContract - the human-to-machine authority bridge.
 *
 * Invariants:
 *  - The machine scope is `this.delegation.scope` (SDK-signed). It is the only
 *    source of authority.
 *  - The human summary is a pure function of that scope (`humanSummary()`).
 *    There is no setter and no stored editable summary field, so the readable
 *    view cannot diverge from what is enforced.
 *  - Any change to the scope is a new contract version that invalidates prior
 *    owner signatures; owners must re-sign the new binding hash. A signature
 *    from an earlier version never validates the current scope.
 */
export class DelegationContract {
  readonly contractId: string
  private _version: number
  private _delegation: Delegation
  private readonly _owners: ContractOwner[]
  private _signatures: OwnerSignature[]
  private readonly _boundReceipts: BoundReceiptRef[]
  readonly createdAt: string

  private constructor(opts: {
    contractId: string
    version: number
    delegation: Delegation
    owners: ContractOwner[]
    signatures: OwnerSignature[]
    boundReceipts: BoundReceiptRef[]
    createdAt: string
  }) {
    this.contractId = opts.contractId
    this._version = opts.version
    this._delegation = opts.delegation
    this._owners = opts.owners
    this._signatures = opts.signatures
    this._boundReceipts = opts.boundReceipts
    this.createdAt = opts.createdAt
  }

  /**
   * Open a new contract around an already-minted SDK delegation. The caller
   * supplies the delegation via createDelegation / subDelegate (this module
   * does not mint authority); the contract wraps it for multi-owner signature.
   */
  static open(opts: {
    delegation: Delegation
    owners: ContractOwner[]
  }): DelegationContract {
    if (!opts.delegation || !Array.isArray(opts.delegation.scope)) {
      throw new Error('DelegationContract.open: delegation with a scope array is required')
    }
    if (!Array.isArray(opts.owners) || opts.owners.length === 0) {
      throw new Error('DelegationContract.open: at least one owner is required')
    }
    const seenRoles = new Set<OwnerRole>()
    for (const o of opts.owners) {
      if (seenRoles.has(o.role)) {
        throw new Error(`DelegationContract.open: duplicate owner role "${o.role}"`)
      }
      seenRoles.add(o.role)
    }
    return new DelegationContract({
      contractId: shortId('dcontract_'),
      version: 1,
      delegation: opts.delegation,
      owners: [...opts.owners],
      signatures: [],
      boundReceipts: [],
      createdAt: nowIso(),
    })
  }

  get version(): number { return this._version }
  get delegation(): Delegation { return this._delegation }
  get owners(): ContractOwner[] { return [...this._owners] }
  get signatures(): OwnerSignature[] { return [...this._signatures] }
  get boundReceipts(): BoundReceiptRef[] { return [...this._boundReceipts] }

  /** The machine scope: the single source of truth for what is authorized. */
  get scope(): string[] { return [...this._delegation.scope] }

  /**
   * The human-readable summary. DERIVED from the machine scope on every call
   * through the (W2-C1-stubbed) scope-dimension renderer. There is no stored,
   * editable summary; this is the only way to obtain one, so it can never
   * describe authority the scope does not grant.
   */
  humanSummary(): ScopeDimension[] {
    const render = getRenderScopeDimension()
    return this._delegation.scope.map(render)
  }

  /**
   * The binding hash an owner signature commits to. It covers the version, the
   * full machine scope, the delegation identity and signature, and the owner
   * roster. Because the scope is inside the hash, a signature is mathematically
   * bound to the exact scope it was shown - it cannot be carried to a different
   * scope without breaking the hash.
   */
  bindingHash(version: number = this._version): string {
    const binding = {
      contractId: this.contractId,
      version,
      delegationId: this._delegation.delegationId,
      delegatedTo: this._delegation.delegatedTo,
      delegatedBy: this._delegation.delegatedBy,
      // The machine scope is the load-bearing field of the binding.
      scope: [...this._delegation.scope],
      delegationSignature: this._delegation.signature,
      owners: this._owners
        .map(o => ({ role: o.role, name: o.name, publicKey: o.publicKey }))
        .sort((a, b) => a.role.localeCompare(b.role)),
    }
    return createHash('sha256').update(canonicalize(binding)).digest('hex')
  }

  /**
   * An owner countersigns the current contract version. The owner signs the
   * binding hash (which contains the scope) with their own Ed25519 key. The
   * signature is rejected if the owner is not on the roster, the key does not
   * match, or the produced signature does not verify.
   */
  signAsOwner(opts: { role: OwnerRole; privateKey: string }): OwnerSignature {
    const owner = this._owners.find(o => o.role === opts.role)
    if (!owner) {
      throw new Error(`signAsOwner: no owner with role "${opts.role}" on this contract`)
    }
    const derivedPub = publicKeyFromPrivate(opts.privateKey)
    if (derivedPub !== owner.publicKey) {
      throw new Error(`signAsOwner: private key does not match registered key for role "${opts.role}"`)
    }
    const bindingHash = this.bindingHash()
    const signature = sdkSign(bindingHash, opts.privateKey)
    const record: OwnerSignature = {
      role: owner.role,
      name: owner.name,
      publicKey: owner.publicKey,
      version: this._version,
      bindingHash,
      signature,
      signedAt: nowIso(),
    }
    // Replace any prior signature from this role (only one signature per role per version).
    this._signatures = this._signatures.filter(
      s => !(s.role === owner.role && s.version === this._version),
    )
    this._signatures.push(record)
    return record
  }

  /**
   * Verify one owner signature against the CURRENT version and scope. A
   * signature is valid only if it commits to the current binding hash and
   * verifies under the registered owner key.
   */
  verifyOwnerSignature(sig: OwnerSignature): boolean {
    const owner = this._owners.find(o => o.role === sig.role)
    if (!owner) return false
    if (owner.publicKey !== sig.publicKey) return false
    if (sig.version !== this._version) return false
    const expected = this.bindingHash()
    if (sig.bindingHash !== expected) return false
    return sdkVerify(sig.bindingHash, sig.signature, sig.publicKey)
  }

  /** The owner roles that have a valid signature on the current version. */
  signedRoles(): OwnerRole[] {
    return this._signatures
      .filter(s => this.verifyOwnerSignature(s))
      .map(s => s.role)
  }

  /**
   * The roster roles still missing a valid current-version signature. A
   * contract is fully signed when every roster role has signed the current
   * scope.
   */
  missingSignatures(): OwnerRole[] {
    const signed = new Set(this.signedRoles())
    return this._owners.map(o => o.role).filter(r => !signed.has(r))
  }

  /** True when every roster owner has a valid signature over the current scope. */
  isFullySigned(): boolean {
    return this.missingSignatures().length === 0
  }

  /**
   * Verify the contract end to end:
   *  - the SDK delegation verifies (signature, expiry, notBefore, depth),
   *  - every roster owner has a valid signature over the current scope.
   * Revocation is sink-enforced via the DelegationStore cache, passed in by the
   * caller; this check is point-in-time and supports evidence, it is not a
   * claim of live non-revocation.
   */
  verify(opts?: {
    cachedRevocationState?: { revoked: boolean; checkedAt: string }
  }): { valid: boolean; errors: string[] } {
    const errors: string[] = []
    const status = verifyDelegation(this._delegation, {
      cachedRevocationState: opts?.cachedRevocationState,
    })
    if (!status.valid) {
      errors.push(...status.errors.map(e => `delegation: ${e}`))
    }
    for (const role of this.missingSignatures()) {
      errors.push(`missing or invalid signature for owner role "${role}"`)
    }
    return { valid: errors.length === 0, errors }
  }

  /**
   * Amend the machine scope. This is the ONLY way to change what is enforced,
   * and it MUST go through a re-minted SDK delegation supplied by the caller
   * (createDelegation / subDelegate). Amending bumps the version and clears all
   * prior owner signatures: because the human summary is derived from scope,
   * any scope change forces every owner to re-sign the new derived summary.
   * Returns the new version number.
   */
  amend(opts: { delegation: Delegation }): number {
    if (!opts.delegation || !Array.isArray(opts.delegation.scope)) {
      throw new Error('amend: a replacement delegation with a scope array is required')
    }
    this._delegation = opts.delegation
    this._version += 1
    // Prior signatures committed to the old scope/version; they no longer apply.
    this._signatures = []
    return this._version
  }

  /**
   * Bind a receipt to this contract. The receipt must have been issued under
   * this contract's delegation (matching delegationId) and must verify under
   * the acting agent's key. Binding records the receipt by id and hash so the
   * contract governs an auditable set of receipts.
   */
  bindReceipt(receipt: ActionReceipt, agentPublicKey: string): BoundReceiptRef {
    if (receipt.delegationId !== this._delegation.delegationId) {
      throw new Error(
        `bindReceipt: receipt delegationId "${receipt.delegationId}" does not match contract delegation "${this._delegation.delegationId}"`,
      )
    }
    const result = verifyReceipt(receipt, agentPublicKey)
    if (!result.valid) {
      throw new Error(`bindReceipt: receipt does not verify - ${result.errors.join(', ')}`)
    }
    const receiptHash = createHash('sha256')
      .update(canonicalize(receipt))
      .digest('hex')
    const ref: BoundReceiptRef = {
      receiptId: receipt.receiptId,
      delegationId: receipt.delegationId,
      receiptHash,
    }
    if (!this._boundReceipts.some(r => r.receiptId === ref.receiptId)) {
      this._boundReceipts.push(ref)
    }
    return ref
  }

  /** True if the given receipt id is governed by this contract. */
  governsReceipt(receiptId: string): boolean {
    return this._boundReceipts.some(r => r.receiptId === receiptId)
  }

  /**
   * Produce the serialized artifact. The humanSummary is re-derived from the
   * current scope here, so a serialized artifact is never carrying a stale or
   * hand-edited summary - it is always a faithful projection of the scope.
   */
  toArtifact(): DelegationContractArtifact {
    return {
      contractId: this.contractId,
      version: this._version,
      delegation: this._delegation,
      owners: this.owners,
      signatures: this.signatures,
      boundReceipts: this.boundReceipts,
      humanSummary: this.humanSummary(),
      createdAt: this.createdAt,
    }
  }

  /**
   * Rehydrate a contract from a stored artifact. The stored humanSummary is
   * intentionally ignored and recomputed from scope - load never trusts a
   * persisted summary as authority. Signatures are re-verified against the
   * current binding hash by the usual methods after load.
   */
  static fromArtifact(artifact: DelegationContractArtifact): DelegationContract {
    return new DelegationContract({
      contractId: artifact.contractId,
      version: artifact.version,
      delegation: artifact.delegation,
      owners: [...artifact.owners],
      signatures: [...artifact.signatures],
      boundReceipts: [...artifact.boundReceipts],
      createdAt: artifact.createdAt,
    })
  }
}
