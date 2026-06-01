// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Delegation Contracts (G-B1) - human-to-machine authority bridge tests
// ══════════════════════════════════════════════════════════════════════
// The load-bearing property under test (GEM): the human-readable summary is
// DERIVED from the machine scope (the SDK-signed delegation.scope) and there
// is no independent, editable render field, so the summary can never drift
// from what is enforced. Plus multi-owner signature, versioning, and receipt
// binding, each with negatives.

import { describe, it, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import {
  generateKeyPair,
  createDelegation,
  subDelegate,
  createReceipt,
} from 'agent-passport-system'
import type { Delegation, KeyPair } from 'agent-passport-system'

import {
  DelegationContract,
  REQUIRED_OWNER_ROLES,
  getRenderScopeDimension,
  setRenderScopeDimension,
  passthroughRenderScopeDimension,
  type ContractOwner,
} from '../src/gateway/delegation-contracts/index.js'

// ── Fixtures ──────────────────────────────────────────────────────────

const principal: KeyPair = generateKeyPair()       // the human delegator
const agent: KeyPair = generateKeyPair()            // the machine delegatee
const business: KeyPair = generateKeyPair()
const security: KeyPair = generateKeyPair()
const compliance: KeyPair = generateKeyPair()

function mintDelegation(scope: string[]): Delegation {
  return createDelegation({
    delegatedTo: agent.publicKey,
    delegatedBy: principal.publicKey,
    scope,
    maxDepth: 3,
    privateKey: principal.privateKey,
  })
}

function owners(): ContractOwner[] {
  return [
    { role: 'business', name: 'Dana Business', publicKey: business.publicKey },
    { role: 'security', name: 'Sam Security', publicKey: security.publicKey },
    { role: 'compliance', name: 'Casey Compliance', publicKey: compliance.publicKey },
  ]
}

function fullySign(contract: DelegationContract): void {
  contract.signAsOwner({ role: 'business', privateKey: business.privateKey })
  contract.signAsOwner({ role: 'security', privateKey: security.privateKey })
  contract.signAsOwner({ role: 'compliance', privateKey: compliance.privateKey })
}

// Reset any injected scope renderer after each test so the seam stays clean.
afterEach(() => {
  setRenderScopeDimension(passthroughRenderScopeDimension)
})

// ── 1. Scope-to-human render fidelity ─────────────────────────────────

describe('G-B1 - human summary is derived from machine scope (fidelity)', () => {
  it('renders one human dimension per scope token, reflecting the scope exactly', () => {
    const scope = ['tool:email:send:*', 'data:read', 'commerce:refund']
    const contract = DelegationContract.open({ delegation: mintDelegation(scope), owners: owners() })

    const summary = contract.humanSummary()
    assert.equal(summary.length, scope.length)
    for (let i = 0; i < scope.length; i++) {
      // The passthrough (W2-C1 stub) is a faithful identity projection.
      assert.equal(summary[i].scope, scope[i])
      assert.equal(summary[i].label, scope[i])
      assert.equal(summary[i].description, scope[i])
      assert.equal(summary[i].dimension, scope[i].split(':')[0])
    }
  })

  it('serialized artifact carries a humanSummary re-derived from scope', () => {
    const scope = ['tool:calendar:write:*']
    const contract = DelegationContract.open({ delegation: mintDelegation(scope), owners: owners() })
    const artifact = contract.toArtifact()
    assert.deepEqual(
      artifact.humanSummary.map(d => d.scope),
      scope,
    )
  })

  it('the render is produced by the W2-C1 scope-registry seam, not hand-authored', () => {
    // Swap the seam: every dimension should now reflect the injected renderer,
    // proving the summary is a function of the renderer over the scope, not a
    // stored string.
    setRenderScopeDimension((s) => ({
      scope: s,
      label: `LABEL(${s})`,
      dimension: 'custom',
      description: `DESC(${s})`,
    }))
    const scope = ['tool:email:send:*']
    const contract = DelegationContract.open({ delegation: mintDelegation(scope), owners: owners() })
    const summary = contract.humanSummary()
    assert.equal(summary[0].label, 'LABEL(tool:email:send:*)')
    assert.equal(summary[0].dimension, 'custom')
    // restore happens in afterEach
    assert.equal(typeof getRenderScopeDimension(), 'function')
  })
})

// ── 2. The render CANNOT diverge from the scope (no-drift / no editable field) ──

describe('G-B1 - render cannot diverge from machine scope', () => {
  it('mutating the scope (via a new delegation amend) changes the render accordingly', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    const before = contract.humanSummary().map(d => d.scope)
    assert.deepEqual(before, ['data:read'])

    // Amend the machine scope through a re-minted SDK delegation (only path to
    // change enforced authority). The human summary must follow.
    contract.amend({ delegation: mintDelegation(['data:read', 'data:write']) })
    const after = contract.humanSummary().map(d => d.scope)
    assert.deepEqual(after, ['data:read', 'data:write'])
    // The render changed because the scope changed - they cannot be decoupled.
    assert.notDeepEqual(before, after)
  })

  it('there is no independent editable render field on the artifact', () => {
    const scope = ['tool:email:send:*']
    const contract = DelegationContract.open({ delegation: mintDelegation(scope), owners: owners() })
    const artifact = contract.toArtifact()

    // Attempt to tamper with the serialized humanSummary, then rehydrate.
    artifact.humanSummary = [
      { scope: 'admin:everything', label: 'Full admin access', dimension: 'admin', description: 'do anything' },
    ]
    const reloaded = DelegationContract.fromArtifact(artifact)

    // The reloaded contract IGNORES the persisted summary and re-derives from
    // the machine scope. The tampered label cannot survive load.
    const summary = reloaded.humanSummary()
    assert.equal(summary.length, 1)
    assert.equal(summary[0].scope, 'tool:email:send:*')
    assert.notEqual(summary[0].label, 'Full admin access')
    assert.deepEqual(reloaded.scope, scope)
  })

  it('humanSummary is the only path to a summary - derived live from scope each call', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    // Two reads with a renderer swap in between: same scope, renderer-driven output.
    const first = contract.humanSummary()
    assert.equal(first[0].label, 'data:read')
    setRenderScopeDimension((s) => ({ scope: s, label: 'X', dimension: 'd', description: 'x' }))
    const second = contract.humanSummary()
    assert.equal(second[0].label, 'X')
    // The scope itself never changed; only the derivation did.
    assert.deepEqual(contract.scope, ['data:read'])
  })
})

// ── 3. Multi-owner signatures ─────────────────────────────────────────

describe('G-B1 - multi-owner signatures', () => {
  it('requires all named owners to sign before the contract is fully signed', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    assert.equal(contract.isFullySigned(), false)
    assert.deepEqual(contract.missingSignatures().sort(), [...REQUIRED_OWNER_ROLES].sort())

    contract.signAsOwner({ role: 'business', privateKey: business.privateKey })
    assert.equal(contract.isFullySigned(), false)
    assert.deepEqual(contract.signedRoles(), ['business'])

    contract.signAsOwner({ role: 'security', privateKey: security.privateKey })
    contract.signAsOwner({ role: 'compliance', privateKey: compliance.privateKey })
    assert.equal(contract.isFullySigned(), true)
    assert.deepEqual(contract.missingSignatures(), [])
  })

  it('verifies each owner signature against the registered key', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    const sig = contract.signAsOwner({ role: 'business', privateKey: business.privateKey })
    assert.equal(contract.verifyOwnerSignature(sig), true)
  })

  it('rejects a signature whose private key does not match the registered owner key (negative)', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    // security owner tries to sign for the business role
    assert.throws(
      () => contract.signAsOwner({ role: 'business', privateKey: security.privateKey }),
      /does not match registered key/,
    )
  })

  it('rejects signing for a role not on the roster (negative)', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: [{ role: 'business', name: 'Dana', publicKey: business.publicKey }],
    })
    assert.throws(
      () => contract.signAsOwner({ role: 'security', privateKey: security.privateKey }),
      /no owner with role/,
    )
  })

  it('rejects a forged signature blob under the right role (negative)', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    const good = contract.signAsOwner({ role: 'business', privateKey: business.privateKey })
    const forged = { ...good, signature: 'deadbeef'.repeat(16) }
    assert.equal(contract.verifyOwnerSignature(forged), false)
  })

  it('full verify() passes only when delegation verifies and all owners signed', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    const partial = contract.verify()
    assert.equal(partial.valid, false)
    assert.ok(partial.errors.some(e => e.includes('missing or invalid signature')))

    fullySign(contract)
    const full = contract.verify()
    assert.equal(full.valid, true, full.errors.join('; '))
  })
})

// ── 4. Versioning ─────────────────────────────────────────────────────

describe('G-B1 - versioning binds signatures to the exact scope signed', () => {
  it('amending the scope bumps the version and clears prior signatures', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    fullySign(contract)
    assert.equal(contract.version, 1)
    assert.equal(contract.isFullySigned(), true)

    const newVersion = contract.amend({ delegation: mintDelegation(['data:read', 'data:write']) })
    assert.equal(newVersion, 2)
    assert.equal(contract.version, 2)
    // Signatures from v1 are gone; owners must re-sign the new scope.
    assert.equal(contract.isFullySigned(), false)
    assert.deepEqual(contract.signatures, [])
  })

  it('a signature captured at an old version does not validate the new scope (negative)', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    const v1Sig = contract.signAsOwner({ role: 'business', privateKey: business.privateKey })
    assert.equal(contract.verifyOwnerSignature(v1Sig), true)

    contract.amend({ delegation: mintDelegation(['data:read', 'commerce:refund']) })
    // The old signature references v1 and the old binding hash; it is now stale.
    assert.equal(contract.verifyOwnerSignature(v1Sig), false)
  })

  it('the binding hash covers the machine scope, so a scope change changes the hash', () => {
    const a = DelegationContract.open({ delegation: mintDelegation(['data:read']), owners: owners() })
    const b = DelegationContract.open({ delegation: mintDelegation(['data:write']), owners: owners() })
    assert.notEqual(a.bindingHash(), b.bindingHash())
  })

  it('re-signing after amend restores full signature over the new scope', () => {
    const contract = DelegationContract.open({
      delegation: mintDelegation(['data:read']),
      owners: owners(),
    })
    fullySign(contract)
    contract.amend({ delegation: mintDelegation(['data:read', 'data:write']) })
    assert.equal(contract.isFullySigned(), false)
    fullySign(contract)
    assert.equal(contract.isFullySigned(), true)
    assert.equal(contract.version, 2)
  })
})

// ── 5. Receipt binding ────────────────────────────────────────────────

describe('G-B1 - receipt binding', () => {
  function receiptUnder(delegation: Delegation, scopeUsed: string) {
    return createReceipt({
      agentId: agent.publicKey,
      delegationId: delegation.delegationId,
      delegation,
      action: { type: 'data', target: 'records/42', scopeUsed },
      result: { status: 'success', summary: 'read 1 record' },
      delegationChain: [delegation.delegationId],
      privateKey: agent.privateKey,
    })
  }

  it('binds a receipt issued under the contract delegation', () => {
    const delegation = mintDelegation(['data:read'])
    const contract = DelegationContract.open({ delegation, owners: owners() })
    const receipt = receiptUnder(delegation, 'data:read')

    const ref = contract.bindReceipt(receipt, agent.publicKey)
    assert.equal(ref.receiptId, receipt.receiptId)
    assert.equal(ref.delegationId, delegation.delegationId)
    assert.ok(ref.receiptHash.length === 64)
    assert.equal(contract.governsReceipt(receipt.receiptId), true)
  })

  it('rejects a receipt issued under a DIFFERENT delegation (negative)', () => {
    const delegation = mintDelegation(['data:read'])
    const other = mintDelegation(['data:read'])
    const contract = DelegationContract.open({ delegation, owners: owners() })
    const foreignReceipt = receiptUnder(other, 'data:read')

    assert.throws(
      () => contract.bindReceipt(foreignReceipt, agent.publicKey),
      /does not match contract delegation/,
    )
    assert.equal(contract.governsReceipt(foreignReceipt.receiptId), false)
  })

  it('rejects a receipt that does not verify under the acting agent key (negative)', () => {
    const delegation = mintDelegation(['data:read'])
    const contract = DelegationContract.open({ delegation, owners: owners() })
    const receipt = receiptUnder(delegation, 'data:read')
    const wrongKey = generateKeyPair().publicKey

    assert.throws(
      () => contract.bindReceipt(receipt, wrongKey),
      /does not verify/,
    )
  })

  it('binding is idempotent on receiptId', () => {
    const delegation = mintDelegation(['data:read'])
    const contract = DelegationContract.open({ delegation, owners: owners() })
    const receipt = receiptUnder(delegation, 'data:read')
    contract.bindReceipt(receipt, agent.publicKey)
    contract.bindReceipt(receipt, agent.publicKey)
    assert.equal(contract.boundReceipts.length, 1)
  })

  it('bound receipts survive serialization roundtrip', () => {
    const delegation = mintDelegation(['data:read'])
    const contract = DelegationContract.open({ delegation, owners: owners() })
    const receipt = receiptUnder(delegation, 'data:read')
    contract.bindReceipt(receipt, agent.publicKey)

    const reloaded = DelegationContract.fromArtifact(contract.toArtifact())
    assert.equal(reloaded.governsReceipt(receipt.receiptId), true)
  })
})

// ── 6. Sub-delegation narrows through the SDK (no reinvented narrowing) ──

describe('G-B1 - narrowing is delegated to the SDK subDelegate', () => {
  it('a sub-delegated contract derives its human summary from the narrowed scope', () => {
    const sub = generateKeyPair()
    // Give the parent a finite spend bound so the SDK narrowing path applies a
    // concrete remaining bound to the child (the SDK rejects an Infinity bound).
    const parent = createDelegation({
      delegatedTo: agent.publicKey,
      delegatedBy: principal.publicKey,
      scope: ['data:read', 'data:write'],
      spendLimit: 1000,
      maxDepth: 3,
      privateKey: principal.privateKey,
    })
    const child = subDelegate({
      parentDelegation: parent,
      delegatedTo: sub.publicKey,
      scope: ['data:read'],
      spendLimit: 500,
      privateKey: agent.privateKey,
    })
    const contract = DelegationContract.open({ delegation: child, owners: owners() })
    assert.deepEqual(contract.humanSummary().map(d => d.scope), ['data:read'])
  })

  it('the SDK rejects a child that widens beyond the parent scope (negative)', () => {
    const sub = generateKeyPair()
    const parent = mintDelegation(['data:read'])
    assert.throws(
      () => subDelegate({
        parentDelegation: parent,
        delegatedTo: sub.publicKey,
        scope: ['data:read', 'admin:write'],
        privateKey: agent.privateKey,
      }),
      /Scope violation/,
    )
  })
})
