// Migrated from SDK (2026-04-17) — tests that depended on the module-scope
// delegation registries now exercise DelegationStore instead.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, subDelegate, verifyDelegation,
  verifyRevocation, verifyReceipt, scopeCovers,
} from 'agent-passport-system'
import type { Delegation, RevocationEvent } from 'agent-passport-system'
import { DelegationStore } from '../../../src/sdk-migrated/core/delegation-store.js'

const human = generateKeyPair()
const agentA = generateKeyPair()
const agentB = generateKeyPair()
const agentC = generateKeyPair()
const agentD = generateKeyPair()

function makeChain(store: DelegationStore) {
  const d1 = createDelegation({
    delegatedTo: agentA.publicKey,
    delegatedBy: human.publicKey,
    scope: ['code_execution', 'web_search', 'data_read'],
    spendLimit: 1000, maxDepth: 3,
    privateKey: human.privateKey,
  })
  store.registerRoot(d1)
  const d2 = subDelegate({
    parentDelegation: d1,
    delegatedTo: agentB.publicKey,
    scope: ['code_execution', 'web_search'],
    spendLimit: 500,
    privateKey: agentA.privateKey,
  })
  store.registerSubDelegation(d2, d1)
  const d3 = subDelegate({
    parentDelegation: d2,
    delegatedTo: agentC.publicKey,
    scope: ['web_search'],
    spendLimit: 100,
    privateKey: agentB.privateKey,
  })
  store.registerSubDelegation(d3, d2)
  return { d1, d2, d3 }
}

/** Helper: verify a delegation and overlay the store's revocation state.
 *  Works regardless of whether the installed SDK's verifyDelegation still
 *  holds a module-scope registry (1.46.x) or is stateless (post-split). */
function verifyWithStore(store: DelegationStore, d: Delegation) {
  const status = verifyDelegation(d)
  const rev = store.getRevocation(d.delegationId)
  if (rev) {
    status.revoked = true
    status.valid = false
    status.revokedAt = rev.revokedAt
    if (!status.errors.some((e: string) => /revok/i.test(e))) {
      status.errors.push(`Revoked at ${rev.revokedAt}: ${rev.reason}`)
    }
  }
  return status
}

// ═════════════════════════════════════════════════════════════════════
// Chain Registry
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Chain Registry', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('tracks root delegation in registry', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d)
    const entry = store.getChainEntry(d.delegationId)
    assert.ok(entry)
    assert.equal(entry!.parentId, null)
    assert.deepEqual(entry!.childIds, [])
  })

  it('tracks parent→child relationship', () => {
    const { d1, d2 } = makeChain(store)
    const parentEntry = store.getChainEntry(d1.delegationId)
    const childEntry = store.getChainEntry(d2.delegationId)
    assert.ok(parentEntry!.childIds.includes(d2.delegationId))
    assert.equal(childEntry!.parentId, d1.delegationId)
  })

  it('tracks full 3-level chain', () => {
    const { d1, d2, d3 } = makeChain(store)
    assert.ok(store.getChainEntry(d1.delegationId)!.childIds.includes(d2.delegationId))
    assert.ok(store.getChainEntry(d2.delegationId)!.childIds.includes(d3.delegationId))
    assert.equal(store.getChainEntry(d3.delegationId)!.childIds.length, 0)
  })
})

// ═════════════════════════════════════════════════════════════════════
// Direct Revocation
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Revocation', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('revokes a delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d)
    const rev = store.revokeDelegation(
      d.delegationId, human.publicKey, 'Trust withdrawn', human.privateKey,
    )
    assert.ok(rev.revocationId.startsWith('rev_'))
    assert.equal(rev.reason, 'Trust withdrawn')
    assert.ok(verifyRevocation(rev))
  })

  it('[ADVERSARIAL] delegation invalid after revocation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d)
    assert.ok(verifyWithStore(store, d).valid)
    store.revokeDelegation(d.delegationId, human.publicKey, 'Revoked', human.privateKey)
    const status = verifyWithStore(store, d)
    assert.ok(!status.valid)
    assert.ok(status.revoked)
  })

  it('[ADVERSARIAL] rejects receipt on revoked delegation', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d)
    store.revokeDelegation(d.delegationId, human.publicKey, 'Revoked', human.privateKey)
    assert.throws(() => {
      store.createReceipt({
        agentId: 'agent-a',
        delegationId: d.delegationId,
        delegation: d,
        action: { type: 'execute', target: 'script.ts', scopeUsed: 'code_execution' },
        result: { status: 'success', summary: 'done' },
        delegationChain: [human.publicKey, agentA.publicKey],
        privateKey: agentA.privateKey,
      })
    }, /delegation invalid/)
  })
})

// ═════════════════════════════════════════════════════════════════════
// Cascade Revocation
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Cascade Revocation', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('revokes root and all descendants', () => {
    const { d1, d2, d3 } = makeChain(store)
    assert.ok(verifyWithStore(store, d1).valid)
    assert.ok(verifyWithStore(store, d2).valid)
    assert.ok(verifyWithStore(store, d3).valid)

    const result = store.cascadeRevoke(
      d1.delegationId, human.publicKey, 'Trust withdrawn', human.privateKey,
    )
    assert.equal(result.totalRevoked, 3)
    assert.equal(result.cascadedRevocations.length, 2)

    assert.ok(!verifyWithStore(store, d1).valid)
    assert.ok(!verifyWithStore(store, d2).valid)
    assert.ok(!verifyWithStore(store, d3).valid)
  })

  it('cascade from middle of chain', () => {
    const { d1, d2, d3 } = makeChain(store)
    const result = store.cascadeRevoke(
      d2.delegationId, agentA.publicKey, 'Sub-agent compromised', agentA.privateKey,
    )
    assert.equal(result.totalRevoked, 2)
    assert.ok(verifyWithStore(store, d1).valid)
    assert.ok(!verifyWithStore(store, d2).valid)
    assert.ok(!verifyWithStore(store, d3).valid)
  })

  it('cascade on leaf is just single revocation', () => {
    const { d1, d2, d3 } = makeChain(store)
    const result = store.cascadeRevoke(
      d3.delegationId, agentB.publicKey, 'Leaf revoked', agentB.privateKey,
    )
    assert.equal(result.totalRevoked, 1)
    assert.equal(result.cascadedRevocations.length, 0)
    assert.ok(verifyWithStore(store, d1).valid)
    assert.ok(verifyWithStore(store, d2).valid)
    assert.ok(!verifyWithStore(store, d3).valid)
  })

  it('[ADVERSARIAL] does not double-revoke already revoked descendants', () => {
    const { d1, d2, d3 } = makeChain(store)
    store.cascadeRevoke(d3.delegationId, agentB.publicKey, 'Pre-revoked', agentB.privateKey)
    const result = store.cascadeRevoke(
      d1.delegationId, human.publicKey, 'Full revoke', human.privateKey,
    )
    assert.equal(result.cascadedRevocations.length, 1)
    assert.equal(result.totalRevoked, 2)
  })

  it('handles branching chains', () => {
    const d1 = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution', 'web_search'], spendLimit: 10000, maxDepth: 2,
      privateKey: human.privateKey,
    })
    store.registerRoot(d1)
    const d2 = subDelegate({
      parentDelegation: d1, delegatedTo: agentB.publicKey,
      scope: ['code_execution'], spendLimit: 5000,
      privateKey: agentA.privateKey,
    })
    store.registerSubDelegation(d2, d1)
    const d3 = subDelegate({
      parentDelegation: d1, delegatedTo: agentC.publicKey,
      scope: ['web_search'], spendLimit: 5000,
      privateKey: agentA.privateKey,
    })
    store.registerSubDelegation(d3, d1)
    const result = store.cascadeRevoke(
      d1.delegationId, human.publicKey, 'Full revoke', human.privateKey,
    )
    assert.equal(result.totalRevoked, 3)
    assert.ok(!verifyWithStore(store, d2).valid)
    assert.ok(!verifyWithStore(store, d3).valid)
  })
})

// ═════════════════════════════════════════════════════════════════════
// Batch Revocation by Agent
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Batch Revocation by Agent', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('revokes all delegations granted to an agent', () => {
    const d1 = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d1)
    const d2 = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['web_search'], privateKey: human.privateKey,
    })
    store.registerRoot(d2)
    const revocations = store.revokeByAgent(
      agentA.publicKey, human.publicKey, 'Agent compromised', human.privateKey,
    )
    assert.ok(revocations.length >= 2)
    assert.ok(!verifyWithStore(store, d1).valid)
    assert.ok(!verifyWithStore(store, d2).valid)
  })

  it('cascade-revokes descendants when batch revoking', () => {
    const { d1, d2, d3 } = makeChain(store)
    store.revokeByAgent(
      agentA.publicKey, human.publicKey, 'Agent A decommissioned', human.privateKey,
    )
    assert.ok(!verifyWithStore(store, d1).valid)
    assert.ok(!verifyWithStore(store, d2).valid)
    assert.ok(!verifyWithStore(store, d3).valid)
  })

  it('does not revoke delegations to other agents', () => {
    const dA = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(dA)
    const dB = createDelegation({
      delegatedTo: agentB.publicKey, delegatedBy: human.publicKey,
      scope: ['web_search'], privateKey: human.privateKey,
    })
    store.registerRoot(dB)
    store.revokeByAgent(agentA.publicKey, human.publicKey, 'Only A', human.privateKey)
    assert.ok(!verifyWithStore(store, dA).valid)
    assert.ok(verifyWithStore(store, dB).valid)
  })
})

// ═════════════════════════════════════════════════════════════════════
// Chain Validation
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Chain Validation', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('validates a healthy chain', () => {
    const { d1, d2, d3 } = makeChain(store)
    const result = store.validateChain([d1.delegationId, d2.delegationId, d3.delegationId])
    assert.ok(result.valid)
    assert.equal(result.chainLength, 3)
    assert.equal(result.firstFailure, undefined)
  })

  it('detects revoked link in chain', () => {
    const { d1, d2, d3 } = makeChain(store)
    store.cascadeRevoke(d2.delegationId, agentA.publicKey, 'Revoked', agentA.privateKey)
    const result = store.validateChain([d1.delegationId, d2.delegationId, d3.delegationId])
    assert.ok(!result.valid)
    assert.ok(result.firstFailure)
    assert.equal(result.firstFailure!.delegationId, d2.delegationId)
  })

  it('detects unknown delegation in chain', () => {
    const { d1 } = makeChain(store)
    const result = store.validateChain([d1.delegationId, 'del_fake123456'])
    assert.ok(!result.valid)
    assert.equal(result.firstFailure!.reason, 'Delegation not found in registry')
  })

  it('detects chain continuity break', () => {
    const d1 = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d1)
    const d2 = createDelegation({
      delegatedTo: agentC.publicKey, delegatedBy: agentB.publicKey,
      scope: ['web_search'], privateKey: agentB.privateKey,
    })
    store.registerRoot(d2)
    const result = store.validateChain([d1.delegationId, d2.delegationId])
    assert.ok(!result.valid)
    assert.ok(result.firstFailure!.reason.includes('Chain break'))
  })
})

// ═════════════════════════════════════════════════════════════════════
// getDescendants
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — getDescendants', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('returns all descendants', () => {
    const { d1, d2, d3 } = makeChain(store)
    const desc = store.getDescendants(d1.delegationId)
    assert.equal(desc.length, 2)
    assert.ok(desc.includes(d2.delegationId))
    assert.ok(desc.includes(d3.delegationId))
  })

  it('returns empty for leaf', () => {
    const { d3 } = makeChain(store)
    assert.deepEqual(store.getDescendants(d3.delegationId), [])
  })

  it('returns empty for unknown delegation', () => {
    assert.deepEqual(store.getDescendants('del_nonexistent'), [])
  })
})

// ═════════════════════════════════════════════════════════════════════
// Revocation Events
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Revocation Events', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('emits events on cascade revocation', () => {
    const events: RevocationEvent[] = []
    store.onRevocation(e => events.push(e))
    const { d1 } = makeChain(store)
    store.cascadeRevoke(d1.delegationId, human.publicKey, 'Test', human.privateKey)
    assert.ok(events.length >= 3)
    assert.ok(events.some(e => e.type === 'direct'))
    assert.ok(events.some(e => e.type === 'cascade'))
  })

  it('unsubscribe stops events', () => {
    const events: RevocationEvent[] = []
    const unsub = store.onRevocation(e => events.push(e))
    unsub()
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], privateKey: human.privateKey,
    })
    store.registerRoot(d)
    store.cascadeRevoke(d.delegationId, human.publicKey, 'Test', human.privateKey)
    assert.equal(events.length, 0)
  })
})

// ═════════════════════════════════════════════════════════════════════
// Action Receipts — cumulative spend accumulation (was in SDK)
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — Action Receipts + Spend', () => {
  let store: DelegationStore
  beforeEach(() => { store = new DelegationStore() })

  it('creates and verifies a valid receipt', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], spendLimit: 100,
      privateKey: human.privateKey,
    })
    store.registerRoot(d)
    const receipt = store.createReceipt({
      agentId: 'agent-a',
      delegationId: d.delegationId,
      delegation: d,
      action: {
        type: 'execute', target: 'build.ts', scopeUsed: 'code_execution',
        spend: { amount: 10, currency: 'USD' },
      },
      result: { status: 'success', summary: 'Built successfully' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey,
    })
    assert.ok(receipt.receiptId.startsWith('rcpt_'))
    const v = verifyReceipt(receipt, agentA.publicKey)
    assert.ok(v.valid)
  })

  it('cumulative spend is tracked across multiple receipts', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], spendLimit: 100,
      privateKey: human.privateKey,
    })
    store.registerRoot(d)
    store.createReceipt({
      agentId: 'agent-a', delegationId: d.delegationId, delegation: d,
      action: {
        type: 'execute', target: 't1', scopeUsed: 'code_execution',
        spend: { amount: 60, currency: 'USD' },
      },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [human.publicKey, agentA.publicKey],
      privateKey: agentA.privateKey,
    })
    assert.equal(store.getSpent(d), 60)
    assert.throws(() => {
      store.createReceipt({
        agentId: 'agent-a', delegationId: d.delegationId, delegation: d,
        action: {
          type: 'execute', target: 't2', scopeUsed: 'code_execution',
          spend: { amount: 50, currency: 'USD' },
        },
        result: { status: 'success', summary: 'ok' },
        delegationChain: [human.publicKey, agentA.publicKey],
        privateKey: agentA.privateKey,
      })
    }, /Spend.*exceeds remaining/)
  })

  it('getReceipts returns all stored receipts', () => {
    const d = createDelegation({
      delegatedTo: agentA.publicKey, delegatedBy: human.publicKey,
      scope: ['code_execution'], spendLimit: 1000,
      privateKey: human.privateKey,
    })
    store.registerRoot(d)
    for (let i = 0; i < 3; i++) {
      store.createReceipt({
        agentId: 'agent-a', delegationId: d.delegationId, delegation: d,
        action: { type: 'execute', target: `t${i}`, scopeUsed: 'code_execution' },
        result: { status: 'success', summary: 'ok' },
        delegationChain: [human.publicKey, agentA.publicKey],
        privateKey: agentA.privateKey,
      })
    }
    assert.equal(store.getReceipts().length, 3)
    assert.equal(store.getReceipts('agent-a').length, 3)
    assert.equal(store.getReceipts('other').length, 0)
  })
})

// ═════════════════════════════════════════════════════════════════════
// Property-based cascade invariants (INV-4 + INV-5)
// ═════════════════════════════════════════════════════════════════════

describe('DelegationStore — INV-4 + INV-5: Cascade Revocation (property-based)', () => {
  it('random tree topology: revoking any node revokes all descendants', () => {
    const store = new DelegationStore()
    const root = generateKeyPair()
    const children: Array<{ publicKey: string; privateKey: string }> = []
    const grandchildren: Array<{ publicKey: string; privateKey: string }> = []
    for (let i = 0; i < 3; i++) children.push(generateKeyPair())
    for (let i = 0; i < 6; i++) grandchildren.push(generateKeyPair())
    const rootDel = createDelegation({
      delegatedTo: children[0].publicKey, delegatedBy: root.publicKey,
      scope: ['code_execution', 'data_analysis'], spendLimit: 10000, maxDepth: 5,
      privateKey: root.privateKey,
    })
    store.registerRoot(rootDel)
    const gc0 = subDelegate({
      parentDelegation: rootDel, delegatedTo: grandchildren[0].publicKey,
      scope: ['code_execution'], spendLimit: 1000,
      privateKey: children[0].privateKey,
    })
    store.registerSubDelegation(gc0, rootDel)
    const gc1 = subDelegate({
      parentDelegation: rootDel, delegatedTo: grandchildren[1].publicKey,
      scope: ['data_analysis'], spendLimit: 1000,
      privateKey: children[0].privateKey,
    })
    store.registerSubDelegation(gc1, rootDel)
    assert.equal(verifyWithStore(store, rootDel).valid, true)
    assert.equal(verifyWithStore(store, gc0).valid, true)
    assert.equal(verifyWithStore(store, gc1).valid, true)
    store.cascadeRevoke(rootDel.delegationId, root.publicKey, 'Compromised', root.privateKey)
    assert.equal(verifyWithStore(store, rootDel).revoked, true)
    assert.equal(verifyWithStore(store, gc0).revoked, true)
    assert.equal(verifyWithStore(store, gc1).revoked, true)
  })

  it('revoking a leaf does not affect parent or siblings', () => {
    const store = new DelegationStore()
    const root = generateKeyPair()
    const child = generateKeyPair()
    const sib1 = generateKeyPair()
    const sib2 = generateKeyPair()
    const parentDel = createDelegation({
      delegatedTo: child.publicKey, delegatedBy: root.publicKey,
      scope: ['code_execution', 'data_analysis'], spendLimit: 10000, maxDepth: 5,
      privateKey: root.privateKey,
    })
    store.registerRoot(parentDel)
    const sib1Del = subDelegate({
      parentDelegation: parentDel, delegatedTo: sib1.publicKey,
      scope: ['code_execution'], spendLimit: 1000,
      privateKey: child.privateKey,
    })
    store.registerSubDelegation(sib1Del, parentDel)
    const sib2Del = subDelegate({
      parentDelegation: parentDel, delegatedTo: sib2.publicKey,
      scope: ['data_analysis'], spendLimit: 1000,
      privateKey: child.privateKey,
    })
    store.registerSubDelegation(sib2Del, parentDel)
    store.cascadeRevoke(sib1Del.delegationId, child.publicKey, 'Leaf revoke', child.privateKey)
    assert.equal(verifyWithStore(store, sib1Del).revoked, true)
    assert.equal(verifyWithStore(store, parentDel).valid, true)
    assert.equal(verifyWithStore(store, sib2Del).valid, true)
    // scopeCovers sanity — ensures we imported the right symbol
    assert.ok(scopeCovers('code_execution', 'code_execution'))
  })
})
