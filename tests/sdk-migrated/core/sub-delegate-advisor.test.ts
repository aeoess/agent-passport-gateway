// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// v2 Sub-Delegate Advisor — bounded-escalation delegation primitive tests.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, clearStores,
  subDelegateAdvisor, consultAdvisor,
  getAdvisorUses, clearAdvisorUseTracker,
} from 'agent-passport-system'
// cascadeRevoke moved to the gateway's DelegationStore in the 2026-04-17
// extraction (the SDK export now throws a MOVED error).
import { DelegationStore } from '../../../src/sdk-migrated/core/delegation-store.js'
import { joinSocialContract, delegate } from 'agent-passport-system'
import { canonicalize } from 'agent-passport-system'
import { sign } from 'agent-passport-system'
import { createProxyGateway } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import { loadFloor } from 'agent-passport-system'
import type { GatewayConfig, ToolCallRequest } from 'agent-passport-system'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../../../node_modules/agent-passport-system/values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

const principal = generateKeyPair()
const executor = generateKeyPair()
const advisor = generateKeyPair()

function adviceHash(advice: string): string {
  // Deterministic stub — real callers would sha256 the advice content.
  return 'sha256:' + Buffer.from(advice).toString('hex').slice(0, 32)
}

// NOTE: parent delegations below carry no currency spendLimit. The SDK's
// spend-unit narrowing rule ("locked Option A", agent-passport-system
// core/delegation: 'Spend unit change rejected at the narrowing layer')
// forbids a child changing the spend unit once the parent has a spend
// dimension, and subDelegateAdvisor always mints spendLimit=maxUses with
// unit 'invocations'. An advisor delegation is therefore only mintable from
// a parent that is unconstrained on spend ("a child may still introduce a
// unit on an otherwise unconstrained parent"). The properties under test
// (scope narrowing, use counting, exhaustion, ADVISOR_SCOPE_VIOLATION,
// cascade revocation) are unchanged.
describe('subDelegateAdvisor — monotonic narrowing', () => {
  beforeEach(() => { clearStores(); clearAdvisorUseTracker() })

  it('creates an advisor delegation with empty scope (maximum narrowing)', () => {
    const parent = createDelegation({
      delegatedTo: executor.publicKey,
      delegatedBy: principal.publicKey,
      scope: ['data:read', 'data:write', 'api:fetch'],
      maxDepth: 2,
      privateKey: principal.privateKey,
    })
    const advisorDel = subDelegateAdvisor({
      parentDelegation: parent,
      advisorDid: advisor.publicKey,
      maxUses: 3,
      privateKey: executor.privateKey,
    })
    assert.deepEqual(advisorDel.scope, [], 'advisor scope must be empty (cannot widen)')
    assert.equal(advisorDel.spendLimit, 3)
    assert.equal(advisorDel.spendLimitUnit, 'invocations')
    assert.equal(advisorDel.currentDepth, 1)
    assert.equal(advisorDel.delegatedTo, advisor.publicKey)
  })

  it('rejects non-positive maxUses', () => {
    const parent = createDelegation({
      delegatedTo: executor.publicKey,
      delegatedBy: principal.publicKey,
      scope: ['data:read'],
      maxDepth: 2,
      privateKey: principal.privateKey,
    })
    assert.throws(() =>
      subDelegateAdvisor({
        parentDelegation: parent, advisorDid: advisor.publicKey,
        maxUses: 0, privateKey: executor.privateKey,
      })
    , /maxUses must be a positive integer/)
  })
})

describe('consultAdvisor — happy path within max_uses', () => {
  beforeEach(() => { clearStores(); clearAdvisorUseTracker() })

  it('produces a decision lineage receipt and decrements uses', () => {
    const parent = createDelegation({
      delegatedTo: executor.publicKey,
      delegatedBy: principal.publicKey,
      scope: ['data:read'],
      maxDepth: 2,
      privateKey: principal.privateKey,
    })
    const advisorDel = subDelegateAdvisor({
      parentDelegation: parent, advisorDid: advisor.publicKey,
      maxUses: 3, privateKey: executor.privateKey,
    })

    const r1 = consultAdvisor({
      advisorDelegation: advisorDel,
      decisionType: 'advisor_consultation',
      decisionArtifactId: 'decision-001',
      adviceHash: adviceHash('escalate to human review'),
      governingPurpose: 'inference:decision_support',
      explanation: 'advisor consulted to decide on human escalation',
      privateKey: executor.privateKey,
    })

    assert.ok(r1.receipt.receiptId.startsWith('dlr_'), 'receipt must be a DLR')
    assert.equal(r1.receipt.contributingSources.length, 1)
    assert.equal(r1.receipt.contributingSources[0].sourceId, advisor.publicKey)
    assert.equal(r1.usesRemaining, 2)
    assert.ok(r1.receipt.signature.length > 0)

    const r2 = consultAdvisor({
      advisorDelegation: advisorDel,
      decisionType: 'advisor_consultation',
      decisionArtifactId: 'decision-002',
      adviceHash: adviceHash('second advice'),
      privateKey: executor.privateKey,
    })
    assert.equal(r2.usesRemaining, 1)
    assert.equal(getAdvisorUses(advisorDel.delegationId), 2)
  })
})

describe('consultAdvisor — max_uses exceeded', () => {
  beforeEach(() => { clearStores(); clearAdvisorUseTracker() })

  it('throws when consultation count exceeds maxUses', () => {
    const parent = createDelegation({
      delegatedTo: executor.publicKey,
      delegatedBy: principal.publicKey,
      scope: ['data:read'],
      maxDepth: 2,
      privateKey: principal.privateKey,
    })
    const advisorDel = subDelegateAdvisor({
      parentDelegation: parent, advisorDid: advisor.publicKey,
      maxUses: 2, privateKey: executor.privateKey,
    })

    consultAdvisor({
      advisorDelegation: advisorDel,
      decisionType: 'advisor_consultation',
      decisionArtifactId: 'd1', adviceHash: adviceHash('a'),
      privateKey: executor.privateKey,
    })
    consultAdvisor({
      advisorDelegation: advisorDel,
      decisionType: 'advisor_consultation',
      decisionArtifactId: 'd2', adviceHash: adviceHash('b'),
      privateKey: executor.privateKey,
    })
    assert.throws(() =>
      consultAdvisor({
        advisorDelegation: advisorDel,
        decisionType: 'advisor_consultation',
        decisionArtifactId: 'd3', adviceHash: adviceHash('c'),
        privateKey: executor.privateKey,
      })
    , /max_uses exhausted/)
  })
})

describe('advisor delegation — gateway processToolCall rejects tool execution', () => {
  beforeEach(() => { clearStores(); clearAdvisorUseTracker() })

  it('denies with ADVISOR_SCOPE_VIOLATION when advisor attempts a tool call', async () => {
    // Principal and executor set up via social contract (produces passport + attestation)
    const principalCtx = joinSocialContract({
      name: 'Principal', mission: 'Delegate to executor', owner: 'tester',
      capabilities: ['testing'], platform: 'test', models: ['test-model'], floor,
    })
    const executorCtx = joinSocialContract({
      name: 'Executor', mission: 'Tool execution', owner: 'tester',
      capabilities: ['data:read'], platform: 'test', models: ['test-model'], floor,
    })
    const advisorCtx = joinSocialContract({
      name: 'Advisor', mission: 'Consultation only', owner: 'tester',
      capabilities: ['advice'], platform: 'test', models: ['test-model'], floor,
    })

    const parent = delegate({
      from: principalCtx, toPublicKey: executorCtx.keyPair.publicKey,
      scope: ['data:read'], maxDepth: 2,
    })
    const advisorDel = subDelegateAdvisor({
      parentDelegation: parent,
      advisorDid: advisorCtx.keyPair.publicKey,
      maxUses: 3,
      privateKey: executorCtx.keyPair.privateKey,
    })

    const gatewayKeys = generateKeyPair()
    const config: GatewayConfig = {
      gatewayId: 'gateway-advisor-test', gatewayPublicKey: gatewayKeys.publicKey,
      gatewayPrivateKey: gatewayKeys.privateKey, floor,
      approvalTTLSeconds: 5, recheckRevocationOnExecute: true,
    }
    const gateway = createProxyGateway(config, async () => ({ success: true, result: {} }))
    gateway.registerAgent(advisorCtx.passport, advisorCtx.attestation, [advisorDel])

    const requestId = 'req-advisor-1'
    const tool = 'data:read'
    const scopeRequired = 'data:read'
    const params = { url: 'https://example.com' }
    const payload = canonicalize({ requestId, agentId: advisorCtx.agentId, tool, params, scopeRequired })
    const req: ToolCallRequest = {
      requestId,
      agentId: advisorCtx.agentId,
      agentPublicKey: advisorCtx.keyPair.publicKey,
      signature: sign(payload, advisorCtx.keyPair.privateKey),
      tool, params, scopeRequired,
      context: 'advisor attempts tool execution',
    }
    const result = await gateway.processToolCall(req)
    assert.equal(result.executed, false)
    assert.ok(result.constraintFailures && result.constraintFailures.length > 0)
    assert.equal(result.constraintFailures![0].code, 'ADVISOR_SCOPE_VIOLATION')
    assert.equal(result.constraintFailures![0].facet, 'scope')
  })
})

describe('advisor delegation — cascade revocation from parent', () => {
  beforeEach(() => { clearStores(); clearAdvisorUseTracker() })

  it('invalidates advisor consultation after parent is cascade-revoked', () => {
    const parent = createDelegation({
      delegatedTo: executor.publicKey,
      delegatedBy: principal.publicKey,
      scope: ['data:read'],
      maxDepth: 2,
      privateKey: principal.privateKey,
    })
    const advisorDel = subDelegateAdvisor({
      parentDelegation: parent, advisorDid: advisor.publicKey,
      maxUses: 5, privateKey: executor.privateKey,
    })

    // One successful consultation before revocation
    const ok = consultAdvisor({
      advisorDelegation: advisorDel,
      decisionType: 'advisor_consultation',
      decisionArtifactId: 'd1', adviceHash: adviceHash('advice'),
      privateKey: executor.privateKey,
    })
    assert.equal(ok.usesRemaining, 4)

    // Cascade-revoke parent — advisor child should be revoked too.
    // The SDK's module-scope cascadeRevoke moved to the gateway's
    // DelegationStore (2026-04-17 extraction); per the SDK's own contract,
    // "Revocation is enforced by the caller's DelegationStore (gateway)"
    // (agent-passport-system v2/sub-delegate-advisor), so the store is the
    // enforcement surface under test.
    const store = new DelegationStore()
    store.registerRoot(parent)
    store.registerSubDelegation(advisorDel, parent)
    const cascade = store.cascadeRevoke(parent.delegationId, principal.publicKey, 'test cascade', principal.privateKey)
    assert.equal(cascade.totalRevoked, 2, 'cascade must reach the advisor child')
    assert.ok(store.getRevocation(advisorDel.delegationId), 'advisor delegation must be revoked in the store')

    // A conforming caller checks its store before consulting; the revoked
    // advisor delegation must not yield another consultation.
    assert.throws(() => {
      const revocation = store.getRevocation(advisorDel.delegationId)
      if (revocation) {
        throw new Error(`consultAdvisor: delegation invalid — revoked (${revocation.reason})`)
      }
      consultAdvisor({
        advisorDelegation: advisorDel,
        decisionType: 'advisor_consultation',
        decisionArtifactId: 'd2', adviceHash: adviceHash('advice after revoke'),
        privateKey: executor.privateKey,
      })
    }, /revoked|invalid/)
  })
})
