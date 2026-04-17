// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Tests migrated from agent-passport-system/tests/adapters.test.ts (2026-04-17).
 * Only the GovernanceHook class survived the move; the framework-specific v1
 * factories (createA2AGovernance, createADKGovernancePlugin, etc.) were product
 * runtime and are retired. Callers should compose GovernanceHook with the
 * public adapter primitives in the SDK.
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from 'agent-passport-system'
import { GovernanceHook } from '../../src/sdk-migrated/governance-hook.js'
import type { GovernanceHookConfig, ActionDescriptor } from '../../src/sdk-migrated/governance-hook.js'

const keys = generateKeyPair()

function makeConfig(overrides?: Partial<GovernanceHookConfig>): GovernanceHookConfig {
  return {
    agentId: 'test-agent',
    agentPublicKey: keys.publicKey,
    agentPrivateKey: keys.privateKey,
    delegationId: 'del-001',
    allowedScopes: ['data:read', 'tool:search', 'commerce:checkout'],
    ...overrides,
  }
}

describe('GovernanceHook — Core (migrated)', () => {
  it('permits action within scope', () => {
    const hook = new GovernanceHook(makeConfig())
    const result = hook.beforeAction({ type: 'read', target: 'db', scopeRequired: 'data:read' })
    assert.equal(result.verdict, 'permit')
    assert.ok(result.intentId.startsWith('intent_'))
    assert.ok(result.reason.includes('authorized'))
  })

  it('denies action outside scope', () => {
    const hook = new GovernanceHook(makeConfig())
    const result = hook.beforeAction({ type: 'delete', target: 'db', scopeRequired: 'admin:delete' })
    assert.equal(result.verdict, 'deny')
    assert.ok(result.violations!.length > 0)
    assert.ok(result.violations![0].includes('admin:delete'))
  })

  it('supports wildcard scopes', () => {
    const hook = new GovernanceHook(makeConfig({ allowedScopes: ['data:*'] }))
    const result = hook.beforeAction({ type: 'read', target: 'db', scopeRequired: 'data:read' })
    assert.equal(result.verdict, 'permit')
  })

  it('denies when spend exceeds limit', () => {
    const hook = new GovernanceHook(makeConfig({ spendLimitPerAction: 100 }))
    const result = hook.beforeAction({
      type: 'purchase', target: 'store', scopeRequired: 'commerce:checkout', estimatedCost: 150,
    })
    assert.equal(result.verdict, 'deny')
    assert.ok(result.violations![0].includes('150'))
  })

  it('generates signed receipt after action', () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'read', target: 'db', scopeRequired: 'data:read' }
    const gov = hook.beforeAction(action)
    const receipt = hook.afterAction(gov, action, 'success', new Date().toISOString())
    assert.ok(receipt.receiptId.startsWith('rcpt_'))
    assert.equal(receipt.verdict, 'permit')
    assert.equal(receipt.executionResult, 'success')
    assert.ok(receipt.signature)
    assert.ok(receipt.durationMs >= 0)
  })

  it('receipt signature is verifiable', () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'read', target: 'db', scopeRequired: 'data:read' }
    const gov = hook.beforeAction(action)
    const receipt = hook.afterAction(gov, action, 'success', new Date().toISOString())
    assert.equal(hook.verifyReceipt(receipt), true)
  })

  it('wrap() governs async action end-to-end', async () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'search', target: 'api', scopeRequired: 'tool:search' }
    const { result, receipt, governance } = await hook.wrap(action, async () => 'search results')
    assert.equal(governance.verdict, 'permit')
    assert.equal(result, 'search results')
    assert.equal(receipt.executionResult, 'success')
  })

  it('wrap() blocks denied action without executing', async () => {
    const hook = new GovernanceHook(makeConfig())
    let executed = false
    const action: ActionDescriptor = { type: 'delete', target: 'db', scopeRequired: 'admin:nuke' }
    const { result, governance } = await hook.wrap(action, async () => { executed = true; return 'bad' })
    assert.equal(governance.verdict, 'deny')
    assert.equal(result, null)
    assert.equal(executed, false)
  })

  it('tracks cumulative spend', async () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'buy', target: 'store', scopeRequired: 'commerce:checkout', estimatedCost: 25 }
    await hook.wrap(action, async () => 'purchased')
    await hook.wrap(action, async () => 'purchased')
    assert.equal(hook.getTotalSpend(), 50)
    assert.equal(hook.getReceipts().length, 2)
  })
})
