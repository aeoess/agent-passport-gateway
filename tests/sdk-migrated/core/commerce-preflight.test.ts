// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests migrated from SDK (tests/commerce.test.ts and tests/idempotency.test.ts)
// after the 6-gate orchestrator was extracted to the gateway. Verifies the
// pipeline composition over SDK gate predicates and the idempotency gate.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  createCommerceDelegation,
  computeIdempotencyKey,
  bindWallet,
} from 'agent-passport-system'
import type { IdempotencyStore, CommercePreflightResult } from 'agent-passport-system'
import { commercePreflight } from '../../../src/sdk-migrated/core/commerce-preflight.js'

function makeFixtures() {
  const { signedPassport } = createPassport({
    agentId: 'shopper-001',
    agentName: 'ShopperAgent',
    ownerAlias: 'tima',
    mission: 'Find and purchase products within delegated budget',
    capabilities: ['commerce', 'web-search', 'product-comparison'],
    runtime: { platform: 'node', models: ['claude-sonnet-4-20250514'], toolsCount: 5, memoryType: 'session' },
    metadata: { beneficiaryPrincipalId: 'tima-principal-001' },
  })

  const delegation = createCommerceDelegation({
    agentId: 'shopper-001',
    delegationId: 'del-commerce-001',
    spendLimit: 50000,
    currency: 'usd',
    approvedMerchants: ['Cartsy', 'TechStore', 'BookShelf'],
    requireHumanApproval: true,
    humanApprovalThreshold: 25000,
  })

  return { passport: signedPassport, delegation }
}

function makePassport() {
  const { signedPassport } = createPassport({
    agentId: `agent-idemp-${Date.now()}`,
    agentName: 'Idempotency Test Agent',
    ownerAlias: 'test',
    mission: 'Test idempotency',
    capabilities: ['commerce'],
    runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'session' },
  })
  return signedPassport
}

function makeDelegation(agentId: string) {
  return createCommerceDelegation({
    agentId,
    delegationId: `del-idemp-${Date.now()}`,
    spendLimit: 100000,
    currency: 'usd',
    approvedMerchants: ['TestMerchant'],
  })
}

function makeInMemoryStore(): IdempotencyStore & { _entries: Map<string, { receiptId: string; recordedAt: number }> } {
  const entries = new Map<string, { receiptId: string; recordedAt: number }>()
  return {
    _entries: entries,
    async check(key: string, windowSeconds: number) {
      const entry = entries.get(key)
      if (!entry) return { duplicate: false }
      const age = (Date.now() - entry.recordedAt) / 1000
      if (age > windowSeconds) return { duplicate: false }
      return { duplicate: true, existingReceiptId: entry.receiptId }
    },
    async record(key: string, receiptId: string) {
      entries.set(key, { receiptId, recordedAt: Date.now() })
    },
  }
}

describe('commercePreflight — 6-gate pipeline', () => {
  it('passes all gates when everything is valid', () => {
    const { passport, delegation } = makeFixtures()
    const result = commercePreflight({
      signedPassport: passport,
      delegation,
      merchantName: 'Cartsy',
      estimatedTotal: { amount: 2600, currency: 'usd' },
    })
    assert.equal(result.permitted, true)
    assert.equal(result.blockedReason, undefined)
    assert.ok(result.checks.every(c => c.passed))
  })

  it('blocks when agent lacks commerce scope', () => {
    const { passport } = makeFixtures()
    const badDelegation = createCommerceDelegation({
      agentId: 'shopper-001',
      delegationId: 'del-bad',
      spendLimit: 50000,
    })
    badDelegation.scope = ['web:search', 'web:fetch']

    const result = commercePreflight({
      signedPassport: passport,
      delegation: badDelegation,
      merchantName: 'Cartsy',
      estimatedTotal: { amount: 1000, currency: 'usd' },
    })
    assert.equal(result.permitted, false)
    assert.ok(result.blockedReason?.includes('commerce:checkout'))
  })

  it('blocks when purchase exceeds spend limit', () => {
    const { passport, delegation } = makeFixtures()
    delegation.spentAmount = 49000

    const result = commercePreflight({
      signedPassport: passport,
      delegation,
      merchantName: 'Cartsy',
      estimatedTotal: { amount: 2000, currency: 'usd' },
    })
    assert.equal(result.permitted, false)
    assert.ok(result.blockedReason?.includes('exceeds'))
  })

  it('blocks when merchant is not on approved list', () => {
    const { passport, delegation } = makeFixtures()
    const result = commercePreflight({
      signedPassport: passport,
      delegation,
      merchantName: 'ShadyStore',
      estimatedTotal: { amount: 1000, currency: 'usd' },
    })
    assert.equal(result.permitted, false)
    assert.ok(result.blockedReason?.includes('NOT on approved list'))
  })

  it('warns when human approval threshold exceeded', () => {
    const { passport, delegation } = makeFixtures()
    const result = commercePreflight({
      signedPassport: passport,
      delegation,
      merchantName: 'TechStore',
      estimatedTotal: { amount: 30000, currency: 'usd' },
    })
    assert.equal(result.permitted, true)
    assert.ok(result.warnings.length > 0)
    assert.ok(result.warnings[0].includes('approval threshold'))
  })

  it('passes with commerce:* wildcard scope', () => {
    const { passport } = makeFixtures()
    const wildcardDelegation = createCommerceDelegation({
      agentId: 'shopper-001',
      delegationId: 'del-wildcard',
      spendLimit: 100000,
    })
    wildcardDelegation.scope = ['commerce:*']

    const result = commercePreflight({
      signedPassport: passport,
      delegation: wildcardDelegation,
      merchantName: 'AnyStore',
      estimatedTotal: { amount: 5000, currency: 'usd' },
    })
    assert.equal(result.permitted, true)
  })

  it('blocks a non-commerce agent', () => {
    const { signedPassport: researchPassport } = createPassport({
      agentId: 'researcher-001',
      agentName: 'ResearchAgent',
      ownerAlias: 'tima',
      mission: 'Research only',
      capabilities: ['web-search', 'document-analysis'],
      runtime: { platform: 'node', models: ['claude-sonnet-4-20250514'], toolsCount: 3, memoryType: 'session' },
    })

    const researchDelegation = createCommerceDelegation({
      agentId: 'researcher-001',
      delegationId: 'del-research',
      spendLimit: 0,
    })
    researchDelegation.scope = ['web:search', 'web:fetch']

    const result = commercePreflight({
      signedPassport: researchPassport,
      delegation: researchDelegation,
      merchantName: 'Cartsy',
      estimatedTotal: { amount: 100, currency: 'usd' },
    })

    assert.equal(result.permitted, false)
    assert.ok(result.blockedReason?.includes('commerce:checkout'))
  })

  it('tracks spend across multiple preflight checks', () => {
    const { passport, delegation } = makeFixtures()

    delegation.spentAmount = 0
    const first = commercePreflight({
      signedPassport: passport, delegation,
      merchantName: 'Cartsy',
      estimatedTotal: { amount: 10000, currency: 'usd' },
    })
    assert.equal(first.permitted, true)

    delegation.spentAmount = 10000
    const second = commercePreflight({
      signedPassport: passport, delegation,
      merchantName: 'TechStore',
      estimatedTotal: { amount: 35000, currency: 'usd' },
    })
    assert.equal(second.permitted, true)

    delegation.spentAmount = 45000
    const third = commercePreflight({
      signedPassport: passport, delegation,
      merchantName: 'BookShelf',
      estimatedTotal: { amount: 10000, currency: 'usd' },
    })
    assert.equal(third.permitted, false)
    assert.ok(third.blockedReason?.includes('exceeds'))
  })
})

describe('commercePreflight — wallet_bound gate (migrated from v2/wallet-binding)', () => {
  function commerceFixture() {
    const { signedPassport, keyPair } = createPassport({
      agentId: `shopper-wallet-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      agentName: 'WalletShopper',
      ownerAlias: 'tima',
      mission: 'Spend Nano via bound wallet',
      capabilities: ['commerce'],
      runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'session' },
    })
    const delegation = createCommerceDelegation({
      agentId: signedPassport.passport.agentId,
      delegationId: `del-wallet-${Date.now()}`,
      spendLimit: 100000,
      currency: 'usd',
      approvedMerchants: ['ApprovedMerchant'],
    })
    return { signedPassport, keyPair, delegation }
  }

  it('denies commerce action referencing an unbound wallet with WALLET_NOT_BOUND', () => {
    const { signedPassport, delegation } = commerceFixture()
    const result = commercePreflight({
      signedPassport,
      delegation,
      merchantName: 'ApprovedMerchant',
      estimatedTotal: { amount: 1000, currency: 'usd' },
      walletRef: { chain: 'nano', address: 'nano_3unbound' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, false)
    const walletCheck = result.checks.find(c => c.check === 'wallet_bound')
    assert.ok(walletCheck, 'wallet_bound check should be present when walletRef provided')
    assert.equal(walletCheck!.passed, false)
    assert.match(walletCheck!.detail, /WALLET_NOT_BOUND/)
  })

  it('permits commerce action when wallet IS bound', () => {
    const { signedPassport, keyPair, delegation } = commerceFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: 'nano_3bound',
    })

    const result = commercePreflight({
      signedPassport: bound,
      delegation,
      merchantName: 'ApprovedMerchant',
      estimatedTotal: { amount: 1000, currency: 'usd' },
      walletRef: { chain: 'nano', address: 'nano_3bound' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, true, `expected permit, blocked: ${result.blockedReason}`)
    const walletCheck = result.checks.find(c => c.check === 'wallet_bound')
    assert.ok(walletCheck)
    assert.equal(walletCheck!.passed, true)
  })

  it('5-gate flow without walletRef is unchanged (wallet_bound check absent)', () => {
    const { signedPassport, delegation } = commerceFixture()
    const result = commercePreflight({
      signedPassport,
      delegation,
      merchantName: 'ApprovedMerchant',
      estimatedTotal: { amount: 1000, currency: 'usd' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    const walletCheck = result.checks.find(c => c.check === 'wallet_bound')
    assert.equal(walletCheck, undefined, 'wallet_bound check should not appear when walletRef omitted')
  })
})

describe('commercePreflight with idempotency', () => {
  it('returns duplicate when idempotency store has match', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    await store.record(key, 'rcpt-existing-123')

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      idempotencyWindowSeconds: 300,
    }) as CommercePreflightResult

    assert.equal(result.permitted, false)
    assert.equal(result.existingReceiptId, 'rcpt-existing-123')
    const idempCheck = result.checks.find(c => c.check === 'idempotency')
    assert.ok(idempCheck)
    assert.equal(idempCheck!.passed, false)
    assert.ok(idempCheck!.detail.includes('Duplicate'))
  })

  it('permits when idempotency store has no match', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      idempotencyWindowSeconds: 300,
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    const idempCheck = result.checks.find(c => c.check === 'idempotency')
    assert.ok(idempCheck)
    assert.equal(idempCheck!.passed, true)
  })

  it('without idempotency key works exactly as before (backward compat)', () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)

    const result = commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    assert.ok(!result.checks.some(c => c.check === 'idempotency'))
  })

  it('window expiry: key recorded, window passes, same key is allowed again', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    store._entries.set(key, { receiptId: 'rcpt-old', recordedAt: Date.now() - 400_000 })

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
      idempotencyWindowSeconds: 300,
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    const idempCheck = result.checks.find(c => c.check === 'idempotency')
    assert.ok(idempCheck)
    assert.equal(idempCheck!.passed, true)
  })

  it('uses default 300s window when idempotencyWindowSeconds not specified', async () => {
    const sp = makePassport()
    const delegation = makeDelegation(sp.passport.agentId)
    const store = makeInMemoryStore()

    const key = computeIdempotencyKey({
      agentId: sp.passport.agentId,
      scope: 'commerce:checkout',
      target: 'TestMerchant',
      amount: { amount: 2000, currency: 'usd' },
    })

    await store.record(key, 'rcpt-default-window')

    const result = await commercePreflight({
      signedPassport: sp,
      delegation,
      merchantName: 'TestMerchant',
      estimatedTotal: { amount: 2000, currency: 'usd' },
      idempotencyKey: key,
      idempotencyStore: store,
    }) as CommercePreflightResult

    assert.equal(result.permitted, false)
    assert.equal(result.existingReceiptId, 'rcpt-default-window')
  })
})
