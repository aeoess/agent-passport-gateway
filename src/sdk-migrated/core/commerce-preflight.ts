// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Commerce Preflight — 6-gate orchestrator + ACP fetch wrappers
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). The SDK retains the pure
// gate predicate primitives (checkPassportGate, checkScopeGate,
// checkSpendGate, checkHumanApprovalThreshold, checkMerchantGate,
// checkWalletGate) plus signCommerceReceipt and extractDelegationChain.
// The 6-gate pipeline that composes them, plus the four ACP REST
// wrappers (createCheckout/updateCheckout/completeCheckout/cancelCheckout),
// live here as gateway product workflow.
// ══════════════════════════════════════════════════════════════════════

import {
  checkPassportGate, checkScopeGate, checkSpendGate,
  checkHumanApprovalThreshold, checkMerchantGate, checkWalletGate,
  signCommerceReceipt, extractDelegationChain,
} from 'agent-passport-system'
import type {
  SignedPassport,
  ACPCheckoutSession, ACPMoney, ACPAddress,
  CommerceConfig, CommerceDelegation,
  CommercePreflightResult, CommercePreflightCheck,
  CommerceActionReceipt,
  IdempotencyStore,
} from 'agent-passport-system'

// Wallet types for the optional gate-5 binding check.
type WalletChain = 'ethereum' | 'solana' | 'bitcoin' | 'sui' | 'polygon' | 'base' | 'arbitrum' | 'optimism' | 'nano'

// ── Preflight Check: 6-Gate Pipeline ──
// Gates: passport_valid → delegation_scope → spend_limit → merchant_approved
//      → wallet_bound (optional) → idempotency (optional)

export function commercePreflight(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
  idempotencyKey: string
  idempotencyStore: IdempotencyStore
  idempotencyWindowSeconds?: number
}): Promise<CommercePreflightResult>
export function commercePreflight(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
}): CommercePreflightResult
export function commercePreflight(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  config?: CommerceConfig
  walletRef?: { chain: WalletChain; address: string }
  idempotencyKey?: string
  idempotencyStore?: IdempotencyStore
  idempotencyWindowSeconds?: number
}): CommercePreflightResult | Promise<CommercePreflightResult> {
  const checks: CommercePreflightCheck[] = []
  const warnings: string[] = []

  // Gate 1: Passport verification
  checks.push(checkPassportGate(opts.signedPassport))

  // Gate 2: Delegation scope
  checks.push(checkScopeGate(opts.delegation))

  // Gate 3: Spend limit
  checks.push(checkSpendGate(opts.delegation, opts.estimatedTotal))

  // Gate 3b: Human approval threshold (warning, not gate)
  const approvalWarning = checkHumanApprovalThreshold(opts.delegation, opts.estimatedTotal)
  if (approvalWarning) warnings.push(approvalWarning)

  // Gate 4: Merchant allowlist (if configured)
  const merchantGate = checkMerchantGate(opts.delegation, opts.merchantName)
  if (merchantGate) checks.push(merchantGate)

  // Gate 5: Wallet binding (only when the action references a specific wallet)
  if (opts.walletRef) {
    checks.push(checkWalletGate(opts.signedPassport, opts.walletRef))
  }

  // Gate 6: Idempotency check (async, only if key + store provided)
  if (opts.idempotencyKey && opts.idempotencyStore) {
    const windowSeconds = opts.idempotencyWindowSeconds ?? 300
    return opts.idempotencyStore.check(opts.idempotencyKey, windowSeconds).then(result => {
      if (result.duplicate) {
        checks.push({
          check: 'idempotency',
          passed: false,
          detail: `Duplicate operation within ${windowSeconds}s window (existing receipt: ${result.existingReceiptId})`,
        })
      } else {
        checks.push({
          check: 'idempotency',
          passed: true,
          detail: `No duplicate found for idempotency key`,
        })
      }

      const permitted = checks.every(c => c.passed)
      return {
        permitted,
        checks,
        delegation: opts.delegation,
        warnings,
        blockedReason: permitted ? undefined : checks.find(c => !c.passed)?.detail,
        existingReceiptId: result.duplicate ? result.existingReceiptId : undefined,
      }
    })
  }

  const permitted = checks.every(c => c.passed)
  return {
    permitted,
    checks,
    delegation: opts.delegation,
    warnings,
    blockedReason: permitted ? undefined : checks.find(c => !c.passed)?.detail,
  }
}

// ── ACP Client: Create Checkout Session ──

export async function createCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  items: { skuId: string; quantity: number }[]
  customer?: { name?: string; email?: string }
  fulfillmentAddress?: ACPAddress
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  const preflight = commercePreflight({
    signedPassport: opts.signedPassport,
    delegation: opts.delegation,
    merchantName: opts.config.merchantName,
    estimatedTotal: { amount: 0, currency: opts.delegation.currency },
  })

  if (!preflight.permitted) {
    throw new Error(`Commerce preflight DENIED: ${preflight.blockedReason}`)
  }

  const requestBody = {
    items: opts.items.map(i => ({ sku_id: i.skuId, quantity: i.quantity })),
    ...(opts.customer && { customer: opts.customer }),
    ...(opts.fulfillmentAddress && { fulfillment_address: opts.fulfillmentAddress }),
  }

  const url = `${opts.config.merchantBaseUrl}/checkout_sessions`
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
    body: JSON.stringify(requestBody),
  })

  if (!response.ok) {
    throw new Error(`ACP CreateCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:create_checkout',
    target: url,
    method: 'POST',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt }
}

// ── ACP Client: Update Checkout Session ──

export async function updateCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  updates: {
    items?: { id: string; quantity: number }[]
    fulfillmentAddress?: ACPAddress
    fulfillmentOptionId?: string
  }
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  const url = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}`
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
    body: JSON.stringify({
      ...(opts.updates.items && { items: opts.updates.items }),
      ...(opts.updates.fulfillmentAddress && { fulfillment_address: opts.updates.fulfillmentAddress }),
      ...(opts.updates.fulfillmentOptionId && { fulfillment_option_id: opts.updates.fulfillmentOptionId }),
    }),
  })

  if (!response.ok) {
    throw new Error(`ACP UpdateCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:update_checkout',
    target: url,
    method: 'PUT',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt }
}

// ── ACP Client: Complete Checkout (Payment) ──

export async function completeCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  paymentToken: string
  paymentMethod?: string
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt; spendUpdated: CommerceDelegation }> {
  const getUrl = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}`
  const getResponse = await fetch(getUrl, {
    headers: opts.config.bearerToken ? { 'Authorization': `Bearer ${opts.config.bearerToken}` } : {},
  })

  if (!getResponse.ok) {
    throw new Error(`ACP GetCheckout failed: ${getResponse.status}`)
  }

  const currentSession: ACPCheckoutSession = await getResponse.json() as ACPCheckoutSession
  const total = currentSession.totals.total

  const preflight = commercePreflight({
    signedPassport: opts.signedPassport,
    delegation: opts.delegation,
    merchantName: opts.config.merchantName,
    estimatedTotal: total,
  })

  if (!preflight.permitted) {
    throw new Error(`Commerce preflight DENIED at payment: ${preflight.blockedReason}`)
  }

  if (opts.delegation.requireHumanApproval && opts.delegation.humanApprovalThreshold) {
    if (total.amount > opts.delegation.humanApprovalThreshold) {
      throw new Error(
        `HUMAN_APPROVAL_REQUIRED: Purchase of ${total.amount} ${total.currency} exceeds threshold of ${opts.delegation.humanApprovalThreshold}. ` +
        `Use requestHumanApproval() to get confirmation before completing.`
      )
    }
  }

  const url = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}/complete`
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
    body: JSON.stringify({
      payment_token: opts.paymentToken,
      ...(opts.paymentMethod && { payment_method: opts.paymentMethod }),
    }),
  })

  if (!response.ok) {
    throw new Error(`ACP CompleteCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  const spendUpdated: CommerceDelegation = {
    ...opts.delegation,
    spentAmount: opts.delegation.spentAmount + total.amount,
  }

  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:complete_checkout',
    target: url,
    method: 'POST',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt, spendUpdated }
}

// ── ACP Client: Cancel Checkout ──

export async function cancelCheckout(opts: {
  signedPassport: SignedPassport
  delegation: CommerceDelegation
  config: CommerceConfig
  sessionId: string
  privateKey: string
}): Promise<{ session: ACPCheckoutSession; receipt: CommerceActionReceipt }> {
  const url = `${opts.config.merchantBaseUrl}/checkout_sessions/${opts.sessionId}/cancel`
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.config.bearerToken && { 'Authorization': `Bearer ${opts.config.bearerToken}` }),
    },
  })

  if (!response.ok) {
    throw new Error(`ACP CancelCheckout failed: ${response.status} ${response.statusText}`)
  }

  const session: ACPCheckoutSession = await response.json() as ACPCheckoutSession

  const receipt = signCommerceReceipt({
    agentId: opts.signedPassport.passport.agentId,
    delegationId: opts.delegation.delegationId,
    actionType: 'commerce:cancel_checkout',
    target: url,
    method: 'POST',
    session,
    merchantName: opts.config.merchantName,
    delegationChain: extractDelegationChain(opts.signedPassport),
    beneficiary: opts.signedPassport.passport.metadata?.beneficiaryPrincipalId as string || 'unknown',
    privateKey: opts.privateKey,
  })

  return { session, receipt }
}
