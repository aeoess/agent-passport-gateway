// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Layer Integration — Wiring isolated modules into a unified protocol
// ══════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). Product intelligence —
// bridges between protocol layers:
//   Commerce → Intent/Policy (require declaration before checkout)
//   Commerce → Attribution   (commerce receipts feed attribution)
//   Commerce → Delegation    (use real delegation verification)
//   Coordination → Agora     (auto-post lifecycle events)
// ══════════════════════════════════════════════════════════════════

import {
  createActionIntent, evaluateIntent,
  createAgoraMessage, appendToFeed,
  verifyDelegation, scopeAuthorizes,
} from 'agent-passport-system'
import { commercePreflight } from './commerce-preflight.js'
import type { SignedPassport, ActionReceipt, Delegation, RevocationRecord } from 'agent-passport-system'
import type { ActionIntent, PolicyDecision, PolicyValidator, ValidationContext } from 'agent-passport-system'
import type {
  CommerceDelegation, CommerceActionReceipt,
  ACPMoney, CommercePreflightResult,
} from 'agent-passport-system'
import type { AgoraFeed, AgoraMessage, AgoraRegistry } from 'agent-passport-system'
import type { TaskBrief, ReviewDecision, TaskCompletion } from 'agent-passport-system'

// ══════════════════════════════════════
// 1. COMMERCE → INTENT/POLICY
// ══════════════════════════════════════

export interface CommerceIntentResult {
  intent: ActionIntent
  decision: PolicyDecision
  preflight: CommercePreflightResult
  permitted: boolean
  blockedAt?: 'policy' | 'preflight'
  reason?: string
}

export function commerceWithIntent(opts: {
  signedPassport: SignedPassport
  agentPrivateKey: string
  delegation: Delegation
  commerceDelegation: CommerceDelegation
  merchantName: string
  estimatedTotal: ACPMoney
  actionDescription: string
  validator: PolicyValidator
  validationContext: ValidationContext
  evaluatorId: string
  evaluatorPublicKey: string
  evaluatorPrivateKey: string
}): CommerceIntentResult {
  const intent = createActionIntent({
    agentId: opts.signedPassport.passport.agentId,
    agentPublicKey: opts.signedPassport.passport.publicKey,
    delegationId: opts.delegation.delegationId,
    action: {
      type: 'commerce:checkout',
      scopeRequired: 'commerce:checkout',
      target: opts.merchantName,
      spend: { amount: opts.estimatedTotal.amount, currency: opts.estimatedTotal.currency },
    },
    context: `Commerce: ${opts.merchantName} — ${opts.estimatedTotal.amount} ${opts.estimatedTotal.currency}. ${opts.actionDescription}`,
    privateKey: opts.agentPrivateKey,
  })

  const decision = evaluateIntent({
    intent,
    validator: opts.validator,
    validationContext: opts.validationContext,
    evaluatorId: opts.evaluatorId,
    evaluatorPublicKey: opts.evaluatorPublicKey,
    evaluatorPrivateKey: opts.evaluatorPrivateKey,
  })

  if (decision.verdict !== 'permit') {
    return {
      intent,
      decision,
      preflight: {
        permitted: false,
        checks: [],
        delegation: opts.commerceDelegation,
        warnings: [],
        blockedReason: `Policy denied: ${decision.verdict} — ${decision.reason}`,
      },
      permitted: false,
      blockedAt: 'policy',
      reason: decision.reason,
    }
  }

  const preflight = commercePreflight({
    signedPassport: opts.signedPassport,
    delegation: opts.commerceDelegation,
    merchantName: opts.merchantName,
    estimatedTotal: opts.estimatedTotal,
  })

  return {
    intent,
    decision,
    preflight,
    permitted: preflight.permitted,
    blockedAt: preflight.permitted ? undefined : 'preflight',
    reason: preflight.permitted ? undefined : preflight.blockedReason,
  }
}

// ══════════════════════════════════════
// 2. COMMERCE → ATTRIBUTION
// ══════════════════════════════════════

export function commerceReceiptToActionReceipt(
  commerceReceipt: CommerceActionReceipt,
  resultStatus: 'success' | 'failure' | 'partial' = 'success',
): ActionReceipt {
  return {
    receiptId: commerceReceipt.receiptId,
    version: commerceReceipt.version,
    timestamp: commerceReceipt.timestamp,
    agentId: commerceReceipt.agentId,
    delegationId: commerceReceipt.delegationId,
    action: {
      type: commerceReceipt.action.type,
      target: commerceReceipt.action.target,
      method: commerceReceipt.action.method,
      scopeUsed: commerceReceipt.action.scopeUsed,
      spend: commerceReceipt.action.spend,
    },
    result: {
      status: resultStatus,
      summary: `${commerceReceipt.checkout.merchantName}: ${commerceReceipt.checkout.items.length} items, ` +
        `${commerceReceipt.checkout.totalAmount} ${commerceReceipt.checkout.totalCurrency} — ` +
        `${commerceReceipt.checkout.status}`,
    },
    delegationChain: commerceReceipt.delegationChain,
    signature: commerceReceipt.signature,
  }
}

// ══════════════════════════════════════
// 3. COMMERCE → DELEGATION
// ══════════════════════════════════════

export interface DelegationValidationResult {
  valid: boolean
  errors: string[]
  scopeMatch: boolean
  withinSpendLimit: boolean
  notRevoked: boolean
}

export function validateCommerceDelegation(
  commerceDelegation: CommerceDelegation,
  protocolDelegation: Delegation,
  opts?: {
    /**
     * Point-in-time revocation record for the protocol delegation, supplied by
     * the caller from its DelegationStore (the SDK's module-scope revocation
     * registry moved there in the 2026-04-17 extraction — see
     * delegation-store.ts). Omitting it means "no cached revocation state",
     * mirroring ScopedDelegationContract.verify(); it is not a claim of live
     * non-revocation.
     */
    revocation?: RevocationRecord
  },
): DelegationValidationResult {
  const errors: string[] = []

  if (commerceDelegation.delegationId !== protocolDelegation.delegationId) {
    errors.push(`Delegation ID mismatch: commerce=${commerceDelegation.delegationId}, protocol=${protocolDelegation.delegationId}`)
  }

  const revocation = opts?.revocation
  const notRevoked = !revocation
  if (revocation) {
    errors.push(`Delegation revoked at ${revocation.revokedAt}: ${revocation.reason || 'no reason'}`)
  }

  const verifyResult = verifyDelegation(protocolDelegation)
  if (!verifyResult.valid) {
    errors.push(...verifyResult.errors)
  }

  const scopeMatch = commerceDelegation.scope.every(
    s => scopeAuthorizes(protocolDelegation.scope, s)
  )
  if (!scopeMatch) {
    errors.push(`Commerce scopes [${commerceDelegation.scope.join(', ')}] not within protocol scopes [${protocolDelegation.scope.join(', ')}]`)
  }

  const protocolLimit = protocolDelegation.spendLimit ?? Infinity
  const withinSpendLimit = commerceDelegation.spendLimit <= protocolLimit
  if (!withinSpendLimit) {
    errors.push(`Commerce spend limit ${commerceDelegation.spendLimit} exceeds protocol limit ${protocolLimit}`)
  }

  return {
    valid: errors.length === 0,
    errors,
    scopeMatch,
    withinSpendLimit,
    notRevoked,
  }
}

// ══════════════════════════════════════
// 4. COORDINATION → AGORA
// ══════════════════════════════════════

export type CoordinationEventType =
  | 'task_created'
  | 'task_assigned'
  | 'evidence_submitted'
  | 'review_completed'
  | 'evidence_handed_off'
  | 'deliverable_submitted'
  | 'task_completed'

export function coordinationToAgora(opts: {
  event: CoordinationEventType
  taskId: string
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
  detail: string
}): { message: AgoraMessage; feed: AgoraFeed } {
  const subjects: Record<CoordinationEventType, string> = {
    task_created: `📋 New task: ${opts.taskId}`,
    task_assigned: `👤 Agent assigned to ${opts.taskId}`,
    evidence_submitted: `📎 Evidence submitted for ${opts.taskId}`,
    review_completed: `✅ Review completed on ${opts.taskId}`,
    evidence_handed_off: `🤝 Evidence handed off in ${opts.taskId}`,
    deliverable_submitted: `📦 Deliverable submitted for ${opts.taskId}`,
    task_completed: `🏁 Task completed: ${opts.taskId}`,
  }

  const message = createAgoraMessage({
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    topic: `coordination:${opts.taskId}`,
    type: 'announcement',
    subject: subjects[opts.event],
    content: opts.detail,
  })

  const updatedFeed = appendToFeed(opts.feed, message)

  return { message, feed: updatedFeed }
}

export function postTaskCreated(opts: {
  brief: TaskBrief
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
}): { message: AgoraMessage; feed: AgoraFeed } {
  return coordinationToAgora({
    event: 'task_created',
    taskId: opts.brief.taskId,
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    feed: opts.feed,
    registry: opts.registry,
    detail: `Task "${opts.brief.title}" created with ${opts.brief.roles.length} roles and ${opts.brief.deliverables.length} deliverables. ${opts.brief.description}`,
  })
}

export function postReviewCompleted(opts: {
  review: ReviewDecision
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
}): { message: AgoraMessage; feed: AgoraFeed } {
  return coordinationToAgora({
    event: 'review_completed',
    taskId: opts.review.taskId,
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    feed: opts.feed,
    registry: opts.registry,
    detail: `Review verdict: ${opts.review.verdict} (score: ${opts.review.score}/${opts.review.threshold}). ${opts.review.rationale}`,
  })
}

export function postTaskCompleted(opts: {
  completion: TaskCompletion
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  feed: AgoraFeed
  registry: AgoraRegistry
}): { message: AgoraMessage; feed: AgoraFeed } {
  return coordinationToAgora({
    event: 'task_completed',
    taskId: opts.completion.taskId,
    agentId: opts.agentId,
    agentName: opts.agentName,
    publicKey: opts.publicKey,
    privateKey: opts.privateKey,
    feed: opts.feed,
    registry: opts.registry,
    detail: `Status: ${opts.completion.status}. Agents: ${opts.completion.metrics.agentCount}, ` +
      `Duration: ${opts.completion.metrics.totalDuration}s, ` +
      `Rework cycles: ${opts.completion.metrics.reworkCount}. ` +
      (opts.completion.retrospective || ''),
  })
}
