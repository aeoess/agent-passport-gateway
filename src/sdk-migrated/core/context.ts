// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Agent Context — Automatic Protocol Compliance
// ══════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). Product intelligence —
// stateful runtime that forces every action through the 3-signature
// chain automatically. The agent physically cannot skip enforcement.
//
// Usage:
//   const ctx = createAgentContext(agent, floor, { enforcement: 'auto' })
//   ctx.addDelegation(delegation)
//   const result = ctx.execute({ type: 'api:fetch', scope: 'data:read', target: '...' })
//   const completed = ctx.complete(result, { status: 'success', summary: '...' })
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import {
  sign,
  canonicalize,
  createActionIntent, evaluateIntent, createPolicyReceipt, FloorValidatorV1,
  createReceipt, scopeAuthorizes,
  verifyAttestation,
} from 'agent-passport-system'
import type { SocialContractAgent } from 'agent-passport-system'
import type { ValuesFloor, Delegation, ActionReceipt } from 'agent-passport-system'
import type { ActionIntent, PolicyDecision, PolicyValidator, ValidationContext } from 'agent-passport-system'
import type {
  AgentContextConfig, AgentContextState,
  ExecuteRequest, ExecuteResult, CompletedAction,
  AuditEntry, EnforcementLevel
} from 'agent-passport-system'

// ══════════════════════════════════════
// AGENT CONTEXT CLASS
// ══════════════════════════════════════

export class AgentContext {
  private agent: SocialContractAgent
  private floor: ValuesFloor
  private config: Required<Pick<AgentContextConfig, 'enforcement' | 'decisionTTLMinutes'>> & AgentContextConfig
  private validator: PolicyValidator
  private state: AgentContextState

  constructor(
    agent: SocialContractAgent,
    floor: ValuesFloor,
    config: Partial<AgentContextConfig> = {}
  ) {
    this.agent = agent
    this.floor = floor
    this.validator = config.validator || new FloorValidatorV1()
    this.config = {
      enforcement: config.enforcement || 'auto',
      decisionTTLMinutes: config.decisionTTLMinutes || 5,
      ...config
    }

    this.state = {
      agentId: agent.agentId,
      publicKey: agent.publicKey,
      delegations: new Map(),
      floor,
      attestation: agent.attestation!,
      receipts: [],
      decisions: [],
      policyReceipts: [],
      auditLog: []
    }
  }

  // ── Delegation Management ──

  addDelegation(delegation: Delegation): void {
    this.state.delegations.set(delegation.delegationId, delegation)
  }

  removeDelegation(delegationId: string): boolean {
    return this.state.delegations.delete(delegationId)
  }

  findDelegation(scopeRequired: string): Delegation | null {
    for (const [, d] of this.state.delegations) {
      if (scopeAuthorizes(d.scope, scopeRequired) && new Date(d.expiresAt) > new Date()) {
        return d
      }
    }
    return null
  }

  // ── Core: Execute with Enforcement ──

  execute(request: ExecuteRequest): ExecuteResult {
    const delegation = request.delegationId
      ? this.state.delegations.get(request.delegationId) || null
      : this.findDelegation(request.scope)

    if (!delegation) {
      const intent = this.createIntent(request, 'no-delegation')
      const denied = this.createDeniedResult(intent, 'No valid delegation for scope: ' + request.scope)
      this.logAudit(request, denied)
      this.config.onDenied?.(denied.decision, denied.intent)
      return denied
    }

    if (this.config.enforcement === 'manual') {
      const intent = this.createIntent(request, delegation.delegationId)
      return this.createPermitResult(intent, 'Manual mode — enforcement skipped')
    }

    return this.enforceAction(request, delegation)
  }

  complete(
    execution: ExecuteResult,
    outcome: { status: 'success' | 'failure' | 'partial'; summary: string }
  ): CompletedAction {
    if (!execution.permitted) {
      throw new Error('Cannot complete a denied action')
    }

    const delegation = this.state.delegations.get(execution.intent.delegationId)
    if (!delegation) {
      throw new Error('Delegation not found: ' + execution.intent.delegationId)
    }

    const receipt = createReceipt({
      agentId: this.agent.agentId,
      delegationId: delegation.delegationId,
      delegation,
      action: {
        type: execution.intent.action.type,
        target: execution.intent.action.target,
        scopeUsed: execution.intent.action.scopeRequired,
        spend: execution.intent.action.spend
      },
      result: outcome,
      delegationChain: [delegation.delegatedBy, this.agent.publicKey],
      privateKey: this.agent.keyPair.privateKey
    })

    const evaluatorKey = this.config.evaluator?.privateKey || this.agent.keyPair.privateKey
    const policyReceipt = createPolicyReceipt({
      intent: execution.intent,
      decision: execution.decision,
      receipt,
      verifierPrivateKey: evaluatorKey
    })

    this.state.receipts.push(receipt)
    this.state.policyReceipts.push(policyReceipt)

    const lastAudit = this.state.auditLog[this.state.auditLog.length - 1]
    if (lastAudit && lastAudit.intentId === execution.intent.intentId) {
      lastAudit.receiptId = receipt.receiptId
    }

    return { execution, receipt, policyReceipt }
  }

  // ── Internal: Enforcement Logic ──

  private enforceAction(request: ExecuteRequest, delegation: Delegation): ExecuteResult {
    const intent = createActionIntent({
      agentId: this.agent.agentId,
      agentPublicKey: this.agent.publicKey,
      delegationId: delegation.delegationId,
      action: {
        type: request.type,
        target: request.target,
        scopeRequired: request.scope,
        spend: request.spend
      },
      context: request.context,
      privateKey: this.agent.keyPair.privateKey
    })

    const validationContext = this.buildValidationContext(delegation)

    const evaluatorId = this.config.evaluator?.id || this.agent.agentId
    const evaluatorPub = this.config.evaluator?.publicKey || this.agent.publicKey
    const evaluatorPriv = this.config.evaluator?.privateKey || this.agent.keyPair.privateKey

    const decision = evaluateIntent({
      intent,
      validator: this.validator,
      validationContext,
      evaluatorId,
      evaluatorPublicKey: evaluatorPub,
      evaluatorPrivateKey: evaluatorPriv,
      decisionTTLMinutes: this.config.decisionTTLMinutes
    })

    this.state.decisions.push(decision)

    const result: ExecuteResult = {
      permitted: decision.verdict !== 'deny',
      verdict: decision.verdict,
      intent,
      decision,
      constraints: decision.constraints,
      auditFindings: decision.auditFindings?.length,
      warnings: decision.warnings?.length,
      reason: decision.reason
    }

    this.config.onPolicyDecision?.(decision, intent)
    if (decision.verdict === 'deny') {
      this.config.onDenied?.(decision, intent)
    }
    if (decision.auditFindings && decision.auditFindings.length > 0) {
      this.config.onAuditFinding?.(decision)
    }
    if (decision.warnings && decision.warnings.length > 0) {
      this.config.onWarning?.(decision)
    }

    this.logAudit(request, result)
    return result
  }

  private buildValidationContext(delegation: Delegation): ValidationContext {
    const attValid = this.agent.attestation
      ? verifyAttestation(this.agent.attestation).valid
      : false

    return {
      floorVersion: this.floor.version,
      floorPrinciples: this.floor.floor.map(p => ({
        id: p.id,
        name: p.name!,
        enforcement: p.enforcement,
        weight: p.weight!
      })),
      delegation: {
        scope: delegation.scope,
        spendLimit: delegation.spendLimit,
        spentAmount: delegation.spentAmount || 0,
        expiresAt: delegation.expiresAt,
        revoked: false,
        currentDepth: delegation.currentDepth,
        maxDepth: delegation.maxDepth
      },
      agentRegistered: true,
      agentAttestationValid: attValid
    }
  }

  // ── Internal: Result Builders ──

  private createIntent(request: ExecuteRequest, delegationId: string): ActionIntent {
    return createActionIntent({
      agentId: this.agent.agentId,
      agentPublicKey: this.agent.publicKey,
      delegationId,
      action: {
        type: request.type,
        target: request.target,
        scopeRequired: request.scope,
        spend: request.spend
      },
      context: request.context,
      privateKey: this.agent.keyPair.privateKey
    })
  }

  private createDeniedResult(intent: ActionIntent, reason: string): ExecuteResult {
    const evaluatorPriv = this.config.evaluator?.privateKey || this.agent.keyPair.privateKey
    const evaluatorPub = this.config.evaluator?.publicKey || this.agent.publicKey
    const evaluatorId = this.config.evaluator?.id || this.agent.agentId

    const now = new Date()
    const expires = new Date(now)
    expires.setMinutes(expires.getMinutes() + (this.config.decisionTTLMinutes || 5))

    const decision: Omit<PolicyDecision, 'signature'> = {
      decisionId: 'pdec_' + uuidv4().slice(0, 12),
      intentId: intent.intentId,
      evaluatorId,
      evaluatorPublicKey: evaluatorPub,
      verdict: 'deny',
      principlesEvaluated: [],
      reason,
      floorVersion: this.floor.version,
      evaluatedAt: now.toISOString(),
      expiresAt: expires.toISOString()
    }

    const signature = sign(canonicalize(decision), evaluatorPriv)
    const signedDecision: PolicyDecision = { ...decision, signature }

    this.state.decisions.push(signedDecision)

    return {
      permitted: false,
      verdict: 'deny',
      intent,
      decision: signedDecision,
      reason
    }
  }

  private createPermitResult(intent: ActionIntent, reason: string): ExecuteResult {
    const now = new Date()
    const manualDecision: PolicyDecision = {
      decisionId: `manual-${intent.intentId}`,
      intentId: intent.intentId,
      evaluatorId: 'manual-mode',
      evaluatorPublicKey: '',
      verdict: 'permit',
      principlesEvaluated: [],
      reason,
      floorVersion: this.floor.version,
      evaluatedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 3600_000).toISOString(),
      signature: '',
    }
    return {
      permitted: true,
      verdict: 'permit',
      intent,
      decision: manualDecision,
      reason
    }
  }

  private logAudit(request: ExecuteRequest, result: ExecuteResult): void {
    this.state.auditLog.push({
      timestamp: new Date().toISOString(),
      action: request,
      verdict: result.verdict,
      intentId: result.intent.intentId,
      decisionId: result.decision.decisionId || 'manual',
      receiptId: undefined,
      reason: result.reason,
      enforcement: {
        inlinePassed: result.verdict !== 'deny',
        auditIssueCount: result.auditFindings || 0,
        warningCount: result.warnings || 0
      }
    })
  }

  // ── Query State ──

  get enforcement(): EnforcementLevel { return this.config.enforcement }

  get allReceipts(): ActionReceipt[] { return [...this.state.receipts] }

  get allDecisions(): PolicyDecision[] { return [...this.state.decisions] }

  get auditLog(): AuditEntry[] { return [...this.state.auditLog] }

  getState(): AgentContextState { return { ...this.state } }

  get stats(): { permitted: number; denied: number; narrowed: number; total: number } {
    const log = this.state.auditLog
    return {
      permitted: log.filter(e => e.verdict === 'permit').length,
      denied: log.filter(e => e.verdict === 'deny').length,
      narrowed: log.filter(e => e.verdict === 'narrow').length,
      total: log.length
    }
  }
}

// ══════════════════════════════════════
// FACTORY FUNCTION
// ══════════════════════════════════════

export function createAgentContext(
  agent: SocialContractAgent,
  floor: ValuesFloor,
  config?: Partial<AgentContextConfig>
): AgentContext {
  if (!agent.attestation) {
    throw new Error('Agent must have a floor attestation to create a context. Did you pass a floor to joinSocialContract()?')
  }
  return new AgentContext(agent, floor, config)
}
