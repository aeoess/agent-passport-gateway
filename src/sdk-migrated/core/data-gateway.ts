// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Data Gateway — Composable Gateway + Data Enforcement
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). Product intelligence —
// wraps ProxyGateway + DataEnforcementGate into a single call. One
// gateway call: identity → delegation → policy → data terms → execute.
// Also adds real-time compensation enforcement via terms acceptance.
// ══════════════════════════════════════════════════════════════════════

import {
  DataEnforcementGate, DataAccessRequest, DataAccessDecision,
} from './data-enforcement.js'
import { ContributionLedger, createContributionLedger } from './data-contribution.js'
import type { SourceReceipt } from 'agent-passport-system'

// ── Terms Acceptance Registry ──

export interface TermsAcceptance {
  agentId: string
  agentPublicKey: string
  sourceReceiptId: string
  acceptedAt: string
  compensationAcknowledged: boolean
  signature?: string
}

export interface DataGatewayConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  enforcementMode: 'enforce' | 'audit' | 'off'
  requireTermsAcceptance: boolean
  onAccessBlocked?: (agentId: string, source: string, reason: string) => void
  onAccessGranted?: (agentId: string, source: string, receiptId: string) => void
  onTermsAccepted?: (acceptance: TermsAcceptance) => void
}

// ── Data Gateway ──

export class DataGateway {
  private config: DataGatewayConfig
  private enforcementGate: DataEnforcementGate
  private acceptances: Map<string, TermsAcceptance> = new Map()

  constructor(config: DataGatewayConfig, ledger?: ContributionLedger) {
    this.config = config
    this.enforcementGate = new DataEnforcementGate({
      gatewayId: config.gatewayId,
      gatewayPublicKey: config.gatewayPublicKey,
      gatewayPrivateKey: config.gatewayPrivateKey,
      mode: config.enforcementMode,
      onAccessBlocked: (agentId, src, violations) => {
        config.onAccessBlocked?.(agentId, src, violations.join('; '))
      },
      onAccessRecorded: (receipt) => {
        config.onAccessGranted?.(receipt.agentId, receipt.sourceReceiptId, receipt.accessReceiptId)
      },
    }, ledger || createContributionLedger())
  }

  registerSource(receipt: SourceReceipt, descriptor: string): void {
    this.enforcementGate.registerSource(receipt, descriptor)
  }

  acceptTerms(opts: {
    agentId: string
    agentPublicKey: string
    sourceReceiptId: string
    signature?: string
  }): TermsAcceptance {
    const acceptance: TermsAcceptance = {
      agentId: opts.agentId,
      agentPublicKey: opts.agentPublicKey,
      sourceReceiptId: opts.sourceReceiptId,
      acceptedAt: new Date().toISOString(),
      compensationAcknowledged: true,
      signature: opts.signature,
    }
    const key = `${opts.agentId}:${opts.sourceReceiptId}`
    this.acceptances.set(key, acceptance)
    this.config.onTermsAccepted?.(acceptance)
    return acceptance
  }

  hasAcceptedTerms(agentId: string, sourceReceiptId: string): boolean {
    return this.acceptances.has(`${agentId}:${sourceReceiptId}`)
  }

  requestAccess(request: DataAccessRequest): DataAccessDecision {
    if (this.config.requireTermsAcceptance) {
      if (!this.hasAcceptedTerms(request.agentId, request.sourceReceiptId)) {
        this.config.onAccessBlocked?.(request.agentId, request.sourceReceiptId, 'Terms not accepted')
        return {
          allowed: false,
          sourceReceiptId: request.sourceReceiptId,
          hardViolations: ['Agent has not accepted DataTerms for this source. Call acceptTerms() first.'],
          advisoryWarnings: [],
        }
      }
    }

    return this.enforcementGate.checkAccess(request)
  }

  preflightAccess(requests: DataAccessRequest[]): { allAllowed: boolean; decisions: DataAccessDecision[] } {
    if (this.config.requireTermsAcceptance) {
      const decisions: DataAccessDecision[] = requests.map(r => {
        if (!this.hasAcceptedTerms(r.agentId, r.sourceReceiptId)) {
          return {
            allowed: false,
            sourceReceiptId: r.sourceReceiptId,
            hardViolations: ['Terms not accepted'],
            advisoryWarnings: [],
          }
        }
        return this.enforcementGate.checkAccess(r)
      })
      return { allAllowed: decisions.every(d => d.allowed), decisions }
    }
    return this.enforcementGate.preflightCheck(requests)
  }

  getEnforcementGate(): DataEnforcementGate { return this.enforcementGate }

  getLedger(): ContributionLedger { return this.enforcementGate.getLedger() }

  getAcceptances(): TermsAcceptance[] { return Array.from(this.acceptances.values()) }

  revokeAcceptance(agentId: string, sourceReceiptId: string): boolean {
    return this.acceptances.delete(`${agentId}:${sourceReceiptId}`)
  }

  revokeAllAcceptancesForSource(sourceReceiptId: string): number {
    let count = 0
    for (const [key] of this.acceptances) {
      if (key.endsWith(`:${sourceReceiptId}`)) {
        this.acceptances.delete(key)
        count++
      }
    }
    return count
  }
}
