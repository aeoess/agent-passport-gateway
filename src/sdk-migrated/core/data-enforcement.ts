// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Data Enforcement Gate
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). Product intelligence —
// sits alongside the ProxyGateway. Before an agent accesses data, the
// enforcement gate checks DataTerms, blocks if non-compliant, and
// automatically generates access receipts + contribution records.
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'
import type {
  DataAccessReceipt, SourceReceipt, DataPurpose, AccessMethod,
} from 'agent-passport-system'
import {
  checkTermsCompliance, recordDataAccess, buildDataAccessMerkleRoot,
} from 'agent-passport-system'
import {
  ContributionLedger, createContributionLedger, recordContribution,
} from './data-contribution.js'

// ── Data Enforcement Config ──

export interface DataEnforcementConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  mode: 'enforce' | 'audit' | 'off'
  onAccessBlocked?: (agentId: string, sourceId: string, violations: string[]) => void
  onAccessRecorded?: (receipt: DataAccessReceipt) => void
  onTermsWarning?: (agentId: string, sourceId: string, warnings: string[]) => void
}

// ── Registered Data Source ──

interface RegisteredSource {
  receipt: SourceReceipt
  descriptor: string
  accessCount: number
}

// ── Access Request ──

export interface DataAccessRequest {
  agentId: string
  agentPublicKey: string
  principalId: string
  delegationId?: string
  sourceReceiptId: string
  declaredPurpose: DataPurpose
  accessMethod: AccessMethod
  accessScope: string
  executionFrameId: string
  dataHash?: string
}

// ── Access Decision ──

export interface DataAccessDecision {
  allowed: boolean
  sourceReceiptId: string
  hardViolations: string[]
  advisoryWarnings: string[]
  receipt?: DataAccessReceipt
  accessesRemaining?: number
}

// ── Data Enforcement Gate ──

export class DataEnforcementGate {
  private config: DataEnforcementConfig
  private sources: Map<string, RegisteredSource> = new Map()
  private ledger: ContributionLedger
  private receipts: DataAccessReceipt[] = []

  constructor(config: DataEnforcementConfig, ledger?: ContributionLedger) {
    this.config = config
    this.ledger = ledger || createContributionLedger()
  }

  registerSource(receipt: SourceReceipt, descriptor: string): void {
    this.sources.set(receipt.sourceReceiptId, { receipt, descriptor, accessCount: 0 })
  }

  getLedger(): ContributionLedger { return this.ledger }

  getReceipts(): DataAccessReceipt[] { return [...this.receipts] }

  getMerkleRoot(): string { return buildDataAccessMerkleRoot(this.receipts) }

  checkAccess(request: DataAccessRequest): DataAccessDecision {
    if (this.config.mode === 'off') {
      return { allowed: true, sourceReceiptId: request.sourceReceiptId, hardViolations: [], advisoryWarnings: [] }
    }

    const source = this.sources.get(request.sourceReceiptId)
    if (!source) {
      return {
        allowed: false,
        sourceReceiptId: request.sourceReceiptId,
        hardViolations: ['Source not registered with enforcement gate'],
        advisoryWarnings: [],
      }
    }

    const compliance = checkTermsCompliance({
      sourceReceipt: source.receipt,
      agentId: request.agentId,
      principalId: request.principalId,
      declaredPurpose: request.declaredPurpose,
      currentAccessCount: source.accessCount,
    })

    if (this.config.mode === 'enforce' && !compliance.compliant) {
      this.config.onAccessBlocked?.(request.agentId, request.sourceReceiptId, compliance.hardViolations)
      return {
        allowed: false,
        sourceReceiptId: request.sourceReceiptId,
        hardViolations: compliance.hardViolations,
        advisoryWarnings: compliance.advisoryWarnings,
        accessesRemaining: compliance.accessesRemaining,
      }
    }

    if (compliance.advisoryWarnings.length > 0) {
      this.config.onTermsWarning?.(request.agentId, request.sourceReceiptId, compliance.advisoryWarnings)
    }

    const receipt = recordDataAccess({
      sourceReceipt: source.receipt,
      dataHash: request.dataHash || crypto.createHash('sha256').update(request.executionFrameId + request.sourceReceiptId).digest('hex'),
      agentId: request.agentId,
      agentPublicKey: request.agentPublicKey,
      delegationId: request.delegationId,
      principalId: request.principalId,
      executionFrameId: request.executionFrameId,
      accessScope: request.accessScope,
      accessMethod: request.accessMethod,
      declaredPurpose: request.declaredPurpose,
      gatewayId: this.config.gatewayId,
      gatewayPublicKey: this.config.gatewayPublicKey,
      gatewayPrivateKey: this.config.gatewayPrivateKey,
    })

    source.accessCount++
    this.receipts.push(receipt)
    this.config.onAccessRecorded?.(receipt)

    recordContribution(this.ledger, receipt, source.descriptor)

    return {
      allowed: true,
      sourceReceiptId: request.sourceReceiptId,
      hardViolations: compliance.hardViolations,
      advisoryWarnings: compliance.advisoryWarnings,
      receipt,
      accessesRemaining: compliance.accessesRemaining,
    }
  }

  preflightCheck(requests: DataAccessRequest[]): { allAllowed: boolean; decisions: DataAccessDecision[] } {
    const decisions = requests.map(r => {
      const source = this.sources.get(r.sourceReceiptId)
      if (!source) return { allowed: false, sourceReceiptId: r.sourceReceiptId, hardViolations: ['Source not registered'], advisoryWarnings: [] }
      const compliance = checkTermsCompliance({
        sourceReceipt: source.receipt,
        agentId: r.agentId,
        principalId: r.principalId,
        declaredPurpose: r.declaredPurpose,
        currentAccessCount: source.accessCount,
      })
      return {
        allowed: this.config.mode === 'enforce' ? compliance.compliant : true,
        sourceReceiptId: r.sourceReceiptId,
        hardViolations: compliance.hardViolations,
        advisoryWarnings: compliance.advisoryWarnings,
        accessesRemaining: compliance.accessesRemaining,
      }
    })
    return { allAllowed: decisions.every(d => d.allowed), decisions }
  }
}
