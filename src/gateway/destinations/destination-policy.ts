// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Destination registry types + before-the-fact destination-control check
// ══════════════════════════════════════════════════════════════════
// A destination is a sink an agent may send classified data to. The
// registry records the destination's POLICY (internal/external, allowed
// data classes, allowed agent roles, storage policy, training policy,
// sink-confirmation SUPPORT, risk tier). The gateway records this state
// and checks-before; it does NOT perform the sink confirmation and is
// never the trusted central brain. The actual confirmation happens at
// the sink. sink_confirmation_support is recorded as a capability, not a
// guarantee.
//
// The destination-control check is a thin verdict, copied from the
// type-interceptor.ts shape: it owns no state, never logs, never
// mutates, never fans out. It composes alongside the existing
// DataEnforcementGate.checkTermsCompliance pre-check (it is an
// ADDITIONAL pre-check, not a replacement). Distinct symbol names so it
// never clashes with DataEnforcementGate / DataAccessDecision.
//
// Storage and training policy reuse SDK vocabulary: DataPurpose 'train'
// and 'redistribute', retentionLimit, DerivativePolicy, AuditVisibility.
// We do not redeclare those enums; we import them.
//
// TODO(W2-destinations): SDK destination / sink-confirmation primitive
//   (sink-confirmation support + risk-tier attestation) will replace the
//   gateway-local DestinationPolicy state. Until then the registry is
//   gateway-local state signed with getGatewayIdentity().
// ══════════════════════════════════════════════════════════════════

import type { DataPurpose, DerivativePolicy, AuditVisibility } from 'agent-passport-system'
import { sensitivityRank } from '../data-classification/data-class.js'

/** Whether the destination is inside or outside the customer trust
 *  boundary. Drives risk posture and, optionally, class matching. */
export type DestinationPlacement = 'internal' | 'external'

/** Risk tier of the destination. Verifier/operator-assigned; informs the
 *  check but is not itself the enforcement boundary. */
export type DestinationRiskTier = 'low' | 'medium' | 'high' | 'unknown'

/** Whether the sink can confirm receipt/handling back to the gateway.
 *  'attested' means the sink has provided a confirmation attestation;
 *  the gateway records the SUPPORT, it does not produce the confirmation. */
export type SinkConfirmationSupport = 'none' | 'supported' | 'attested'

/** Storage policy for data landing at the destination. retentionLimit
 *  reuses the SDK DataTerms.retentionLimit string vocabulary (e.g. an ISO
 *  duration or 'none'). */
export interface DestinationStoragePolicy {
  /** Whether the destination persists data at rest at all. */
  persists: boolean
  /** ISO-8601 duration or 'none'. Aligns with SDK DataTerms.retentionLimit. */
  retentionLimit?: string
  /** Whether data at rest is encrypted. */
  encryptedAtRest?: boolean
  /** SDK audit-visibility level for stored data. */
  auditVisibility?: AuditVisibility
}

/** Training policy for data landing at the destination. Maps onto SDK
 *  DataPurpose 'train' / 'redistribute' + DerivativePolicy. */
export interface DestinationTrainingPolicy {
  /** Whether the destination may use data for model training. */
  allowsTraining: boolean
  /** Whether the destination may redistribute data. */
  allowsRedistribution?: boolean
  /** SDK derivative policy governing derived artifacts. */
  derivativePolicy?: DerivativePolicy
}

/** A registered destination policy. Gateway-local until W2-destinations. */
export interface DestinationPolicy {
  destinationId: string
  destinationName: string
  placement: DestinationPlacement
  /** Class strings this destination accepts. Empty = accepts none. */
  allowedDataClasses: string[]
  /** Agent roles permitted to send to this destination. Empty = any role. */
  allowedAgentRoles: string[]
  /** SDK DataPurpose values permitted at this destination. Empty = any. */
  allowedPurposes: DataPurpose[]
  storagePolicy: DestinationStoragePolicy
  trainingPolicy: DestinationTrainingPolicy
  sinkConfirmationSupport: SinkConfirmationSupport
  riskTier: DestinationRiskTier
}

/** A request to send a classified source to a destination. */
export interface DestinationCheckRequest {
  /** The class of the source being sent. Verbatim source class string. */
  sourceClass: string
  /** The role of the sending agent, if known. */
  agentRole?: string
  /** The declared purpose of the send, if known. */
  purpose?: DataPurpose
  /** Whether this send trains a model at the destination. */
  forTraining?: boolean
}

export type DestinationDenyReason =
  | 'destination_revoked'
  | 'class_not_allowed'
  | 'role_not_allowed'
  | 'purpose_not_allowed'
  | 'training_not_allowed'

/** Thin verdict. Mirrors GatewayInterceptResult: permit | deny + reason.
 *  Carries the sink-confirmation support and risk tier so the caller can
 *  route the decision to the sink, which performs the actual confirmation. */
export interface DestinationCheckResult {
  decision: 'permit' | 'deny'
  reason: DestinationDenyReason | 'destination_permits'
  /** Recorded, not enforced by the gateway: the sink confirms. */
  sinkConfirmationSupport: SinkConfirmationSupport
  riskTier: DestinationRiskTier
}

/**
 * Before-the-fact destination-control check. Pure, deterministic, thin.
 *
 * Deny on the first failing check. The gateway coordinates and checks
 * before; the sink enforces. This function does not call the sink, does
 * not mutate the registry, and does not emit. The caller emits and (for
 * a 'supported'/'attested' sink) routes the permit to the sink for the
 * actual confirmation.
 *
 * @param req       The send request (class, role, purpose, training).
 * @param policy    The registered destination policy.
 * @param isActive  Whether the destination is active (not revoked).
 */
export function checkDestination(
  req: DestinationCheckRequest,
  policy: DestinationPolicy,
  isActive: boolean,
): DestinationCheckResult {
  const base = {
    sinkConfirmationSupport: policy.sinkConfirmationSupport,
    riskTier: policy.riskTier,
  }

  if (!isActive) {
    return { decision: 'deny', reason: 'destination_revoked', ...base }
  }

  // Class match. A destination accepts a class if the class string is
  // listed, OR the destination lists a more sensitive class than the one
  // being sent AND placement is internal (an internal sink cleared for
  // 'secret' implicitly clears 'public'). External destinations require
  // an exact class listing - no implicit widening across the boundary.
  if (!classAllowed(req.sourceClass, policy)) {
    return { decision: 'deny', reason: 'class_not_allowed', ...base }
  }

  // Role match. Empty allowedAgentRoles means any role.
  if (
    policy.allowedAgentRoles.length > 0 &&
    (req.agentRole === undefined || !policy.allowedAgentRoles.includes(req.agentRole))
  ) {
    return { decision: 'deny', reason: 'role_not_allowed', ...base }
  }

  // Purpose match. Empty allowedPurposes means any purpose.
  if (
    req.purpose !== undefined &&
    policy.allowedPurposes.length > 0 &&
    !policy.allowedPurposes.includes(req.purpose)
  ) {
    return { decision: 'deny', reason: 'purpose_not_allowed', ...base }
  }

  // Training gate.
  if (req.forTraining === true && !policy.trainingPolicy.allowsTraining) {
    return { decision: 'deny', reason: 'training_not_allowed', ...base }
  }

  return { decision: 'permit', reason: 'destination_permits', ...base }
}

function classAllowed(sourceClass: string, policy: DestinationPolicy): boolean {
  if (policy.allowedDataClasses.includes(sourceClass)) return true
  if (policy.placement !== 'internal') return false
  // Internal destination: cleared for any class at least as sensitive.
  const reqRank = sensitivityRank(sourceClass)
  return policy.allowedDataClasses.some((c) => sensitivityRank(c) >= reqRank)
}
