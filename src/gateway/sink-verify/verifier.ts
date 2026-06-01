// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Sink-side APS receipt verifier (drop-in for the receiving API)
// ══════════════════════════════════════════════════════════════════
// A gateway pre-check is theater if the agent can call the tool
// directly. The SINK (the receiving API) must independently verify the
// APS receipt before it accepts the action, so the pre-check is not the
// only gate. This module is the first-class drop-in the receiving API
// runs at consumption time.
//
// Design posture (thin gateway): trust is pushed to the EDGE. The sink
// verifies the receipt itself against keys it already holds. It does NOT
// call back to the gateway to ask "is this allowed". The full path runs
// OFFLINE - every primitive used here is a pure function over the
// receipt plus a caller-supplied trust set.
//
// What it composes (consumed from the SDK, never reimplemented):
//   - verifyReceipt(receipt, agentPublicKey)  - Ed25519 signature check
//     against the EXECUTING agent's key. This is the spine.
//   - scopeAuthorizes / scopeMatchesWithArguments - the SAME SDK-backed
//     scope matcher the source-side pre-check uses (imported from
//     enforce.ts so source and sink agree on the matching rule).
//
// What it re-checks at consumption time (two-sided enforcement):
//   - signature validity (agent key)
//   - the scope the receipt claims (scopeUsed) is the scope the sink is
//     being asked to act on, and is covered by the granted delegation
//   - spend bound, when the trust set declares one
//   - delegation binding (the receipt names the delegation the sink
//     trusts)
//
// The verdict shape mirrors the source-side pre-check at
// POST /api/v1/evaluate: { verdict, reason, violations }.
// ══════════════════════════════════════════════════════════════════

import { verifyReceipt } from 'agent-passport-system'
import type { ActionReceipt } from 'agent-passport-system'
import {
  getScopeAuthorizes,
  scopeMatchesWithArguments,
} from '../enforce.js'

/** What the receiving API independently knows and trusts at consumption
 *  time. None of these fields require a network call to populate: they
 *  are the keys and bounds the sink was provisioned with (out-of-band,
 *  from a signed delegation contract, or cached from the gateway). The
 *  verifier never reaches out to fill them in. */
export interface SinkTrustSet {
  /** Ed25519 public key (hex) of the agent that signed the receipt.
   *  Resolved by the sink from its own trust store, keyed by agentId. */
  agentPublicKey: string
  /** Scopes the sink will honor for this agent, e.g. the granted
   *  delegation scope. The receipt's scopeUsed must be authorized by
   *  this set. Omit to skip the scope re-check (signature-only mode). */
  grantedScopes?: string[]
  /** Delegation id the sink expects this receipt to be bound to. When
   *  set, a receipt naming a different delegation is rejected. */
  expectedDelegationId?: string
  /** Remaining spend the sink will honor (same unit as the receipt's
   *  action.spend.amount). When set and the receipt declares a spend,
   *  a spend above this bound is rejected. */
  remainingSpend?: number
}

/** The action the sink is actually about to perform. The verifier
 *  confirms the receipt authorizes THIS action, not merely that the
 *  receipt is internally well-formed. Defaults are read from the
 *  receipt when the caller does not pin them. */
export interface SinkAction {
  /** The scope the sink requires to perform the action. Defaults to the
   *  receipt's action.scopeUsed when omitted. Pinning it lets the sink
   *  assert "I am about to do X" independently of what the receipt says. */
  scopeRequired?: string
  /** action_type for hierarchical/arg-pattern scope matching. Defaults
   *  to the receipt's action.type. */
  actionType?: string
  /** Arguments for arg-pattern scope matching (path/target/resource). */
  actionArgs?: Record<string, unknown>
}

export interface SinkVerdict {
  /** 'accept' when the sink may proceed, 'reject' otherwise. Mirrors the
   *  source-side permit/deny but named for the consumption boundary. */
  verdict: 'accept' | 'reject'
  reason: string
  violations: string[]
  /** Echoed for the sink's own audit log. */
  agent_id: string
  receipt_id: string
  /** True only when the Ed25519 signature verified against the agent
   *  key. Surfaced separately so a sink can tell "forged" from
   *  "authentic but out of scope". */
  signature_valid: boolean
  /** Wall-clock cost of the check, for the sink's telemetry. */
  duration_ms: number
}

const EMPTY_ARGS: Record<string, unknown> = {}

/**
 * Verify an APS receipt at the sink, fully offline.
 *
 * Composes the installed SDK verifiers (alpha.3). When the SDK ships its
 * Wave 2 relying-party verifier, the body of this function is the single
 * call site to swap.
 *
 * // TODO(W2-C2): replace this composed verifier (verifyReceipt + SDK
 * //   scope matcher) with the SDK relyingPartyVerify / relying-party
 * //   middleware entry point when Wave 2 lands. The seam is this one
 * //   function; callers and middleware do not change.
 */
export async function verifySinkOffline(
  receipt: ActionReceipt,
  trust: SinkTrustSet,
  action: SinkAction = {},
): Promise<SinkVerdict> {
  const start = Date.now()
  const violations: string[] = []

  const agent_id = receipt?.agentId ?? ''
  const receipt_id = receipt?.receiptId ?? ''

  // ── Structural guard. A malformed receipt is a reject, never a throw,
  // so a hostile payload cannot crash the sink. ──
  if (!receipt || typeof receipt !== 'object' || !receipt.action) {
    return {
      verdict: 'reject',
      reason: 'Malformed receipt',
      violations: ['malformed_receipt'],
      agent_id,
      receipt_id,
      signature_valid: false,
      duration_ms: Date.now() - start,
    }
  }

  // ── 1. Signature. SDK verifyReceipt checks the Ed25519 signature of
  // the receipt against the executing agent's public key. This is the
  // spine: it is what makes a gateway pre-check NOT the only gate. ──
  let signatureValid = false
  try {
    const sig = verifyReceipt(receipt, trust.agentPublicKey)
    signatureValid = sig.valid === true
    if (!signatureValid) {
      for (const e of sig.errors || []) violations.push(`signature: ${e}`)
      if ((sig.errors || []).length === 0) violations.push('signature_invalid')
    }
  } catch (e) {
    // FAIL CLOSED: any verifier error is a rejection, not an accept.
    violations.push(`signature_error: ${(e as Error).message}`)
    signatureValid = false
  }

  // ── 2. Delegation binding. If the sink expects a specific delegation,
  // a receipt bound to another delegation is rejected even if signed. ──
  if (trust.expectedDelegationId &&
      receipt.delegationId !== trust.expectedDelegationId) {
    violations.push(
      `delegation_mismatch: receipt is bound to "${receipt.delegationId}", sink expects "${trust.expectedDelegationId}"`,
    )
  }

  // ── 3. Scope. The scope the sink is about to act on must (a) match
  // what the receipt claims it used, and (b) be authorized by the
  // scopes the sink grants this agent. Uses the SAME SDK-backed matcher
  // as the source-side pre-check. ──
  const scopeUsed = receipt.action.scopeUsed || ''
  const scopeRequired = action.scopeRequired ?? scopeUsed
  const actionType = action.actionType ?? receipt.action.type ?? ''
  const actionArgs = action.actionArgs ?? EMPTY_ARGS

  // (a) the sink's required scope must be the scope the receipt used.
  if (scopeRequired && scopeUsed && scopeRequired !== scopeUsed) {
    violations.push(
      `scope_mismatch: sink requires "${scopeRequired}" but receipt used "${scopeUsed}"`,
    )
  }

  // (b) the receipt's scope must be authorized by the granted set.
  if (trust.grantedScopes && trust.grantedScopes.length > 0) {
    const scopeAuth = await getScopeAuthorizes()
    const authorized = scopeMatchesWithArguments(
      trust.grantedScopes,
      scopeRequired || scopeUsed,
      actionArgs,
      scopeAuth,
    )
    if (!authorized) {
      violations.push(
        `scope_denied: "${scopeRequired || scopeUsed}" not authorized by granted scopes [${trust.grantedScopes.join(', ')}]`,
      )
    }
  }

  // ── 4. Spend. When the sink declares a remaining budget and the
  // receipt carries a spend, a spend above the bound is rejected. ──
  if (typeof trust.remainingSpend === 'number' && receipt.action.spend) {
    const amount = receipt.action.spend.amount
    if (typeof amount === 'number' && amount > trust.remainingSpend) {
      violations.push(
        `spend_exceeded: receipt spend ${amount} exceeds remaining ${trust.remainingSpend}`,
      )
    }
  }

  const ok = signatureValid && violations.length === 0
  return {
    verdict: ok ? 'accept' : 'reject',
    reason: ok
      ? `Accepted: receipt for "${scopeRequired || scopeUsed}" verified at sink`
      : `Rejected: ${violations.join('; ')}`,
    violations,
    agent_id,
    receipt_id,
    signature_valid: signatureValid,
    duration_ms: Date.now() - start,
  }
}
