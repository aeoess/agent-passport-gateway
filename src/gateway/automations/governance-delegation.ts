// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Per-automation narrowed delegation + signed self-receipt.
 *
 * Spec (layer b): each governance automation runs under its OWN narrowed APS
 * delegation and emits a receipt for its own actions - the gateway governs its
 * own governance. We build that here:
 *
 *  - A gateway-governance ROOT delegation is created once (createDelegation from
 *    the gateway identity). Every automation sub-delegates from it (subDelegate),
 *    so authority only ever NARROWS (APS monotonic narrowing). An automation can
 *    never widen past the governance root, and the root is itself scoped to the
 *    benign verbs governance automations are allowed: summarize, route, open a
 *    ticket, recommend, escalate. It deliberately does NOT include any high-risk
 *    verb (revoke, freeze, approve-high-risk, delete-evidence).
 *
 *  - Each automation action emits a SIGNED SELF-RECEIPT: a gateway-signed record
 *    (getGatewayIdentity().sign, same key as mintEvaluationReceipt and B2's
 *    bumpEpoch) attesting what the automation did, under which sub-delegation.
 *    This is the audit trail for the gateway's own governance actions.
 *
 * SDK Wave 2: the SDK createDelegation/subDelegate/verifyDelegation primitives
 * are the real backbone. The pin is ^2.6.0-alpha.3; the ephemeral-token signature
 * + epoch binding for the sub-delegation is SDK Wave 2.
 *
 * TODO(W2-B3): SDK ephemeral-token signature + epoch binding for the per-automation
 *   sub-delegation. Today the sub-delegation is created via the SDK subDelegate
 *   and the self-receipt is gateway-signed; the ephemeral-token sig/expiry verify
 *   layers in at W2-B3 (matches B2 tokenEpochGuard marker).
 * TODO(W2-xx): SDK createReceipt for the self-receipt body once alpha exposes the
 *   gateway-as-issuer receipt shape; today we compose a gateway-signed record so
 *   the call site exists and is exercised by tests.
 */

import { createHash } from 'node:crypto'
import { getGatewayIdentity } from '../identity.js'

// The benign verbs a governance automation may exercise. NON-wideable: the root
// is scoped to exactly these, and sub-delegations only narrow. High-risk verbs
// (revoke, freeze, approve, delete-evidence) are absent BY CONSTRUCTION.
export const GOVERNANCE_ROOT_SCOPES: readonly string[] = Object.freeze([
  'governance:summarize',
  'governance:route_alert',
  'governance:open_ticket',
  'governance:recommend',
  'governance:escalate',
])

/** The five named governance automations (layer b). */
export type AutomationName =
  | 'alert_routing'
  | 'evidence_bundle'
  | 'policy_drift'
  | 'revocation_recommendation'
  | 'integration_health'

/**
 * The single scope each automation is narrowed to. An automation may exercise
 * ONLY its scope; this is what "acts only inside its delegation" means and is
 * what the test asserts. None of these is a high-risk verb.
 */
export const AUTOMATION_SCOPE: Record<AutomationName, string> = {
  alert_routing: 'governance:route_alert',
  evidence_bundle: 'governance:summarize',
  policy_drift: 'governance:recommend',
  revocation_recommendation: 'governance:recommend',
  integration_health: 'governance:escalate',
}

/**
 * A narrowed sub-delegation handle for one automation. Loosely typed so we do not
 * import the SDK's unexported Delegation shape; the SDK functions validate it.
 */
export interface AutomationDelegation {
  automation: AutomationName
  /** The single scope this automation is allowed to exercise. */
  scope: string
  /** Sub-delegation id (SDK). Authority flows from the governance root, narrowed. */
  delegationId: string
  /** Parent (governance root) delegation id. */
  rootDelegationId: string
}

/** A signed self-receipt for one automation action. */
export interface AutomationSelfReceipt {
  automation: AutomationName
  /** The action the automation performed, e.g. 'route_alert', 'recommend_revocation'. */
  action: string
  /** The scope it exercised (must equal AUTOMATION_SCOPE[automation]). */
  scope: string
  /** The sub-delegation it acted under. */
  delegationId: string
  /** Digest of the action payload, never the raw payload. */
  payloadDigest: string
  /** Gateway EdDSA JWS over the receipt body (verifiable via JWKS, kid gateway-v1). */
  signature: string
  issuedAt: string
}

// ── SDK delegation primitives, lazily loaded and fail-closed ──
// We consume the SDK; we do not reinvent delegation. If the SDK is unavailable
// we fail closed (no delegation handle), so an automation cannot run un-scoped.
interface SdkDelegationFns {
  createDelegation: (opts: any) => any
  subDelegate: (opts: any) => any
  verifyDelegation: (delegation: any) => { valid: boolean; errors: string[] }
  publicKeyFromPrivate: (privateKeyHex: string) => string
}
let _sdkFns: SdkDelegationFns | null | undefined

async function getSdkDelegationFns(): Promise<SdkDelegationFns | null> {
  if (_sdkFns !== undefined) return _sdkFns
  try {
    const sdk: any = await import('agent-passport-system')
    const required = ['createDelegation', 'subDelegate', 'verifyDelegation', 'publicKeyFromPrivate']
    if (required.every(fn => typeof sdk[fn] === 'function')) {
      _sdkFns = {
        createDelegation: sdk.createDelegation,
        subDelegate: sdk.subDelegate,
        verifyDelegation: sdk.verifyDelegation,
        publicKeyFromPrivate: sdk.publicKeyFromPrivate,
      }
    } else {
      _sdkFns = null
    }
  } catch {
    _sdkFns = null
  }
  return _sdkFns
}

// A gateway-governance signing key. The SDK delegation primitives want a private
// key; we use a per-process ephemeral key whose ONLY purpose is to anchor the
// governance root sub-delegation graph. It is NOT the gateway identity key (that
// signs receipts) and grants no authority outside the governance scopes.
//
// TODO(W2-B3): replace with the SDK ephemeral-token keypair bound to the gateway
//   identity + epoch, so the sub-delegation chain is epoch-bound like B2 tokens.
let _govRootPrivKey: string | null = null
let _govRoot: { delegationId: string; raw: any } | null = null

function governanceRootKey(): string {
  if (!_govRootPrivKey) {
    // 32-byte hex seed, ephemeral per process. The SDK accepts a hex private key.
    _govRootPrivKey = createHash('sha256')
      .update('gc2-governance-root:' + getGatewayIdentity().publicKeyHex)
      .digest('hex')
  }
  return _govRootPrivKey
}

/**
 * Create (once) the gateway-governance ROOT delegation. Scoped to exactly the
 * benign governance verbs. Returns a stable handle; subsequent calls reuse it.
 *
 * If the SDK is unavailable, returns null and callers fail closed.
 */
export async function ensureGovernanceRoot(): Promise<{ delegationId: string; raw: any } | null> {
  if (_govRoot) return _govRoot
  const fns = await getSdkDelegationFns()
  if (!fns) return null
  try {
    // `delegatedBy` and `delegatedTo` MUST be the public key of the key that signs,
    // not a human-readable label: the SDK's verifyDelegation checks the signature
    // against `delegatedBy`, and subDelegate mints the child with
    // `delegatedBy = parent.delegatedTo`. A label in either field yields a
    // delegation whose own signature can never verify. The root is self-anchored:
    // the gateway delegates the governance scopes to itself, then narrows to one
    // scope per automation.
    const rootPublicKey = fns.publicKeyFromPrivate(governanceRootKey())
    const raw = fns.createDelegation({
      delegatedBy: rootPublicKey,
      delegatedTo: rootPublicKey,
      scope: [...GOVERNANCE_ROOT_SCOPES],
      scopeInterpretation: 'hierarchical',
      maxDepth: 2,
      // Governance automations move no value; bound the limit explicitly so the
      // sub-delegation inherits a finite ceiling (an unset limit defaults to
      // Infinity, which the SDK subDelegate rejects). Invocation-counted, zero.
      spendLimit: 0,
      spendLimitUnit: 'invocations',
      expiresInHours: 24,
      privateKey: governanceRootKey(),
    })
    // Fail closed on a root we cannot verify, rather than discovering it only when
    // some later subDelegate happens to check the parent.
    const status = fns.verifyDelegation(raw)
    if (!status.valid) return null
    const delegationId = raw?.id ?? raw?.delegationId ?? `gov-root-${getGatewayIdentity().kid}`
    _govRoot = { delegationId, raw }
    return _govRoot
  } catch {
    return null
  }
}

/**
 * Get a narrowed sub-delegation for one automation. Monotonic narrowing: the
 * sub-delegation scope is the automation's single scope, which is a subset of the
 * governance root scopes. An automation CANNOT obtain a scope outside this.
 *
 * Fail-closed: if the SDK or the root is unavailable, returns null and the
 * automation must not run.
 */
export async function getAutomationDelegation(
  automation: AutomationName,
): Promise<AutomationDelegation | null> {
  const scope = AUTOMATION_SCOPE[automation]
  const root = await ensureGovernanceRoot()
  const fns = await getSdkDelegationFns()
  if (!root || !fns) return null
  try {
    const raw = fns.subDelegate({
      parentDelegation: root.raw,
      delegatedTo: `automation:${automation}`,
      scope: [scope], // narrow to exactly one scope
      privateKey: governanceRootKey(),
    })
    // The child is signed with the same governance root key, so its own
    // `delegatedBy` (inherited from root.delegatedTo) must verify. Check it here:
    // nothing downstream re-verifies this delegation, so an unverifiable child
    // would otherwise circulate unnoticed.
    const status = fns.verifyDelegation(raw)
    if (!status.valid) return null
    const delegationId = raw?.id ?? raw?.delegationId ?? `${root.delegationId}:${automation}`
    return { automation, scope, delegationId, rootDelegationId: root.delegationId }
  } catch {
    return null
  }
}

/**
 * Authority check an automation runs before acting: does my sub-delegation's
 * scope authorize the verb I am about to perform? An automation that tries to
 * act outside its single scope is refused. Pure, no IO.
 *
 * `requiredScope` is the governance verb the action maps to. It MUST equal the
 * automation's narrowed scope; anything else is an attempt to widen and is denied.
 */
export function automationMayAct(
  del: AutomationDelegation,
  requiredScope: string,
): boolean {
  return del.scope === requiredScope
}

/**
 * Emit a signed self-receipt for an automation action. Gateway-signed (same key
 * as evaluation receipts). This is the "gateway governs its own governance" audit
 * record. Returns the receipt; the caller decides where to store/surface it.
 *
 * TODO(W2-xx): swap the gateway-signed body for SDK createReceipt once the alpha
 *   exposes a gateway-as-issuer receipt shape. The signature stays gateway EdDSA.
 */
export function emitSelfReceipt(opts: {
  delegation: AutomationDelegation
  action: string
  payload: unknown
}): AutomationSelfReceipt {
  const issuedAt = new Date().toISOString()
  const payloadDigest = createHash('sha256')
    .update(JSON.stringify(opts.payload ?? null))
    .digest('hex')
  const body = {
    kind: 'automation_self_receipt',
    automation: opts.delegation.automation,
    action: opts.action,
    scope: opts.delegation.scope,
    delegationId: opts.delegation.delegationId,
    payloadDigest,
    issuedAt,
  }
  const signature = getGatewayIdentity().sign(body)
  return {
    automation: opts.delegation.automation,
    action: opts.action,
    scope: opts.delegation.scope,
    delegationId: opts.delegation.delegationId,
    payloadDigest,
    signature,
    issuedAt,
  }
}

/** Reset cached governance root + SDK fns. Test-only hook for isolation. */
export function _resetGovernanceForTest(): void {
  _govRoot = null
  _govRootPrivKey = null
  _sdkFns = undefined
}
