// APS Regulated Action Profile v0: gateway reconciliation matcher (private).
//
// This is the deterministic disposition function from RAPV0-FROZEN-CONTRACT.md section B
// (amended guard order). It is the SAME truth-table as the public SDK verifier
// (agent-passport-system src/v2/regulated-action/verify.ts). It is VENDORED here because the
// installed SDK version predates the published RegulatedActionV0 module; once the SDK version
// bumps, this should import RegulatedActionV0.verifyRegulatedAction instead. It reuses the SDK
// canonicalizeJCS and Ed25519 verify so the canonical bytes are identical across the boundary.
//
// Pure, stateless, total, most-dangerous-first, first match wins. judgment_correctness is
// always not_claimed. Replay (jti/nonce uniqueness) is layered ON TOP by the gateway in
// reconcile.ts; this function reports authority_replay: not_evaluated like the public verifier.

import { createHash } from 'node:crypto'
import { canonicalizeJCS, verify as edVerify } from 'agent-passport-system'

export const RAPV0_TAG = {
  actor: 'APS-RAPV0-ACTOR',
  intent: 'APS-RAPV0-INTENT',
  policy: 'APS-RAPV0-POLICY',
  resource: 'APS-RAPV0-RESOURCE-CONFIRMATION',
  authority: 'APS-RAPV0-AUTHORITY',
} as const

export const ACTION_CLASS_RANK: Record<string, number> = {
  read: 0, internal_write: 1, external_message: 2,
  financial_movement: 3, regulated_decision: 4, irreversible_action: 5,
}

export type Disposition =
  | 'void' | 'void_policy_violation' | 'void_temporal_violation' | 'void_reconciliation_mismatch'
  | 'resource_unbound' | 'authority_invalid' | 'self_attested' | 'regulator_grade_for_class'
  | 'reconciled' | 'intent_precommitted' | 'authority_bound' | 'incomplete_for_class'

export interface RegulatedReceipt {
  profile: string
  receipt_id: string
  action_class: string
  actor_signature: { alg: string; key_id: string; sig: string }
  aps_delegation_ref?: string
  authority_ref?: Record<string, unknown> & { issuer: string; assertion_hash: string; assertion_sig: string; issued_at: string; expires_at: string }
  intent_commitment?: Record<string, unknown> & { intent_hash: string; expected_effect_hash: string; gateway_nonce: string; scope: string; signature: string; created_before_execution: boolean }
  decision_basis_commitment?: { root_hash: string }
  gateway_policy_decision?: Record<string, unknown> & { decision: string; action_class_assigned: string; signer: string; signature: string }
  resource_confirmation_ref?: Record<string, unknown> & { type: string; gateway_nonce_echo: string; realized_effect_hash: string; realized_effect_provenance: string; status: string; signer_key_id: string; signature: string }
  transparency_ref?: { log_id: string; inclusion_proof: Array<{ dir: string; hash: string }>; anchored_at_state: string; leaf_hash: string }
}

export interface RegulatedContext {
  idp_keyset: Record<string, string>
  operator_anchored_idp_copy?: Record<string, string>
  registered_resource_keys: Record<string, { publicKey: string; registered_by_operator: boolean }>
  operator_domain_registry: Record<string, { publicKey: string; identity: string }>
  operator_identity_id: string
  gateway_key_id?: string
  registered_log_roots: Record<string, string>
  reserved_ts: number
  submitted_ts: number
  max_authority_execution_window_ms: number
  per_class_required_fields?: Record<string, string[]>
  completeness_match?: boolean
  anchor_orders_intent_before_resource?: boolean
  non_equivocation_ok?: boolean
}

export interface DispositionResult {
  disposition: Disposition
  incomplete_reason?: string
  violations: Disposition[]
  missing_evidence: string[]
  trust_domain_separation: { computed_domains: number; idp_counts: boolean; resource_counts: boolean; operator_identity: string; separation_ok: boolean }
  authority_basis?: 'external_idp' | 'operator_anchored_copy_weak'
  authority_replay: 'not_evaluated' | 'pass' | 'fail'
  judgment_correctness: 'not_claimed'
}

const RES_VALID_TYPES = new Set(['native_resource_signed', 'boundary_attested'])
const RES_VALID_STATUS = new Set(['accepted', 'settled'])

function jcsHash(obj: unknown): string {
  return createHash('sha256').update(canonicalizeJCS(obj), 'utf8').digest('hex')
}
function sigOk(payload: string, sig: string | undefined, pub: string | undefined): boolean {
  if (!sig || !pub) return false
  try { return edVerify(payload, sig, pub) } catch { return false }
}
function signedPayload(tag: string, sub: Record<string, unknown>, sigField: string): string {
  const c: Record<string, unknown> = { ...sub }
  delete c[sigField]
  return `${tag}.${canonicalizeJCS(c)}`
}

export function rank(actionClass: string): number {
  return ACTION_CLASS_RANK[actionClass] ?? 0
}

/** Deterministic disposition over a receipt + a gateway-assembled context. */
export function evaluateDisposition(receipt: RegulatedReceipt, ctx: RegulatedContext): DispositionResult {
  const missing: string[] = []
  const opReg = ctx.operator_domain_registry || {}

  const actorKey = opReg[receipt.actor_signature?.key_id]?.publicKey
  let cryptoOk = sigOk(
    signedPayload(RAPV0_TAG.actor, { profile: receipt.profile, receipt_id: receipt.receipt_id, action_class: receipt.action_class, key_id: receipt.actor_signature?.key_id }, 'sig'),
    receipt.actor_signature?.sig, actorKey,
  )
  const ic = receipt.intent_commitment
  const pd = receipt.gateway_policy_decision
  if (ic) {
    const signerId = pd?.signer ?? ctx.gateway_key_id
    cryptoOk = cryptoOk && sigOk(signedPayload(RAPV0_TAG.intent, ic, 'signature'), ic.signature, signerId ? opReg[signerId]?.publicKey : undefined)
  }
  if (pd) {
    cryptoOk = cryptoOk && sigOk(signedPayload(RAPV0_TAG.policy, pd, 'signature'), pd.signature, opReg[pd.signer]?.publicKey)
  }
  if (!cryptoOk) missing.push('crypto')

  const rc = receipt.resource_confirmation_ref
  let resSigOk = false
  let resIndependent = false
  if (rc) {
    const rk = ctx.registered_resource_keys?.[rc.signer_key_id]
    resSigOk = sigOk(signedPayload(RAPV0_TAG.resource, rc, 'signature'), rc.signature, rk?.publicKey)
    resIndependent = !!rk && rk.registered_by_operator === false
  }

  const ar = receipt.authority_ref
  const authorityPresent = !!ar
  let authorityOk = false, authorityWeak = false, authorityInvalid = false
  let authorityBasis: DispositionResult['authority_basis']
  if (ar) {
    const claims: Record<string, unknown> = { ...ar }
    delete claims.assertion_sig
    const payload = `${RAPV0_TAG.authority}.${canonicalizeJCS(claims)}`
    const ext = sigOk(payload, ar.assertion_sig, ctx.idp_keyset?.[ar.issuer])
    const op = sigOk(payload, ar.assertion_sig, ctx.operator_anchored_idp_copy?.[ar.issuer])
    const issued = Date.parse(ar.issued_at), expires = Date.parse(ar.expires_at)
    const validAcross = Number.isFinite(issued) && Number.isFinite(expires) && issued <= ctx.reserved_ts && expires >= ctx.submitted_ts
    const within = ctx.submitted_ts - ctx.reserved_ts <= ctx.max_authority_execution_window_ms
    const fresh = validAcross && within
    authorityOk = ext && fresh
    authorityWeak = !authorityOk && !ext && op && fresh
    authorityInvalid = !authorityOk && !authorityWeak
    authorityBasis = authorityOk ? 'external_idp' : authorityWeak ? 'operator_anchored_copy_weak' : undefined
    if (authorityInvalid) missing.push('authority')
  } else {
    missing.push('authority')
  }

  let intentOk = false
  if (ic) {
    const recomputed = jcsHash({
      action_class: receipt.action_class,
      scope: ic.scope,
      authority_assertion_hash: ar?.assertion_hash ?? '',
      decision_basis_root_hash: receipt.decision_basis_commitment?.root_hash ?? '',
      expected_effect_hash: ic.expected_effect_hash,
    })
    intentOk = ic.created_before_execution === true && recomputed === ic.intent_hash
  }

  const policyAllow = !!pd && pd.decision === 'allow' && pd.action_class_assigned === receipt.action_class
  const policyDeny = !!pd && (pd.decision === 'deny' || pd.decision === 'hold')

  const resPresentValid = !!rc && RES_VALID_TYPES.has(rc.type) && rc.realized_effect_provenance === 'ban_derived' && resSigOk && resIndependent && RES_VALID_STATUS.has(rc.status)
  const resMatches = intentOk && !!rc && !!ic && rc.gateway_nonce_echo === ic.gateway_nonce && rc.realized_effect_hash === ic.expected_effect_hash
  const resOk = resPresentValid && resMatches
  const executed = resPresentValid || ctx.completeness_match === true

  let anchorPresent = false
  const tr = receipt.transparency_ref
  if (tr) {
    const root = ctx.registered_log_roots?.[tr.log_id]
    let proofOk = false
    if (root) {
      let acc = tr.leaf_hash
      try {
        for (const step of tr.inclusion_proof) {
          acc = step.dir === 'L' ? jcsHash({ l: step.hash, r: acc }) : jcsHash({ l: acc, r: step.hash })
        }
        proofOk = acc === root
      } catch { proofOk = false }
    }
    anchorPresent = proofOk && tr.anchored_at_state === 'reserved'
  }
  if (!anchorPresent) missing.push('transparency_anchor')

  const temporalViolation = anchorPresent && ctx.anchor_orders_intent_before_resource === false
  const temporalConsistent = anchorPresent && ctx.anchor_orders_intent_before_resource === true
  const noneqOk = anchorPresent && ctx.non_equivocation_ok !== false

  const idpCounts = authorityOk
  const resourceCounts = resOk && resIndependent
  const domains = (idpCounts ? 1 : 0) + (resourceCounts ? 1 : 0)

  const opKeys: string[] = []
  if (receipt.actor_signature?.key_id) opKeys.push(receipt.actor_signature.key_id)
  if (pd?.signer) opKeys.push(pd.signer)
  if (ic) { const s = pd?.signer ?? ctx.gateway_key_id; if (s) opKeys.push(s) }
  const separationOk = opKeys.every((k) => opReg[k]?.identity === ctx.operator_identity_id)

  const req = ctx.per_class_required_fields?.[receipt.action_class] ?? []
  const perClassOk = req.length > 0 && req.every((f) => (receipt as unknown as Record<string, unknown>)[f] !== undefined)

  const terminal: Array<[boolean, Disposition]> = [
    [!cryptoOk, 'void'],
    [policyDeny && executed, 'void_policy_violation'],
    [resPresentValid && !!ic && temporalViolation, 'void_temporal_violation'],
    [resPresentValid && intentOk && !resMatches, 'void_reconciliation_mismatch'],
    [resPresentValid && !intentOk, 'resource_unbound'],
    [authorityInvalid, 'authority_invalid'],
    [!authorityPresent && !resPresentValid, 'self_attested'],
  ]
  const violations = terminal.filter(([h]) => h).map(([, d]) => d)

  let disposition: Disposition
  let incompleteReason: string | undefined
  const first = terminal.find(([h]) => h)
  if (first) {
    disposition = first[1]
  } else if (authorityOk && intentOk && policyAllow && resOk && domains >= 2 && temporalConsistent && noneqOk && perClassOk && separationOk) {
    disposition = 'regulator_grade_for_class'
  } else if (authorityOk && intentOk && policyAllow && resOk && domains >= 2 && temporalConsistent) {
    disposition = 'reconciled'
  } else if (authorityOk && intentOk && policyAllow && !resOk) {
    disposition = 'intent_precommitted'
  } else if (authorityOk && !intentOk) {
    disposition = 'authority_bound'
  } else {
    disposition = 'incomplete_for_class'
    if (policyDeny) incompleteReason = 'policy_denied_no_execution'
    else if (!authorityOk) incompleteReason = 'missing_authority'
    else if (!anchorPresent) incompleteReason = 'missing_transparency_anchor'
    else incompleteReason = 'execution_unconfirmed'
  }

  if ((disposition === 'reconciled' || disposition === 'regulator_grade_for_class') && !(domains >= 2 && resOk && temporalConsistent)) {
    throw new Error('RAPV0 invariant breach in gateway matcher')
  }

  const result: DispositionResult = {
    disposition,
    violations,
    missing_evidence: missing,
    trust_domain_separation: { computed_domains: domains, idp_counts: idpCounts, resource_counts: resourceCounts, operator_identity: ctx.operator_identity_id, separation_ok: separationOk },
    authority_replay: 'not_evaluated',
    judgment_correctness: 'not_claimed',
  }
  if (incompleteReason) result.incomplete_reason = incompleteReason
  if (authorityBasis) result.authority_basis = authorityBasis
  return result
}

export { jcsHash, canonicalizeJCS }
