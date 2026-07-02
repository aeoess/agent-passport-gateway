// APS Regulated Action Profile v0: authority binding (private gateway).
//
// Binds the external authority anchor (EMA / ID-JAG, an IETF draft) to an authority ceiling the
// gateway enforces at action time. The ceiling is the monotonic upper bound: a delegated agent's
// action can be narrowed below it, never widened above it. This is the integration seam for
// enforce.ts entity authority_ceiling; v0 derives the ceiling fields from the validated anchor.
//
// EMA is built on ID-JAG; ID-JAG is an IETF draft (draft-ietf-oauth-identity-assertion-authz-grant).
// We do not call ID-JAG "the MCP standard" and we do not invent an "XAA" anchor.

import { rank } from './disposition.js'

export interface AuthorityCeiling {
  source: 'id_jag' | 'ema'
  subject: string
  audience: string
  scope_hash: string
  not_after: string
  /** Maximum action class this authority grants. An action above this rank is refused. */
  max_action_class: string
}

export interface AuthorityAnchor {
  type: 'id_jag' | 'ema'
  subject: string
  audience: string
  scope_hash: string
  expires_at: string
  granted_max_action_class?: string
}

/** Derive the enforced ceiling from a validated authority anchor. */
export function bindAuthorityCeiling(anchor: AuthorityAnchor): AuthorityCeiling {
  return {
    source: anchor.type,
    subject: anchor.subject,
    audience: anchor.audience,
    scope_hash: anchor.scope_hash,
    not_after: anchor.expires_at,
    max_action_class: anchor.granted_max_action_class ?? 'financial_movement',
  }
}

/** Monotonic narrowing: an action is within the ceiling only if its rank does not exceed it. */
export function actionWithinCeiling(actionClass: string, ceiling: AuthorityCeiling): boolean {
  return rank(actionClass) <= rank(ceiling.max_action_class)
}
