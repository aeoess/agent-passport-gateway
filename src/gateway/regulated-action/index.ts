// APS Regulated Action Profile v0: gateway orchestrator (private).
//
// The FORCED CHOKEPOINT and lifecycle state machine. A regulated action (class rank >= 3) cannot
// reach finality except through reconcile(): markFinal() THROWS if the disposition is not
// reconciled/regulator_grade_for_class with a passing replay check. This is where the protocol's
// "no finality without reconciliation against two external domains" is ENFORCED, not just attested.
//
// Honest floor: with the reference-build BAN at level_1, the resource confirmation is
// boundary_attested_weak, so the disposition is intent_precommitted and markFinal() refuses to
// finalize. reconciled finality requires a level_2 BAN deployment (a separate principal the
// gateway uid cannot ptrace). The gateway does not relax this.

import { evaluateDisposition, rank, type RegulatedReceipt, type RegulatedContext, type DispositionResult } from './disposition.js'
import { anchorReservedIntent, type TransparencyAnchor } from './transparency.js'
import { openRaStore, type RaStore, type LifecycleState } from './store.js'
import { type BanSigner, spawnBan } from './ban.js'

export * from './disposition.js'
export * from './transparency.js'
export * from './completeness.js'
export { openRaStore } from './store.js'
export type { RaStore, LifecycleState } from './store.js'
export { spawnBan } from './ban.js'
export type { BanSigner } from './ban.js'
export { bindAuthorityCeiling, actionWithinCeiling, type AuthorityCeiling, type AuthorityAnchor } from './authority.js'

export class RegulatedChokepointError extends Error {
  constructor(message: string, public readonly result: DispositionResult) {
    super(message)
    this.name = 'RegulatedChokepointError'
  }
}

export interface ReconcileOutcome {
  result: DispositionResult
  final: boolean
  replayed: boolean
  state: LifecycleState
}

function mapState(disposition: string, final: boolean): LifecycleState {
  if (final) return 'reconciled'
  if (disposition.startsWith('void') || disposition === 'resource_unbound') return 'voided'
  if (disposition === 'intent_precommitted' || disposition === 'authority_bound') return 'intent_precommitted'
  return 'incomplete'
}

export interface RegulatedGateway {
  reserveIntent(tenantId: string, receipt: RegulatedReceipt, intentHash: string): TransparencyAnchor
  reconcile(tenantId: string, receipt: RegulatedReceipt, ctx: RegulatedContext): ReconcileOutcome
  /** Chokepoint: returns the result, or throws RegulatedChokepointError for an unfinalizable rank>=3 action. */
  markFinal(tenantId: string, receipt: RegulatedReceipt, ctx: RegulatedContext): ReconcileOutcome
}

export function createRegulatedGateway(store: RaStore): RegulatedGateway {
  return {
    reserveIntent(tenantId, receipt, intentHash) {
      const anchor = anchorReservedIntent(receipt.receipt_id, intentHash)
      store.setState(tenantId, receipt.receipt_id, 'intent_reserved')
      return anchor
    },

    reconcile(tenantId, receipt, ctx) {
      const result = evaluateDisposition(receipt, ctx)

      // Replay layer (the gateway concern the public verifier defers as not_evaluated).
      let replayed = false
      const ar = receipt.authority_ref
      const ic = receipt.intent_commitment
      if (ar?.jti) {
        const owner = store.bindOwner(tenantId, 'jti', String(ar.jti), receipt.receipt_id)
        if (owner !== receipt.receipt_id) replayed = true
      }
      if (ic?.gateway_nonce) {
        const owner = store.bindOwner(tenantId, 'nonce', String(ic.gateway_nonce), receipt.receipt_id)
        if (owner !== receipt.receipt_id) replayed = true
      }
      result.authority_replay = replayed ? 'fail' : 'pass'

      const wouldBeFinal = result.disposition === 'reconciled' || result.disposition === 'regulator_grade_for_class'
      const final = wouldBeFinal && !replayed
      const state = mapState(result.disposition, final)
      store.setState(tenantId, receipt.receipt_id, state)
      return { result, final, replayed, state }
    },

    markFinal(tenantId, receipt, ctx) {
      const outcome = this.reconcile(tenantId, receipt, ctx)
      if (rank(receipt.action_class) >= 3 && !outcome.final) {
        throw new RegulatedChokepointError(
          `regulated action ${receipt.receipt_id} (class ${receipt.action_class}) cannot be finalized: ` +
          `disposition=${outcome.result.disposition}` +
          (outcome.result.incomplete_reason ? `:${outcome.result.incomplete_reason}` : '') +
          `, replay=${outcome.result.authority_replay}, domains=${outcome.result.trust_domain_separation.computed_domains}`,
          outcome.result,
        )
      }
      return outcome
    },
  }
}

/** Convenience: open an in-memory gateway (tests) or a path-backed one (deployment). */
export function openRegulatedGateway(path = ':memory:'): { gateway: RegulatedGateway; store: RaStore } {
  const store = openRaStore(path)
  return { gateway: createRegulatedGateway(store), store }
}

export { spawnBan as spawnBoundaryAttestationNode }
