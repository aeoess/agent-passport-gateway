// APS Regulated Action Profile v0: private gateway subsystem tests.
// Covers the forced chokepoint, lifecycle state machine, the level_1 BAN honest floor (the live
// path returns intent_precommitted, not reconciled), the BAN forge test, replay detection, the
// completeness/orphan layer, authority ceiling binding, and transparency inclusion. A level_2 BAN
// is SIMULATED (an independently-registered boundary_attested confirmation) to prove the verifier
// and chokepoint do reconcile under a genuine level_2 deployment, which is the deployment upgrade.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { sign, publicKeyFromPrivate, canonicalizeJCS } from 'agent-passport-system'
import {
  openRegulatedGateway, RegulatedChokepointError, spawnBoundaryAttestationNode,
  anchorReservedIntent, verifyInclusion, detectOrphans, bindAuthorityCeiling, actionWithinCeiling,
  jcsHash, RAPV0_TAG, evaluateDisposition,
  type BanSigner, type RegulatedReceipt, type RegulatedContext,
} from '../src/gateway/regulated-action/index.js'

const priv = (l: string) => createHash('sha256').update(`rapv0-gw-${l}`).digest('hex')
const idpPriv = priv('idp'); const idpPub = publicKeyFromPrivate(idpPriv)
const gwPriv = priv('gw'); const gwPub = publicKeyFromPrivate(gwPriv)
const agentPriv = priv('agent'); const agentPub = publicKeyFromPrivate(agentPriv)
const strongPriv = priv('strong-resource'); const strongPub = publicKeyFromPrivate(strongPriv)

const ISSUER = 'https://idp.example.com'
const RES = 1700000000000
const SUB = RES + 60000
const ISO = (ms: number) => new Date(ms).toISOString()

function baseCtx(overrides: Partial<RegulatedContext> = {}): RegulatedContext {
  return {
    idp_keyset: { [ISSUER]: idpPub },
    registered_resource_keys: {},
    operator_domain_registry: {
      'agent-key': { publicKey: agentPub, identity: 'op-1' },
      'gw-key': { publicKey: gwPub, identity: 'op-1' },
    },
    operator_identity_id: 'op-1',
    gateway_key_id: 'gw-key',
    registered_log_roots: {},
    reserved_ts: RES,
    submitted_ts: SUB,
    max_authority_execution_window_ms: 900000,
    anchor_orders_intent_before_resource: true,
    ...overrides,
  }
}

function buildAuthority(id: string) {
  const claims = {
    type: 'id_jag', issuer: ISSUER, subject: 'agent:bot-1', audience: 'bank-api',
    scope_hash: jcsHash({ s: id }), issued_at: ISO(RES - 5000), expires_at: ISO(SUB + 3600000),
    assertion_hash: jcsHash({ a: id }), jti: `jti-${id}`,
  }
  const sig = sign(`${RAPV0_TAG.authority}.${canonicalizeJCS(claims)}`, idpPriv)
  return { ...claims, assertion_sig: sig }
}

function buildHonestCore(id: string) {
  const action_class = 'financial_movement'
  const ar = buildAuthority(id)
  const dbRoot = jcsHash({ db: id })
  const expected_effect_hash = jcsHash({ effect: id })
  const scope = `transfer:${id}`
  const gateway_nonce = `nonce-${id}`
  const intent_hash = jcsHash({ action_class, scope, authority_assertion_hash: ar.assertion_hash, decision_basis_root_hash: dbRoot, expected_effect_hash })
  const icCore = { created_before_execution: true, intent_hash, expected_effect_hash, gateway_nonce, timestamp_ms: RES, scope }
  const ic = { ...icCore, signature: sign(`${RAPV0_TAG.intent}.${canonicalizeJCS(icCore)}`, gwPriv) }
  const pdCore = { policy_version_hash: jcsHash({ p: id }), decision: 'allow', action_class_assigned: action_class, signer: 'gw-key' }
  const pd = { ...pdCore, signature: sign(`${RAPV0_TAG.policy}.${canonicalizeJCS(pdCore)}`, gwPriv) }
  const actorCore = { profile: 'aps-regulated-action-v0', receipt_id: `r-${id}`, action_class, key_id: 'agent-key' }
  const actor_signature = { alg: 'ed25519', key_id: 'agent-key', sig: sign(`${RAPV0_TAG.actor}.${canonicalizeJCS(actorCore)}`, agentPriv) }
  return { id, action_class, ar, dbRoot, expected_effect_hash, gateway_nonce, intent_hash, ic, pd, actor_signature }
}

function assembleReceipt(c: ReturnType<typeof buildHonestCore>, resource_confirmation_ref?: Record<string, unknown>): RegulatedReceipt {
  const anchor = anchorReservedIntent(`r-${c.id}`, c.intent_hash)
  return {
    profile: 'aps-regulated-action-v0', receipt_id: `r-${c.id}`, action_class: c.action_class,
    actor_signature: c.actor_signature,
    authority_ref: c.ar,
    intent_commitment: c.ic,
    decision_basis_commitment: { root_hash: c.dbRoot },
    gateway_policy_decision: c.pd,
    ...(resource_confirmation_ref ? { resource_confirmation_ref: resource_confirmation_ref as RegulatedReceipt['resource_confirmation_ref'] } : {}),
    transparency_ref: anchor.transparency_ref,
  }
}
function ctxFor(c: ReturnType<typeof buildHonestCore>, overrides: Partial<RegulatedContext> = {}): RegulatedContext {
  const anchor = anchorReservedIntent(`r-${c.id}`, c.intent_hash)
  return baseCtx({ registered_log_roots: { [anchor.log_id]: anchor.root }, ...overrides })
}

// A level_2-grade (independently registered, boundary_attested) confirmation, signed off-BAN.
function strongResourceConfirmation(c: ReturnType<typeof buildHonestCore>) {
  const core = {
    type: 'boundary_attested', resource_transaction_id: `tx-${c.id}`, correlation_id: `corr-${c.id}`,
    gateway_nonce_echo: c.gateway_nonce, realized_effect_hash: c.expected_effect_hash,
    realized_effect_provenance: 'ban_derived', status: 'settled', timestamp_ms: SUB, signer_key_id: 'strong-key',
  }
  return { ...core, signature: sign(`${RAPV0_TAG.resource}.${canonicalizeJCS(core)}`, strongPriv) }
}

describe('RAPV0 gateway: forced chokepoint + honest level_1 floor', () => {
  let ban: BanSigner
  before(() => { ban = spawnBoundaryAttestationNode() })
  after(() => { ban.close() })

  it('the BAN is level_1 / boundary_attested_weak and exposes no key-extraction method (forge test)', async () => {
    const pub = await ban.getPublicKey()
    assert.equal(pub.length, 64)
    assert.equal(ban.level, 'level_1')
    assert.equal(ban.resourceConfirmationType(), 'boundary_attested_weak')
    // forge test: the handle has no path to the private key
    const keys = Object.keys(ban)
    assert.ok(!keys.some((k) => /private|secret|seed/i.test(k)), 'no private-key accessor on the BAN handle')
    assert.equal((ban as Record<string, unknown>).privateKey, undefined)
    assert.equal((ban as Record<string, unknown>).getPrivateKey, undefined)
  })

  it('honest end-to-end with the level_1 BAN returns intent_precommitted, NOT reconciled', async () => {
    const c = buildHonestCore('e2e-1')
    const core = {
      type: ban.resourceConfirmationType(), resource_transaction_id: 'tx-e2e-1', correlation_id: 'corr-e2e-1',
      gateway_nonce_echo: c.gateway_nonce, realized_effect_hash: c.expected_effect_hash,
      realized_effect_provenance: 'ban_derived', status: 'settled', timestamp_ms: SUB, signer_key_id: 'ban-key',
    }
    const sig = await ban.signResourceConfirmation(core)
    const rc = { ...core, signature: sig }
    const receipt = assembleReceipt(c, rc)
    const ctx = ctxFor(c, { registered_resource_keys: { 'ban-key': { publicKey: await ban.getPublicKey(), registered_by_operator: false } } })

    const { gateway, store } = openRegulatedGateway()
    gateway.reserveIntent('tenant-1', receipt, c.intent_hash)
    assert.equal(store.getState('tenant-1', receipt.receipt_id), 'intent_reserved')

    const outcome = gateway.reconcile('tenant-1', receipt, ctx)
    assert.equal(outcome.result.disposition, 'intent_precommitted')
    assert.equal(outcome.final, false)
    assert.equal(store.getState('tenant-1', receipt.receipt_id), 'intent_precommitted')

    // chokepoint: a regulated action cannot be finalized on the honest level_1 path
    assert.throws(() => gateway.markFinal('tenant-1', receipt, ctx), RegulatedChokepointError)
    store.close()
  })

  it('the chokepoint refuses finality for a forged (gateway-held key) resource confirmation', async () => {
    const c = buildHonestCore('forge-1')
    // sign with the gateway key but present it as a resource confirmation under an unregistered id
    const core = {
      type: 'boundary_attested', resource_transaction_id: 'tx-forge', correlation_id: 'corr-forge',
      gateway_nonce_echo: c.gateway_nonce, realized_effect_hash: c.expected_effect_hash,
      realized_effect_provenance: 'ban_derived', status: 'settled', timestamp_ms: SUB, signer_key_id: 'unregistered',
    }
    const rc = { ...core, signature: sign(`${RAPV0_TAG.resource}.${canonicalizeJCS(core)}`, gwPriv) }
    const receipt = assembleReceipt(c, rc)
    const ctx = ctxFor(c) // 'unregistered' not in registered_resource_keys
    const { gateway, store } = openRegulatedGateway()
    const outcome = gateway.reconcile('tenant-1', receipt, ctx)
    assert.equal(outcome.result.disposition, 'intent_precommitted') // not reconciled, not void
    assert.throws(() => gateway.markFinal('tenant-1', receipt, ctx), RegulatedChokepointError)
    store.close()
  })
})

describe('RAPV0 gateway: level_2 deployment reconciles (finality is deployment-gated)', () => {
  it('an independently registered boundary_attested confirmation reconciles and finalizes', () => {
    const c = buildHonestCore('lvl2-1')
    const rc = strongResourceConfirmation(c)
    const receipt = assembleReceipt(c, rc)
    const ctx = ctxFor(c, { registered_resource_keys: { 'strong-key': { publicKey: strongPub, registered_by_operator: false } } })
    const { gateway, store } = openRegulatedGateway()
    const outcome = gateway.markFinal('tenant-1', receipt, ctx)
    assert.equal(outcome.result.disposition, 'reconciled')
    assert.equal(outcome.final, true)
    assert.equal(outcome.result.trust_domain_separation.computed_domains, 2)
    assert.equal(store.getState('tenant-1', receipt.receipt_id), 'reconciled')
    store.close()
  })

  it('replay: a different receipt reusing the same authority jti is flagged and cannot finalize', () => {
    const c1 = buildHonestCore('replay-a')
    const receipt1 = assembleReceipt(c1, strongResourceConfirmation(c1))
    const ctx1 = ctxFor(c1, { registered_resource_keys: { 'strong-key': { publicKey: strongPub, registered_by_operator: false } } })
    const { gateway, store } = openRegulatedGateway()
    const first = gateway.markFinal('tenant-1', receipt1, ctx1)
    assert.equal(first.final, true)

    // second receipt, different id, reuses the SAME jti
    const c2 = buildHonestCore('replay-b')
    c2.ar.jti = c1.ar.jti // forced reuse
    const receipt2 = assembleReceipt(c2, strongResourceConfirmation(c2))
    const ctx2 = ctxFor(c2, { registered_resource_keys: { 'strong-key': { publicKey: strongPub, registered_by_operator: false } } })
    const second = gateway.reconcile('tenant-1', receipt2, ctx2)
    assert.equal(second.replayed, true)
    assert.equal(second.result.authority_replay, 'fail')
    assert.equal(second.final, false)
    store.close()
  })
})

describe('RAPV0 gateway: completeness, authority ceiling, transparency', () => {
  it('completeness: in-scope unreceipted event is an orphan (V20); out-of-scope is not (V21)', () => {
    const v20 = detectOrphans({
      coverage_scope: { resource: 'bank-api', tenant: 'tenant-1' },
      resource_events: [{ resource: 'bank-api', tenant: 'tenant-1', resource_transaction_id: 'tx-orphan', timestamp_ms: SUB }],
      reconciled_correlation_ids: [],
    })
    assert.equal(v20.orphans.length, 1)
    assert.equal(v20.orphans[0].resource_transaction_id, 'tx-orphan')

    const v21 = detectOrphans({
      coverage_scope: { resource: 'bank-api', tenant: 'tenant-1' },
      resource_events: [{ resource: 'other-system', tenant: 'tenant-1', resource_transaction_id: 'tx-oob', timestamp_ms: SUB }],
      reconciled_correlation_ids: [],
    })
    assert.equal(v21.orphans.length, 0)
    assert.equal(v21.out_of_scope, 1)
  })

  it('authority ceiling: monotonic narrowing, never widening', () => {
    const ceiling = bindAuthorityCeiling({ type: 'id_jag', subject: 'agent:bot-1', audience: 'bank-api', scope_hash: 'x', expires_at: ISO(SUB + 1000), granted_max_action_class: 'financial_movement' })
    assert.equal(actionWithinCeiling('external_message', ceiling), true)
    assert.equal(actionWithinCeiling('financial_movement', ceiling), true)
    assert.equal(actionWithinCeiling('irreversible_action', ceiling), false)
  })

  it('transparency: a valid inclusion proof verifies; a tampered leaf does not', () => {
    const anchor = anchorReservedIntent('r-tr-1', jcsHash({ i: 1 }))
    assert.equal(verifyInclusion(anchor.transparency_ref.leaf_hash, anchor.transparency_ref.inclusion_proof, anchor.root), true)
    assert.equal(verifyInclusion(jcsHash({ tampered: true }), anchor.transparency_ref.inclusion_proof, anchor.root), false)
  })

  it('a same-uid forged confirmation never reconciles even with intent precommitted (disposition unit)', () => {
    const c = buildHonestCore('unit-weak')
    const core = {
      type: 'boundary_attested_weak', resource_transaction_id: 'tx', correlation_id: 'corr',
      gateway_nonce_echo: c.gateway_nonce, realized_effect_hash: c.expected_effect_hash,
      realized_effect_provenance: 'ban_derived', status: 'settled', timestamp_ms: SUB, signer_key_id: 'strong-key',
    }
    const rc = { ...core, signature: sign(`${RAPV0_TAG.resource}.${canonicalizeJCS(core)}`, strongPriv) }
    const receipt = assembleReceipt(c, rc)
    const ctx = ctxFor(c, { registered_resource_keys: { 'strong-key': { publicKey: strongPub, registered_by_operator: false } } })
    const r = evaluateDisposition(receipt, ctx)
    assert.equal(r.disposition, 'intent_precommitted')
    assert.equal(r.judgment_correctness, 'not_claimed')
  })
})
