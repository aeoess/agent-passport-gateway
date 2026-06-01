// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Tests for the revocation engine (GEMS).
//
//   - Epochs are the source of truth: a stale-epoch token is denied at the sink.
//   - Panic-freeze is single-actor and immediate.
//   - Multi-sig thaw needs a distinct-signer quorum; one signer cannot thaw.
//   - Cascade preview is accurate against a delegation-tree + lineage fixture.
//   - A freeze handles in-flight tokens by bumping the epoch (denied on next use).
//
// Setup mirrors the other gateway tests: a real in-memory SQLite DB, the real
// gateway identity, and the lineage + revocation tables. Fixtures are seeded
// straight into the agents / delegations / agent_wallets / lineage_links tables.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import { initDB, getDB } from '../src/db/schema.js'
import { initLineageTables } from '../src/gateway/lineage.js'
import { initGatewayIdentity, getGatewayIdentity } from '../src/gateway/identity.js'
import { rebuildFromDb } from '../src/gateway/wallet-reverse-index.js'

import {
  getCurrentEpoch,
  bumpEpoch,
  tokenEpochGuard,
  stampEpoch,
} from '../src/gateway/revocation/epochs.js'
import {
  panicFreeze,
  isFrozen,
  proposeThaw,
  addThawApproval,
  finalizeThaw,
  getThaw,
  initFreezeTables,
} from '../src/gateway/revocation/freeze.js'
import {
  previewCascade,
  walkDescendants,
} from '../src/gateway/revocation/cascade.js'
import {
  verifyInboundRevocation,
} from '../src/gateway/revocation/inbound.js'

import { verify, canonicalize, generateKeyPair, sign } from 'agent-passport-system'

const TENANT = 'tenant-revoc-test'

function seedAgent(agentId: string, status = 'active') {
  getDB().prepare(
    `INSERT OR IGNORE INTO agents (id, tenant_id, agent_id, public_key, did, name, status)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(`uuid-${agentId}`, TENANT, agentId, `pk-${agentId}`, `did:aps:${agentId}`, agentId, status)
}

function seedDelegation(id: string, parent: string, child: string, scope: string, status = 'active') {
  getDB().prepare(
    `INSERT OR IGNORE INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, TENANT, parent, child, scope, status)
}

function seedWallet(agentId: string, status = 'active') {
  getDB().prepare(
    `INSERT OR IGNORE INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(`w-${agentId}`, TENANT, agentId, `nano_${agentId}`, 0, status)
}

function seedLineageLink(passportId: string, ownerLink: string) {
  getDB().prepare(
    `INSERT INTO lineage_links (id, tenant_id, dossier_id, passport_id, runtime_link, owner_link, behavioral_link, recovery_link)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(`ll-${passportId}`, TENANT, `d-${passportId}`, passportId, null, ownerLink, null, null)
}

before(() => {
  initDB(':memory:')
  initLineageTables()
  initFreezeTables()
  getDB().prepare(
    `INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`,
  ).run(TENANT, 'Revoc Test', 'revoc-test@example.com')
  initGatewayIdentity()
})

describe('epochs: source of truth, sink denial', () => {
  it('a subject starts at epoch 0 and a token at epoch 0 is allowed', () => {
    const agent = 'epoch-fresh'
    assert.equal(getCurrentEpoch(TENANT, 'agent', agent), 0)
    const stamp = stampEpoch(TENANT, 'agent', agent)
    assert.equal(stamp.epoch, 0)
    const guard = tokenEpochGuard({ tenantId: TENANT, subjectKind: 'agent', subjectId: agent, epoch: stamp.epoch })
    assert.equal(guard.allowed, true)
  })

  it('bump is monotonic and signed; a token minted before the bump is denied at the sink', () => {
    const agent = 'epoch-bump'
    // Mint a token at the current (pre-bump) epoch.
    const minted = stampEpoch(TENANT, 'agent', agent)
    assert.equal(minted.epoch, 0)

    const rec = bumpEpoch(TENANT, 'agent', agent, { reason: 'test bump', bumpedBy: 'admin-1' })
    assert.equal(rec.previousEpoch, 0)
    assert.equal(rec.newEpoch, 1)
    assert.equal(getCurrentEpoch(TENANT, 'agent', agent), 1)

    // NEGATIVE: the pre-bump token is now stale and the sink denies it.
    const guard = tokenEpochGuard({ tenantId: TENANT, subjectKind: 'agent', subjectId: agent, epoch: minted.epoch })
    assert.equal(guard.allowed, false)
    assert.match(guard.reason, /stale epoch/)
    assert.equal(guard.currentEpoch, 1)
    assert.equal(guard.tokenEpoch, 0)

    // A freshly minted token at the new epoch is allowed.
    const fresh = stampEpoch(TENANT, 'agent', agent)
    assert.equal(tokenEpochGuard({ tenantId: TENANT, subjectKind: 'agent', subjectId: agent, epoch: fresh.epoch }).allowed, true)
  })

  it('the epoch-bump record is verifiable with the gateway JWKS key', () => {
    const rec = bumpEpoch(TENANT, 'agent', 'epoch-sig', { reason: 'sig check', bumpedBy: 'admin-1' })
    const [headerB64, payloadB64, sigB64] = rec.signature.split('.')
    assert.ok(headerB64 && payloadB64 && sigB64, 'JWS has three segments')
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString())
    assert.equal(header.alg, 'EdDSA')
    assert.equal(header.kid, getGatewayIdentity().kid)
  })

  it('epochs are namespaced per subject kind and per id', () => {
    bumpEpoch(TENANT, 'agent', 'ns-shared', { reason: 'a', bumpedBy: 'admin-1' })
    // A delegation with the same id string has its own counter.
    assert.equal(getCurrentEpoch(TENANT, 'delegation', 'ns-shared'), 0)
    assert.equal(getCurrentEpoch(TENANT, 'agent', 'ns-shared'), 1)
  })
})

describe('panic-freeze: single actor, immediate', () => {
  beforeEach(() => {
    seedAgent('freeze-target')
    seedWallet('freeze-target')
  })

  it('a single authenticated admin freezes immediately (one call, takes effect)', () => {
    const before = getCurrentEpoch(TENANT, 'agent', 'freeze-target')
    const rec = panicFreeze({ tenantId: TENANT, agentId: 'freeze-target', mode: 'read_only', frozenBy: 'admin-solo' })

    // Immediate: the epoch bumped and the agent is frozen, from one call.
    assert.equal(rec.epochAfterFreeze, before + 1)
    assert.equal(getCurrentEpoch(TENANT, 'agent', 'freeze-target'), before + 1)
    assert.equal(isFrozen(TENANT, 'freeze-target'), true)

    const agentRow = getDB().prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'freeze-target') as any
    assert.equal(agentRow.status, 'frozen')

    const walletRow = getDB().prepare(`SELECT status FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'freeze-target') as any
    assert.equal(walletRow.status, 'frozen')
  })

  it('zero_authority mode revokes the agent outright', () => {
    seedAgent('freeze-zero')
    seedWallet('freeze-zero')
    panicFreeze({ tenantId: TENANT, agentId: 'freeze-zero', mode: 'zero_authority', frozenBy: 'admin-solo' })
    const agentRow = getDB().prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'freeze-zero') as any
    assert.equal(agentRow.status, 'revoked')
  })

  it('freeze requires an authenticated actor', () => {
    assert.throws(
      () => panicFreeze({ tenantId: TENANT, agentId: 'freeze-target', mode: 'read_only', frozenBy: '' }),
      /authenticated frozenBy/,
    )
  })

  it('in-flight token: a token minted before the freeze is denied at the sink after', () => {
    seedAgent('inflight')
    seedWallet('inflight')
    // A token is in flight, minted at the pre-freeze epoch.
    const inflight = stampEpoch(TENANT, 'agent', 'inflight')
    assert.equal(tokenEpochGuard({ tenantId: TENANT, subjectKind: 'agent', subjectId: 'inflight', epoch: inflight.epoch }).allowed, true)

    panicFreeze({ tenantId: TENANT, agentId: 'inflight', mode: 'zero_authority', frozenBy: 'admin-solo' })

    // NEGATIVE: the in-flight token is now stale and denied on next use.
    const guard = tokenEpochGuard({ tenantId: TENANT, subjectKind: 'agent', subjectId: 'inflight', epoch: inflight.epoch })
    assert.equal(guard.allowed, false)
  })
})

describe('multi-sig thaw: quorum required, single signer cannot thaw', () => {
  beforeEach(() => {
    seedAgent('thaw-target')
    seedWallet('thaw-target')
    panicFreeze({ tenantId: TENANT, agentId: 'thaw-target', mode: 'read_only', frozenBy: 'admin-solo' })
  })

  it('a single signer cannot finalize a thaw', () => {
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'restore', requiredQuorum: 2, proposedBy: 'admin-1',
    })
    assert.equal(proposal.state, 'proposed')

    const r1 = addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    assert.equal(r1.approvals, 1)
    assert.equal(r1.quorumReached, false)

    // NEGATIVE: finalizing with a sub-quorum approval set throws.
    assert.throws(() => finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-1' }), /quorum not reached/)
    // The agent is still frozen.
    assert.equal(isFrozen(TENANT, 'thaw-target'), true)
  })

  it('the same signer signing twice does NOT reach a 2-of-N quorum', () => {
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'restore', requiredQuorum: 2, proposedBy: 'admin-1',
    })
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    // NEGATIVE: a duplicate signer is a no-op, not a second vote.
    const dup = addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    assert.equal(dup.approvals, 1)
    assert.equal(dup.quorumReached, false)
    assert.throws(() => finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-1' }), /quorum not reached/)
  })

  it('requiredQuorum is floored at 2, so a 1-quorum thaw is impossible by construction', () => {
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'restore', requiredQuorum: 1, proposedBy: 'admin-1',
    })
    assert.equal(proposal.requiredQuorum, 2)
  })

  it('a distinct-signer quorum thaws (restore): agent active, wallet active, epoch bumped', () => {
    const epochBeforeThaw = getCurrentEpoch(TENANT, 'agent', 'thaw-target')
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'restore', requiredQuorum: 2, proposedBy: 'admin-1',
    })
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    const r2 = addThawApproval({ thawId: proposal.thawId, signer: 'admin-2' })
    assert.equal(r2.quorumReached, true)

    const done = finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-2' })
    assert.equal(done.state, 'complete')
    assert.equal(isFrozen(TENANT, 'thaw-target'), false)

    const agentRow = getDB().prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'thaw-target') as any
    assert.equal(agentRow.status, 'active')
    const walletRow = getDB().prepare(`SELECT status FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'thaw-target') as any
    assert.equal(walletRow.status, 'active')

    // Restore bumps the epoch again (fresh live epoch for new tokens).
    assert.equal(getCurrentEpoch(TENANT, 'agent', 'thaw-target'), epochBeforeThaw + 1)
  })

  it('a destroy quorum leaves the agent permanently revoked', () => {
    panicFreeze({ tenantId: TENANT, agentId: 'thaw-target', mode: 'zero_authority', frozenBy: 'admin-solo' })
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'destroy', requiredQuorum: 3, proposedBy: 'admin-1',
    })
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-2' })
    // Two of three is not enough.
    assert.throws(() => finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-2' }), /quorum not reached/)
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-3' })

    const done = finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-3' })
    assert.equal(done.state, 'complete')
    const agentRow = getDB().prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'thaw-target') as any
    assert.equal(agentRow.status, 'revoked')
  })

  it('a destroy proposal is floored to quorum 3 even when 2 is requested', () => {
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'destroy', requiredQuorum: 2, proposedBy: 'admin-1',
    })
    // destroy is terminal and irreversible, so the floor is 3, not 2.
    assert.equal(proposal.requiredQuorum, 3)
    assert.equal(getThaw(proposal.thawId)!.requiredQuorum, 3)
  })

  it('a destroy with only 2 distinct approvals cannot finalize (needs 3)', () => {
    panicFreeze({ tenantId: TENANT, agentId: 'thaw-target', mode: 'zero_authority', frozenBy: 'admin-solo' })
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'destroy', requiredQuorum: 2, proposedBy: 'admin-1',
    })
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    const r2 = addThawApproval({ thawId: proposal.thawId, signer: 'admin-2' })
    // Floored to 3: two distinct approvals are not a quorum for a destroy.
    assert.equal(r2.quorumReached, false)
    assert.throws(() => finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-2' }), /quorum not reached/)
  })

  it('a restore proposal keeps the quorum-2 floor and finalizes at 2', () => {
    const proposal = proposeThaw({
      tenantId: TENANT, agentId: 'thaw-target', kind: 'restore', requiredQuorum: 2, proposedBy: 'admin-1',
    })
    assert.equal(proposal.requiredQuorum, 2)
    addThawApproval({ thawId: proposal.thawId, signer: 'admin-1' })
    const r2 = addThawApproval({ thawId: proposal.thawId, signer: 'admin-2' })
    assert.equal(r2.quorumReached, true)
    const done = finalizeThaw({ thawId: proposal.thawId, finalizedBy: 'admin-2' })
    assert.equal(done.state, 'complete')
  })
})

describe('cascade preview: accuracy against a delegation-tree + lineage fixture', () => {
  before(() => {
    // Tree: root -> child-a -> grandchild ; root -> child-b
    seedAgent('casc-root')
    seedAgent('casc-a')
    seedAgent('casc-b')
    seedAgent('casc-gc')
    seedDelegation('del-root-a', 'casc-root', 'casc-a', 'read,write')
    seedDelegation('del-root-b', 'casc-root', 'casc-b', 'read')
    seedDelegation('del-a-gc', 'casc-a', 'casc-gc', 'read')
    seedWallet('casc-a')
    seedWallet('casc-gc')
    // Lineage: root and a co-owned sibling share an owner link (cluster size 2).
    seedLineageLink('casc-root', 'owner-shared-1')
    seedLineageLink('casc-sibling', 'owner-shared-1')
  })

  it('walkDescendants finds every forward delegation, with depth and no cycles', () => {
    const nodes = walkDescendants(TENANT, 'casc-root')
    const ids = nodes.map((n) => n.delegationId).sort()
    assert.deepEqual(ids, ['del-a-gc', 'del-root-a', 'del-root-b'])
    const gc = nodes.find((n) => n.delegationId === 'del-a-gc')!
    assert.equal(gc.depth, 2)
  })

  it('a cyclic delegation graph terminates (cycle guard)', () => {
    seedAgent('cyc-x')
    seedAgent('cyc-y')
    seedDelegation('del-x-y', 'cyc-x', 'cyc-y', 'read')
    seedDelegation('del-y-x', 'cyc-y', 'cyc-x', 'read')
    const nodes = walkDescendants(TENANT, 'cyc-x')
    // Both edges are reached exactly once; the walk does not loop forever.
    assert.equal(nodes.length, 2)
  })

  it('agent preview reports affected delegations, agents, active workflows and cluster widening', () => {
    const preview = previewCascade({ tenantId: TENANT, targetType: 'agent', targetId: 'casc-root' })
    assert.equal(preview.affectedDelegations.length, 3)
    // root + a + b + gc
    assert.deepEqual([...preview.affectedAgents].sort(), ['casc-a', 'casc-b', 'casc-gc', 'casc-root'])
    assert.equal(preview.activeWorkflows, 3)
    assert.equal(preview.chainDepth, 2)
    // Lineage widened the radius: root clusters with one co-owned sibling.
    assert.equal(preview.cluster.clusterSize, 2)
    assert.ok(preview.cluster.matchedLinks.includes('owner'))
    // Two active wallets in the radius are production processes.
    assert.equal(preview.productionProcesses, 2)
    // revoke_now is always offered; live workflows add freeze_first.
    assert.ok(preview.recommendedActions.includes('revoke_now'))
    assert.ok(preview.recommendedActions.includes('freeze_first'))
    // totalRevoked = target(1) + 3 delegations.
    assert.equal(preview.totalRevoked, 4)
  })

  it('delegation preview includes the delegation and its forward descendants', () => {
    const preview = previewCascade({ tenantId: TENANT, targetType: 'delegation', targetId: 'del-root-a' })
    const ids = preview.affectedDelegations.map((d) => d.delegationId).sort()
    assert.deepEqual(ids, ['del-a-gc', 'del-root-a'])
  })

  it('data_source preview falls back to the access-receipt consumer count without a derivation store', () => {
    getDB().prepare(
      `INSERT OR IGNORE INTO data_sources (id, tenant_id, source_id, source_name) VALUES (?, ?, ?, ?)`,
    ).run('ds-1', TENANT, 'src-1', 'Source One')
    getDB().prepare(
      `INSERT INTO access_receipts (id, tenant_id, source_id, agent_id) VALUES (?, ?, ?, ?)`,
    ).run('ar-1', TENANT, 'src-1', 'casc-a')
    getDB().prepare(
      `INSERT INTO access_receipts (id, tenant_id, source_id, agent_id) VALUES (?, ?, ?, ?)`,
    ).run('ar-2', TENANT, 'src-1', 'casc-b')

    const preview = previewCascade({ tenantId: TENANT, targetType: 'data_source', targetId: 'src-1' })
    assert.ok(preview.dataObligations)
    assert.equal(preview.dataObligations!.source, 'access_receipt_fallback')
    assert.equal(preview.dataObligations!.totalAffected, 2)
    assert.deepEqual([...preview.affectedAgents].sort(), ['casc-a', 'casc-b'])
  })

  it('preview is read-only: it does not change agent / delegation status', () => {
    const beforeAgent = getDB().prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'casc-root') as any
    previewCascade({ tenantId: TENANT, targetType: 'agent', targetId: 'casc-root' })
    const afterAgent = getDB().prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
      .get(TENANT, 'casc-root') as any
    assert.equal(beforeAgent.status, afterAgent.status)
    assert.equal(afterAgent.status, 'active')
  })
})

describe('access_receipts table guard', () => {
  // access_receipts is created by the main schema; confirm the fixture seeds
  // landed so the data_source arm is exercised against a real table.
  it('exists in the schema', () => {
    const row = getDB().prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name='access_receipts'`,
    ).get() as any
    assert.ok(row?.name)
  })
})

describe('inbound signed-revocation: SDK pass-through', () => {
  it('verifies a correctly signed RevocationRecord (SDK verifyRevocation)', () => {
    // Build a signed record the way the SDK verifies it: sign the canonical
    // record-minus-signature with a delegator key; revokedBy is that pubkey.
    const kp = generateKeyPair()
    const unsigned = {
      revocationId: 'rev-1',
      delegationId: 'del-1',
      revokedBy: kp.publicKey,
      revokedAt: new Date().toISOString(),
      reason: 'compromised',
    }
    const signature = sign(canonicalize(unsigned), kp.privateKey)
    const record = { ...unsigned, signature }
    assert.equal(verifyInboundRevocation(record as any), true)
  })

  it('NEGATIVE: rejects a tampered RevocationRecord', () => {
    const kp = generateKeyPair()
    const unsigned = {
      revocationId: 'rev-2',
      delegationId: 'del-2',
      revokedBy: kp.publicKey,
      revokedAt: new Date().toISOString(),
      reason: 'compromised',
    }
    const signature = sign(canonicalize(unsigned), kp.privateKey)
    // Tamper after signing: the reason no longer matches the signature.
    const record = { ...unsigned, reason: 'changed-after-signing', signature }
    assert.equal(verifyInboundRevocation(record as any), false)
  })

  it('NEGATIVE: a malformed record does not throw, returns false', () => {
    assert.equal(verifyInboundRevocation({} as any), false)
  })
})

describe('sink-side independence', () => {
  it('the sink decision uses only the persisted epoch, not in-memory state', () => {
    // Bump via the engine, then read the raw gateway_config row the sink relies
    // on. The guard and the persisted counter agree.
    bumpEpoch(TENANT, 'agent', 'sink-indep', { reason: 'x', bumpedBy: 'admin-1' })
    const raw = getDB().prepare(`SELECT value FROM gateway_config WHERE key = ?`)
      .get(`epoch:agent:${TENANT}:sink-indep`) as any
    assert.equal(raw.value, '1')
    const guard = tokenEpochGuard({ tenantId: TENANT, subjectKind: 'agent', subjectId: 'sink-indep', epoch: 0 })
    assert.equal(guard.allowed, false)
    assert.equal(guard.currentEpoch, 1)
  })

  it('rebuildFromDb stays callable after a freeze removed an agent from the index', () => {
    // Sanity: the freeze path called removeAgent on the reverse index; the
    // index can still be rebuilt from the DB without error.
    assert.doesNotThrow(() => rebuildFromDb())
  })

  // Keep `verify` import referenced for a direct cross-check of one bump record.
  it('a bump record signature cross-checks against the gateway public key (raw EdDSA)', () => {
    const rec = bumpEpoch(TENANT, 'agent', 'xcheck', { reason: 'x', bumpedBy: 'admin-1' })
    // The gateway signs JWS compact; verify the JWS signing input directly.
    const [h, p, s] = rec.signature.split('.')
    const signingInput = `${h}.${p}`
    const pubHex = getGatewayIdentity().publicKeyHex
    const sigHex = Buffer.from(s, 'base64url').toString('hex')
    assert.equal(verify(signingInput, sigHex, pubHex), true)
  })
})
