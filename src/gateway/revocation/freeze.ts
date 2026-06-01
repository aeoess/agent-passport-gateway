// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Asymmetric panic-freeze and multi-signature thaw.
 *
 * Stopping is cheap and unilateral; restoring is expensive and quorate.
 *
 *  - Panic-freeze: any single authenticated admin (or a pre-authorized
 *    automation actor) can immediately freeze an agent to a safe state
 *    (read-only or zero-authority). One signer, one call, takes effect at once
 *    by bumping the agent epoch (every live token at the prior epoch is then
 *    stale at the sink) and freezing the agent record + wallet.
 *
 *  - Multi-sig thaw / destroy: restoring authority or permanently destroying a
 *    root identity requires a quorum of distinct admin signatures. A single
 *    signer cannot thaw. The thaw is a state machine modeled on the existing
 *    key_rotations lifecycle (proposed -> collecting -> complete).
 *
 * Thin-gateway note: the freeze acts by bumping the epoch (the source of truth
 * the sink reads) and flipping the agent/wallet status. The gateway is not the
 * place the freeze is "enforced"; the sink denies stale-epoch tokens. The
 * gateway records freeze state and coordinates the quorum.
 *
 * In-flight actions: a freeze does not retroactively undo committed effects. It
 * bumps the epoch so that any in-flight token minted before the freeze is
 * denied at the sink on its next use, and it freezes the wallet so no new value
 * leaves. Effects already settled are out of scope for freeze; they are
 * cascade-preview and obligation concerns.
 */

import { randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { getGatewayIdentity } from '../identity.js'
import { removeAgent } from '../wallet-reverse-index.js'
import { bumpEpoch } from './epochs.js'
import { emitRevocationEvent } from './sinks.js'

export type FreezeMode = 'read_only' | 'zero_authority'
export type ThawState = 'proposed' | 'collecting' | 'complete' | 'rejected'
export type ThawKind = 'restore' | 'destroy'

export interface FreezeRecord {
  type: 'panic_freeze'
  freezeId: string
  tenantId: string
  agentId: string
  mode: FreezeMode
  frozenBy: string
  reason: string
  epochAfterFreeze: number
  frozenAt: string
  signature: string
}

export interface ThawProposal {
  thawId: string
  tenantId: string
  agentId: string
  kind: ThawKind
  requiredQuorum: number
  proposedBy: string
  reason: string
  state: ThawState
  approvals: ThawApproval[]
  createdAt: string
  completedAt?: string
}

export interface ThawApproval {
  signer: string
  approvedAt: string
  signature: string
}

/**
 * Initialize freeze / thaw tables. Idempotent. Mirrors the key_rotations
 * lifecycle shape (a state column with a small fixed vocabulary).
 */
export function initFreezeTables(): void {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS agent_freezes (
      freeze_id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      mode TEXT NOT NULL,
      frozen_by TEXT NOT NULL,
      reason TEXT NOT NULL DEFAULT '',
      epoch_after_freeze INTEGER NOT NULL,
      record_signature TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      frozen_at TEXT NOT NULL DEFAULT (datetime('now')),
      thawed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_agent_freezes_tenant
      ON agent_freezes(tenant_id, agent_id, active);

    CREATE TABLE IF NOT EXISTS agent_thaws (
      thaw_id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      required_quorum INTEGER NOT NULL,
      proposed_by TEXT NOT NULL,
      reason TEXT NOT NULL DEFAULT '',
      state TEXT NOT NULL DEFAULT 'proposed',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS agent_thaw_approvals (
      id TEXT PRIMARY KEY,
      thaw_id TEXT NOT NULL,
      signer TEXT NOT NULL,
      signature TEXT NOT NULL,
      approved_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(thaw_id, signer)
    );
  `)
}

/**
 * Panic-freeze an agent. Single authenticated actor, immediate. Returns a
 * signed freeze record. Idempotent-ish: a second freeze re-bumps the epoch
 * (still monotonic) and records a new freeze row, which is the safe direction.
 */
export function panicFreeze(opts: {
  tenantId: string
  agentId: string
  mode: FreezeMode
  frozenBy: string
  reason?: string
}): FreezeRecord {
  const { tenantId, agentId, mode } = opts
  const frozenBy = opts.frozenBy
  const reason = opts.reason ?? 'panic freeze'
  if (!frozenBy) throw new Error('panicFreeze requires an authenticated frozenBy actor')

  const db = getDB()

  // Bump the agent epoch FIRST: this is the propagation primitive. Every token
  // minted at the prior epoch is now stale at the sink.
  const bump = bumpEpoch(tenantId, 'agent', agentId, { reason: `panic_freeze: ${reason}`, bumpedBy: frozenBy })

  // Flip agent status. zero_authority -> revoked; read_only -> frozen.
  const newStatus = mode === 'zero_authority' ? 'revoked' : 'frozen'
  db.prepare(`UPDATE agents SET status = ? WHERE tenant_id = ? AND agent_id = ?`)
    .run(newStatus, tenantId, agentId)

  // Freeze the wallet so no new value leaves, and drop the agent from the
  // wallet reverse index (route through the shared helper rather than touching
  // the index map directly).
  db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`)
    .run(tenantId, agentId)
  removeAgent(tenantId, agentId)

  const freezeId = randomUUID()
  const frozenAt = new Date().toISOString()
  const unsigned = {
    type: 'panic_freeze' as const,
    freezeId,
    tenantId,
    agentId,
    mode,
    frozenBy,
    reason,
    epochAfterFreeze: bump.newEpoch,
    frozenAt,
  }
  const signature = getGatewayIdentity().sign(unsigned)

  db.prepare(
    `INSERT INTO agent_freezes
       (freeze_id, tenant_id, agent_id, mode, frozen_by, reason, epoch_after_freeze, record_signature, active, frozen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
  ).run(freezeId, tenantId, agentId, mode, frozenBy, reason, bump.newEpoch, signature, frozenAt)

  emitRevocationEvent(
    tenantId,
    'panic_freeze',
    { freezeId, agentId, mode, frozenBy, reason, epochAfterFreeze: bump.newEpoch },
    agentId,
  )

  return { ...unsigned, signature }
}

/** Is the agent currently under an active freeze? */
export function isFrozen(tenantId: string, agentId: string): boolean {
  const db = getDB()
  const row = db.prepare(
    `SELECT 1 FROM agent_freezes WHERE tenant_id = ? AND agent_id = ? AND active = 1 LIMIT 1`,
  ).get(tenantId, agentId)
  return !!row
}

/**
 * Propose a thaw (restore) or destroy. Records the proposal in 'proposed'
 * state with a required quorum. The proposer's own approval is NOT auto-added;
 * approvals (including the proposer's, if they choose) are collected via
 * addThawApproval. A quorum of distinct signers is required to complete.
 */
export function proposeThaw(opts: {
  tenantId: string
  agentId: string
  kind: ThawKind
  requiredQuorum: number
  proposedBy: string
  reason?: string
}): ThawProposal {
  const { tenantId, agentId, kind, proposedBy } = opts
  // The quorum floor is asymmetric by kind. A 'destroy' (zero_authority,
  // terminal) is irreversible, so it is forced to at least 3 distinct signers;
  // a 'restore' is recoverable and is forced to at least 2. A caller may raise
  // the quorum above the floor but never below it.
  const floor = kind === 'destroy' ? 3 : 2
  const requiredQuorum = Math.max(floor, Math.floor(opts.requiredQuorum))
  const reason = opts.reason ?? `${kind} proposal`
  if (!proposedBy) throw new Error('proposeThaw requires an authenticated proposedBy actor')

  const db = getDB()
  const thawId = randomUUID()
  db.prepare(
    `INSERT INTO agent_thaws (thaw_id, tenant_id, agent_id, kind, required_quorum, proposed_by, reason, state)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'proposed')`,
  ).run(thawId, tenantId, agentId, kind, requiredQuorum, proposedBy, reason)

  return getThaw(thawId)!
}

/**
 * Add one admin's approval signature to a thaw proposal. Distinct signers only
 * (a UNIQUE(thaw_id, signer) constraint rejects a duplicate signer, so one
 * admin cannot fill a quorum by signing twice). Does NOT complete the thaw; the
 * caller completes via finalizeThaw once quorum is reached.
 */
export function addThawApproval(opts: {
  thawId: string
  signer: string
}): { thawId: string; approvals: number; requiredQuorum: number; quorumReached: boolean } {
  const { thawId, signer } = opts
  if (!signer) throw new Error('addThawApproval requires an authenticated signer')

  const db = getDB()
  const thaw = getThaw(thawId)
  if (!thaw) throw new Error(`thaw ${thawId} not found`)
  if (thaw.state === 'complete' || thaw.state === 'rejected') {
    throw new Error(`thaw ${thawId} already ${thaw.state}`)
  }

  const approvedAt = new Date().toISOString()
  const signature = getGatewayIdentity().sign({
    type: 'thaw_approval',
    thawId,
    tenantId: thaw.tenantId,
    agentId: thaw.agentId,
    signer,
    approvedAt,
  })

  // Distinct signer enforcement: UNIQUE(thaw_id, signer). A repeat signer is a
  // no-op, not a second vote toward quorum.
  db.prepare(
    `INSERT OR IGNORE INTO agent_thaw_approvals (id, thaw_id, signer, signature, approved_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(randomUUID(), thawId, signer, signature, approvedAt)

  // Move proposed -> collecting on first approval.
  db.prepare(`UPDATE agent_thaws SET state = 'collecting' WHERE thaw_id = ? AND state = 'proposed'`)
    .run(thawId)

  const approvals = countApprovals(thawId)
  return {
    thawId,
    approvals,
    requiredQuorum: thaw.requiredQuorum,
    quorumReached: approvals >= thaw.requiredQuorum,
  }
}

/**
 * Finalize a thaw once a distinct-signer quorum is reached. A single signer can
 * never reach this: requiredQuorum is forced >= 2 for a 'restore' and >= 3 for
 * a 'destroy' (terminal, irreversible), and approvals are distinct.
 *
 *  - kind 'restore': bumps the agent epoch (new live epoch for fresh tokens),
 *    sets the agent status back to active, reactivates the wallet, marks the
 *    active freeze rows thawed.
 *  - kind 'destroy': bumps the epoch and leaves the agent revoked permanently;
 *    the active freeze rows are marked thawed (resolved) but status stays
 *    revoked. Destruction is terminal.
 *
 * Throws if quorum is not yet reached, so a single-signer call cannot thaw.
 */
export function finalizeThaw(opts: {
  thawId: string
  finalizedBy: string
}): ThawProposal {
  const { thawId, finalizedBy } = opts
  const db = getDB()
  const thaw = getThaw(thawId)
  if (!thaw) throw new Error(`thaw ${thawId} not found`)
  if (thaw.state === 'complete') return thaw
  if (thaw.state === 'rejected') throw new Error(`thaw ${thawId} was rejected`)

  const approvals = countApprovals(thawId)
  if (approvals < thaw.requiredQuorum) {
    throw new Error(
      `thaw quorum not reached: ${approvals}/${thaw.requiredQuorum} distinct approvals`,
    )
  }

  const completedAt = new Date().toISOString()
  const epochEvent = bumpEpoch(thaw.tenantId, 'agent', thaw.agentId, {
    reason: `multisig_thaw:${thaw.kind}`,
    bumpedBy: finalizedBy,
  })

  if (thaw.kind === 'restore') {
    db.prepare(`UPDATE agents SET status = 'active' WHERE tenant_id = ? AND agent_id = ?`)
      .run(thaw.tenantId, thaw.agentId)
    db.prepare(`UPDATE agent_wallets SET status = 'active' WHERE tenant_id = ? AND agent_id = ? AND status = 'frozen'`)
      .run(thaw.tenantId, thaw.agentId)
  }
  // 'destroy' leaves the agent revoked; the proposal completing is the record.

  db.prepare(`UPDATE agent_freezes SET active = 0, thawed_at = ? WHERE tenant_id = ? AND agent_id = ? AND active = 1`)
    .run(completedAt, thaw.tenantId, thaw.agentId)
  db.prepare(`UPDATE agent_thaws SET state = 'complete', completed_at = ? WHERE thaw_id = ?`)
    .run(completedAt, thawId)

  emitRevocationEvent(
    thaw.tenantId,
    'multisig_thaw',
    {
      thawId,
      agentId: thaw.agentId,
      kind: thaw.kind,
      approvals,
      requiredQuorum: thaw.requiredQuorum,
      epochAfterThaw: epochEvent.newEpoch,
    },
    thaw.agentId,
  )

  return getThaw(thawId)!
}

/** Read a thaw proposal and its approvals. */
export function getThaw(thawId: string): ThawProposal | null {
  const db = getDB()
  const row = db.prepare(`SELECT * FROM agent_thaws WHERE thaw_id = ?`).get(thawId) as any
  if (!row) return null
  const approvals = (db.prepare(
    `SELECT signer, signature, approved_at FROM agent_thaw_approvals WHERE thaw_id = ? ORDER BY approved_at ASC`,
  ).all(thawId) as any[]).map((a) => ({
    signer: a.signer,
    signature: a.signature,
    approvedAt: a.approved_at,
  }))
  return {
    thawId: row.thaw_id,
    tenantId: row.tenant_id,
    agentId: row.agent_id,
    kind: row.kind,
    requiredQuorum: row.required_quorum,
    proposedBy: row.proposed_by,
    reason: row.reason,
    state: row.state,
    approvals,
    createdAt: row.created_at,
    completedAt: row.completed_at ?? undefined,
  }
}

function countApprovals(thawId: string): number {
  const db = getDB()
  const row = db.prepare(
    `SELECT COUNT(*) AS c FROM agent_thaw_approvals WHERE thaw_id = ?`,
  ).get(thawId) as { c: number }
  return row.c
}
