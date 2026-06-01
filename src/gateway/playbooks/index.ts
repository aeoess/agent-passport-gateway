// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C2 layer (c): incident playbooks as customer pre-signed delegations.
 *
 * Settled-decision constraint C1, made concrete:
 *
 *  - A hosted incident response is authorized ONLY by a playbook the CUSTOMER
 *    pre-signed. The playbook is a scoped delegation: it names the exact trigger,
 *    the exact emergency responses it authorizes, and the scopes those responses
 *    may exercise. There is no free-form autonomous incident response outside a
 *    signed playbook; an uncovered high-risk action is blocked by the layer (a)
 *    guard, never improvised.
 *
 *  - The delegation is NARROWED, NON-WIDEABLE, short-TTL, and bound to a SPECIFIC
 *    delegation epoch. Narrowing and non-wideability come from APS monotonic
 *    narrowing (SDK subDelegate from the customer root, scope only ever shrinks).
 *    The epoch binding is the B2 surface: the playbook records the epoch it was
 *    signed at, and the kill is the sink denying any token stamped at a stale
 *    epoch (B2 tokenEpochGuard, offline).
 *
 *  - The CUSTOMER can kill a hosted playbook UNILATERALLY, and the kill is
 *    SINK-ENFORCED OFFLINE through the epoch check, with NO AEOESS action in the
 *    kill path. We model this exactly: the kill bumps the customer-subject epoch
 *    (B2 bumpEpoch, authenticated bumpedBy = the customer), and from that moment
 *    every token stamped at the playbook's signed epoch is stale at the sink. The
 *    gateway is not consulted at enforcement time; the sink decides offline.
 *
 *  - Root rotation cascade-revokes stale playbooks via the B2 GEMS engine: a root
 *    epoch bump makes every playbook signed under the prior epoch stale at the
 *    sink. We surface that here through the same epoch check.
 *
 *  - Every fired playbook carries MANDATORY POST-REVIEW. A fire is recorded with
 *    review_state = 'pending_review'; it is never auto-closed. Closing requires
 *    an explicit human review action.
 *
 * Thin-gateway note: the gateway stores the registry and checks-before; it holds
 * NO kill switch of its own. The customer holds the kill (epoch bump), the sink
 * holds enforcement (offline epoch check). The gateway only records and coordinates.
 */

import { randomUUID, createHash } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { getGatewayIdentity } from '../identity.js'
import { getEventBus } from '../events.js'

// ── B2 revocation engine (NOT merged into this base). Read-only public surface
//    at gw-b2-revocation/src/gateway/revocation/index.ts. We depend
//    on its PUBLIC interface only, and stub the actual import behind a typed seam.
//    When B2 merges, replace the local shim with the real import.
//
// TODO(G-B2 / gw-b2-revocation): import { getCurrentEpoch, bumpEpoch, tokenEpochGuard,
//   type EpochSubjectKind } from '../revocation/index.js' (or '../revocation/epochs.js').
//   Until merged, the typed seam below mirrors that surface against gateway_config,
//   which is the same source-of-truth table B2 epochs.ts reads/writes. The shim is
//   intentionally epoch-compatible: it reads/writes the identical gateway_config keys
//   B2 uses, so behavior is continuous when the real module lands.
import {
  getCurrentEpochSeam,
  bumpEpochSeam,
  tokenEpochGuardSeam,
  type EpochSubjectKindSeam,
} from './b2-seam.js'

// ── SDK Wave 2 (pin ^2.6.0-alpha.3; W2 surface NOT installed) ──
// The pre-signed scoped epoch-bound playbook delegation is built on the SDK
// createDelegation / subDelegate / verifyDelegation primitives. The ephemeral
// token signature + epoch binding is SDK Wave 2.
//
// TODO(W2-B3): SDK ephemeral-token signature + epoch binding. Today the playbook
//   records the customer-signed delegation id and the signed epoch; the
//   ephemeral token minted for a fired response is stamped with that epoch and
//   verified at the sink. When W2-B3 lands, the ephemeral-token sig/expiry is
//   layered in front of the exact-epoch check (matches B2 tokenEpochGuard marker).

export type PlaybookReviewState = 'pending_review' | 'reviewed_ok' | 'reviewed_action_taken'
export type PlaybookSubjectKind = EpochSubjectKindSeam // 'agent' | 'delegation'

/**
 * A customer pre-signed incident playbook. The scoped, epoch-bound delegation is
 * the unit of authority; this row is the gateway's registry record of it.
 */
export interface SignedPlaybook {
  playbookId: string
  tenantId: string
  /** Human label, e.g. 'credential-leak-containment'. */
  name: string
  /** The exact trigger this playbook responds to, e.g. 'integration_health:degraded'. */
  trigger: string
  /** The exact scoped emergency responses authorized. Each names a scope it may exercise. */
  authorizedResponses: PlaybookResponse[]
  /** Customer-signed delegation id (SDK). Authority flows from here, not from the gateway. */
  delegationId: string
  /** Subject the epoch binding keys off (the customer root delegation/agent). */
  subjectKind: PlaybookSubjectKind
  subjectId: string
  /** The delegation epoch the playbook was signed at. The kill is "current epoch > this". */
  signedEpoch: number
  /** TTL: the playbook is inert after this instant even without an epoch bump. */
  expiresAt: string
  /** Gateway record signature (EdDSA JWS) over the registry row, for audit. */
  recordSignature: string
  /** Lifecycle: 'live' | 'killed' | 'expired'. Derived; killed/expired are sink-enforced too. */
  status: 'live' | 'killed' | 'expired'
  createdAt: string
}

export interface PlaybookResponse {
  /** Stable id of the response within the playbook, referenced when firing. */
  responseId: string
  /** What the response does, e.g. 'route_alert', 'open_ticket', 'recommend_freeze'. */
  action: string
  /** The single scope this response may exercise. Non-wideable: only ever narrows. */
  scope: string
}

export interface PlaybookFireRecord {
  fireId: string
  tenantId: string
  playbookId: string
  responseId: string
  /** Trigger payload digest, for audit; never the raw payload. */
  triggerDigest: string
  /** The epoch the fired response's ephemeral token was stamped at (== signedEpoch). */
  stampedEpoch: number
  /** Whether the sink would currently honor this fire (epoch still live). */
  sinkAllowedAtFire: boolean
  reviewState: PlaybookReviewState
  firedAt: string
  reviewedAt: string | null
  reviewedBy: string | null
}

/** Initialize playbook registry tables. Idempotent; call once at startup. */
export function initPlaybookTables(): void {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS gc2_playbooks (
      playbook_id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      trigger TEXT NOT NULL,
      authorized_responses TEXT NOT NULL,
      delegation_id TEXT NOT NULL,
      subject_kind TEXT NOT NULL,
      subject_id TEXT NOT NULL,
      signed_epoch INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      record_signature TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'live',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_gc2_playbooks_tenant ON gc2_playbooks(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_gc2_playbooks_trigger ON gc2_playbooks(tenant_id, trigger);

    CREATE TABLE IF NOT EXISTS gc2_playbook_fires (
      fire_id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      playbook_id TEXT NOT NULL,
      response_id TEXT NOT NULL,
      trigger_digest TEXT NOT NULL,
      stamped_epoch INTEGER NOT NULL,
      sink_allowed_at_fire INTEGER NOT NULL,
      review_state TEXT NOT NULL DEFAULT 'pending_review',
      fired_at TEXT NOT NULL DEFAULT (datetime('now')),
      reviewed_at TEXT,
      reviewed_by TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_gc2_fires_tenant ON gc2_playbook_fires(tenant_id, review_state);
  `)
}

/**
 * Register a customer pre-signed playbook. The caller has already created the
 * scoped delegation via the SDK (createDelegation/subDelegate from the customer
 * root); this records it and binds it to the CURRENT subject epoch.
 *
 * We never widen: authorizedResponses are taken as-is, and the layer (a) guard
 * plus the sink epoch check are what actually constrain a fire. Registration is
 * a record, not an authority grant - authority is the customer's signed delegation.
 */
export function registerPlaybook(opts: {
  tenantId: string
  name: string
  trigger: string
  authorizedResponses: PlaybookResponse[]
  delegationId: string
  subjectKind: PlaybookSubjectKind
  subjectId: string
  /** TTL in hours; the playbook is inert after this even with no epoch bump. */
  ttlHours: number
}): SignedPlaybook {
  const db = getDB()
  const playbookId = randomUUID()
  const createdAt = new Date().toISOString()
  const expiresAt = new Date(Date.now() + opts.ttlHours * 3600_000).toISOString()

  // Bind to the CURRENT epoch of the customer subject. The kill is a future
  // epoch bump making this signed epoch stale at the sink.
  const signedEpoch = getCurrentEpochSeam(opts.tenantId, opts.subjectKind, opts.subjectId)

  const unsigned = {
    playbookId,
    tenantId: opts.tenantId,
    name: opts.name,
    trigger: opts.trigger,
    authorizedResponses: opts.authorizedResponses,
    delegationId: opts.delegationId,
    subjectKind: opts.subjectKind,
    subjectId: opts.subjectId,
    signedEpoch,
    expiresAt,
    createdAt,
  }
  // Gateway record signature is for AUDIT of the registry row only. It is NOT the
  // authority: authority is the customer-signed delegation (opts.delegationId).
  const recordSignature = getGatewayIdentity().sign(unsigned)

  db.prepare(`
    INSERT INTO gc2_playbooks
      (playbook_id, tenant_id, name, trigger, authorized_responses, delegation_id,
       subject_kind, subject_id, signed_epoch, expires_at, record_signature, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'live', ?)
  `).run(
    playbookId, opts.tenantId, opts.name, opts.trigger,
    JSON.stringify(opts.authorizedResponses), opts.delegationId,
    opts.subjectKind, opts.subjectId, signedEpoch, expiresAt, recordSignature, createdAt,
  )

  return { ...unsigned, recordSignature, status: 'live' }
}

function rowToPlaybook(row: any): SignedPlaybook {
  return {
    playbookId: row.playbook_id,
    tenantId: row.tenant_id,
    name: row.name,
    trigger: row.trigger,
    authorizedResponses: JSON.parse(row.authorized_responses),
    delegationId: row.delegation_id,
    subjectKind: row.subject_kind,
    subjectId: row.subject_id,
    signedEpoch: row.signed_epoch,
    expiresAt: row.expires_at,
    recordSignature: row.record_signature,
    status: row.status,
    createdAt: row.created_at,
  }
}

/**
 * Is a playbook LIVE at the sink right now? This is the offline-style check the
 * gateway uses for "checks-before" coordination; the AUTHORITATIVE version is the
 * sink running B2 tokenEpochGuard against the response's ephemeral token. The two
 * agree by construction: both compare the stamped epoch to the current epoch.
 *
 * Live iff: not past TTL AND the signed epoch is still current (no kill, no root
 * rotation bumped the subject past it). Pure read; no mutation.
 */
export function isPlaybookLive(pb: SignedPlaybook, now: number = Date.now()): {
  live: boolean
  reason: string
} {
  if (Date.parse(pb.expiresAt) <= now) {
    return { live: false, reason: 'playbook expired (past TTL)' }
  }
  // Sink-style epoch check via the B2 seam. A stale signed epoch means the
  // customer killed it (epoch bump) or a root rotation cascaded past it.
  const guard = tokenEpochGuardSeam({
    tenantId: pb.tenantId,
    subjectKind: pb.subjectKind,
    subjectId: pb.subjectId,
    epoch: pb.signedEpoch,
  })
  if (!guard.allowed) {
    return { live: false, reason: `sink would deny: ${guard.reason}` }
  }
  return { live: true, reason: 'live' }
}

/**
 * Find a LIVE playbook that authorizes the given (trigger, scope). Returns the
 * playbook and the matching response, or null. This is what layer (a) uses to
 * resolve `coveredBySignedPlaybook` for a high-risk scope, and what fireResponse
 * uses to authorize a fire. Bounded scan over the tenant's live playbooks.
 */
export function findAuthorizingPlaybook(
  tenantId: string,
  trigger: string,
  scope: string,
  now: number = Date.now(),
): { playbook: SignedPlaybook; response: PlaybookResponse } | null {
  const db = getDB()
  const rows = db.prepare(
    `SELECT * FROM gc2_playbooks WHERE tenant_id = ? AND trigger = ? AND status = 'live'`,
  ).all(tenantId, trigger) as any[]
  for (const row of rows) {
    const pb = rowToPlaybook(row)
    if (!isPlaybookLive(pb, now).live) continue
    for (const resp of pb.authorizedResponses) {
      if (resp.scope === scope) return { playbook: pb, response: resp }
    }
  }
  return null
}

/**
 * Does ANY live playbook cover this scope for this tenant, under any trigger?
 * Used by the pre-flight guard to set `coveredBySignedPlaybook`. A high-risk
 * scope with no covering live playbook is blocked by the guard. Pure read.
 */
export function scopeCoveredByLivePlaybook(
  tenantId: string,
  scope: string,
  now: number = Date.now(),
): boolean {
  const db = getDB()
  const rows = db.prepare(
    `SELECT * FROM gc2_playbooks WHERE tenant_id = ? AND status = 'live'`,
  ).all(tenantId) as any[]
  for (const row of rows) {
    const pb = rowToPlaybook(row)
    if (!isPlaybookLive(pb, now).live) continue
    for (const resp of pb.authorizedResponses) {
      if (resp.scope === scope) return true
    }
  }
  return false
}

/**
 * Fire a pre-authorized response from a live playbook. This is the ONLY way a
 * hosted emergency response runs, and it fires ONLY a response the customer
 * pre-signed. A fire:
 *
 *  1. requires a LIVE playbook that authorizes (trigger, response). If none, it
 *     refuses - there is no free-form incident response.
 *  2. stamps the response's ephemeral token at the playbook's signed epoch
 *     (TODO(W2-B3) for the SDK ephemeral-token signature; the epoch is real now).
 *  3. records the fire with review_state = 'pending_review' - MANDATORY POST-
 *     REVIEW. The fire is never auto-closed.
 *  4. emits a 'playbook_triggered' event.
 *
 * It does NOT, by itself, perform a high-risk side effect. A response whose
 * action is high-risk (e.g. 'recommend_freeze') produces a RECOMMENDATION routed
 * through layer (b); it never silently revokes or freezes. The customer kill and
 * the sink epoch check remain the only authority that stops in-flight tokens.
 */
export function fireResponse(opts: {
  tenantId: string
  trigger: string
  responseScope: string
  triggerPayload: unknown
  now?: number
}): { fired: boolean; reason: string; record?: PlaybookFireRecord } {
  const now = opts.now ?? Date.now()
  const match = findAuthorizingPlaybook(opts.tenantId, opts.trigger, opts.responseScope, now)
  if (!match) {
    return {
      fired: false,
      reason:
        'no live signed playbook authorizes this (trigger, scope). ' +
        'No free-form incident response exists outside a signed playbook.',
    }
  }
  const { playbook, response } = match

  // Stamp the ephemeral token at the playbook's signed epoch and confirm the
  // sink would honor it RIGHT NOW (it will, since findAuthorizingPlaybook already
  // filtered to live; we re-check to record the sink verdict in the fire row).
  const stampedEpoch = playbook.signedEpoch
  const sinkGuard = tokenEpochGuardSeam({
    tenantId: playbook.tenantId,
    subjectKind: playbook.subjectKind,
    subjectId: playbook.subjectId,
    epoch: stampedEpoch,
  })

  const db = getDB()
  const fireId = randomUUID()
  const firedAt = new Date(now).toISOString()
  const triggerDigest = createHash('sha256')
    .update(JSON.stringify(opts.triggerPayload ?? null))
    .digest('hex')

  const record: PlaybookFireRecord = {
    fireId,
    tenantId: playbook.tenantId,
    playbookId: playbook.playbookId,
    responseId: response.responseId,
    triggerDigest,
    stampedEpoch,
    sinkAllowedAtFire: sinkGuard.allowed,
    reviewState: 'pending_review',
    firedAt,
    reviewedAt: null,
    reviewedBy: null,
  }

  db.prepare(`
    INSERT INTO gc2_playbook_fires
      (fire_id, tenant_id, playbook_id, response_id, trigger_digest, stamped_epoch,
       sink_allowed_at_fire, review_state, fired_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_review', ?)
  `).run(
    fireId, playbook.tenantId, playbook.playbookId, response.responseId,
    triggerDigest, stampedEpoch, sinkGuard.allowed ? 1 : 0, firedAt,
  )

  try {
    getEventBus().emit(playbook.tenantId, {
      type: 'playbook_triggered',
      data: {
        playbook_id: playbook.playbookId,
        response_id: response.responseId,
        action: response.action,
        scope: response.scope,
        stamped_epoch: stampedEpoch,
        sink_allowed: sinkGuard.allowed,
        review_state: 'pending_review',
      },
    })
  } catch { /* event emit must not break a fire */ }

  return { fired: true, reason: 'fired pre-authorized response (post-review pending)', record }
}

/**
 * Customer kill: bump the customer-subject epoch so every playbook signed at the
 * prior epoch is stale at the SINK. This is the C1 unilateral kill. Crucially:
 *
 *  - the kill is the CUSTOMER's action (bumpedBy = the authenticated customer),
 *  - enforcement is OFFLINE at the sink (epoch check), NOT a gateway call,
 *  - there is NO AEOESS action in the kill path: AEOESS does not approve, gate,
 *    or relay. The gateway merely records that the registry rows are now stale.
 *
 * After this returns, isPlaybookLive() and the sink agree the killed playbooks
 * are dead, because both read the bumped epoch.
 */
export function customerKillPlaybooks(opts: {
  tenantId: string
  subjectKind: PlaybookSubjectKind
  subjectId: string
  /** The AUTHENTICATED customer principal performing the kill. Required. */
  killedBy: string
  reason?: string
}): { newEpoch: number; killedPlaybookIds: string[] } {
  if (!opts.killedBy) {
    throw new Error('customerKillPlaybooks requires an authenticated killedBy (the customer)')
  }
  // The epoch bump IS the kill. B2 owns the epoch logic; we call the seam with
  // the customer as the actor. No gateway-side enforcement decision is taken.
  const bump = bumpEpochSeam(opts.tenantId, opts.subjectKind, opts.subjectId, {
    reason: `customer_kill: ${opts.reason ?? 'unilateral playbook kill'}`,
    bumpedBy: opts.killedBy,
  })

  // Mark the now-stale registry rows. This is bookkeeping only; the SINK already
  // denies them via the epoch check. We do NOT touch the customer's delegation.
  const db = getDB()
  const stale = db.prepare(
    `SELECT playbook_id FROM gc2_playbooks
     WHERE tenant_id = ? AND subject_kind = ? AND subject_id = ?
       AND status = 'live' AND signed_epoch < ?`,
  ).all(opts.tenantId, opts.subjectKind, opts.subjectId, bump.newEpoch) as any[]
  const killedPlaybookIds = stale.map(r => r.playbook_id)
  if (killedPlaybookIds.length > 0) {
    const placeholders = killedPlaybookIds.map(() => '?').join(',')
    db.prepare(
      `UPDATE gc2_playbooks SET status = 'killed' WHERE playbook_id IN (${placeholders})`,
    ).run(...killedPlaybookIds)
  }

  return { newEpoch: bump.newEpoch, killedPlaybookIds }
}

/**
 * Record the MANDATORY post-review of a fired playbook response. A fire is never
 * auto-closed; a human must review it. `actionTaken` distinguishes a review that
 * found the response correct from one that required follow-up. Returns false if
 * the fire is unknown or already reviewed.
 */
export function reviewFire(opts: {
  tenantId: string
  fireId: string
  reviewedBy: string
  actionTaken: boolean
  notes?: string
}): { reviewed: boolean; reason: string } {
  if (!opts.reviewedBy) return { reviewed: false, reason: 'reviewedBy required' }
  const db = getDB()
  const row = db.prepare(
    `SELECT review_state FROM gc2_playbook_fires WHERE tenant_id = ? AND fire_id = ?`,
  ).get(opts.tenantId, opts.fireId) as any
  if (!row) return { reviewed: false, reason: 'fire not found' }
  if (row.review_state !== 'pending_review') {
    return { reviewed: false, reason: `already ${row.review_state}` }
  }
  const newState: PlaybookReviewState = opts.actionTaken ? 'reviewed_action_taken' : 'reviewed_ok'
  db.prepare(
    `UPDATE gc2_playbook_fires SET review_state = ?, reviewed_at = ?, reviewed_by = ?
     WHERE tenant_id = ? AND fire_id = ?`,
  ).run(newState, new Date().toISOString(), opts.reviewedBy, opts.tenantId, opts.fireId)
  return { reviewed: true, reason: newState }
}

/** Fires still awaiting the mandatory post-review. Surfaced for the dashboard. */
export function pendingReviews(tenantId: string): PlaybookFireRecord[] {
  const db = getDB()
  const rows = db.prepare(
    `SELECT * FROM gc2_playbook_fires WHERE tenant_id = ? AND review_state = 'pending_review'
     ORDER BY fired_at ASC`,
  ).all(tenantId) as any[]
  return rows.map(r => ({
    fireId: r.fire_id,
    tenantId: r.tenant_id,
    playbookId: r.playbook_id,
    responseId: r.response_id,
    triggerDigest: r.trigger_digest,
    stampedEpoch: r.stamped_epoch,
    sinkAllowedAtFire: !!r.sink_allowed_at_fire,
    reviewState: r.review_state,
    firedAt: r.fired_at,
    reviewedAt: r.reviewed_at,
    reviewedBy: r.reviewed_by,
  }))
}

export function getPlaybook(tenantId: string, playbookId: string): SignedPlaybook | null {
  const db = getDB()
  const row = db.prepare(
    `SELECT * FROM gc2_playbooks WHERE tenant_id = ? AND playbook_id = ?`,
  ).get(tenantId, playbookId) as any
  return row ? rowToPlaybook(row) : null
}
