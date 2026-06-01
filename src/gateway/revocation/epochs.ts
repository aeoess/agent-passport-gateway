// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Revocation epochs: the source of truth for propagation.
 *
 * Every agent and delegation carries a monotonic epoch counter. Tokens and
 * receipts minted under that subject carry the epoch they were issued at. The
 * sink denies a token whose epoch is older than the subject's current epoch.
 *
 * This is exact and has zero false positives: a token is stale iff its epoch is
 * strictly below the current epoch. Any bloom/filter layer is an edge
 * optimization only, never the source of truth.
 *
 * Thin-gateway note: the epoch is the small fact the gateway publishes; the
 * sink does the denying. The gateway does not hold the enforcement decision.
 *
 * State lives in the existing gateway_config k/v table (lineage.ts owns the
 * table; we only read/write keys). Bump records are signed with the gateway
 * identity (EdDSA JWS) so an auditor can verify the monotonic history.
 */

import { getDB } from '../../db/schema.js'
import { getGatewayIdentity } from '../identity.js'
import { emitRevocationEvent } from './sinks.js'

// gateway_config key namespace for epoch counters.
const AGENT_EPOCH_PREFIX = 'epoch:agent:'
const DELEGATION_EPOCH_PREFIX = 'epoch:delegation:'

export type EpochSubjectKind = 'agent' | 'delegation'

export interface EpochBumpRecord {
  type: 'epoch_bump'
  tenantId: string
  subjectKind: EpochSubjectKind
  subjectId: string
  previousEpoch: number
  newEpoch: number
  reason: string
  bumpedBy: string
  bumpedAt: string
  /** Gateway EdDSA JWS over the record (verifiable via JWKS, kid: gateway-v1). */
  signature: string
}

function configKey(tenantId: string, kind: EpochSubjectKind, subjectId: string): string {
  const prefix = kind === 'agent' ? AGENT_EPOCH_PREFIX : DELEGATION_EPOCH_PREFIX
  return `${prefix}${tenantId}:${subjectId}`
}

/**
 * Read the current epoch for a subject. Absent counter means epoch 0 (the
 * subject has never been bumped); a token at epoch 0 is therefore valid until
 * the first bump. Monotonic and non-negative.
 */
export function getCurrentEpoch(tenantId: string, kind: EpochSubjectKind, subjectId: string): number {
  const db = getDB()
  const row = db.prepare(`SELECT value FROM gateway_config WHERE key = ?`)
    .get(configKey(tenantId, kind, subjectId)) as { value?: string } | undefined
  if (!row?.value) return 0
  const n = parseInt(row.value, 10)
  return Number.isFinite(n) && n >= 0 ? n : 0
}

/**
 * Bump a subject's epoch by one, persist it, sign the bump record, and emit to
 * both sinks. This is the primary revocation-propagation action: after a bump,
 * every token minted at the prior epoch is stale at the sink.
 *
 * Monotonic: the stored value only ever increases. Concurrent bumps are
 * serialized by the surrounding transaction the caller is expected to hold; the
 * read-then-write here is wrapped in an IMMEDIATE transaction for safety.
 */
export function bumpEpoch(
  tenantId: string,
  kind: EpochSubjectKind,
  subjectId: string,
  opts: { reason: string; bumpedBy: string },
): EpochBumpRecord {
  const db = getDB()
  const key = configKey(tenantId, kind, subjectId)

  const txn = db.transaction(() => {
    const current = getCurrentEpoch(tenantId, kind, subjectId)
    const next = current + 1
    db.prepare(
      `INSERT INTO gateway_config (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    ).run(key, String(next))
    return { current, next }
  })
  const { current, next } = txn.immediate()

  const unsigned = {
    type: 'epoch_bump' as const,
    tenantId,
    subjectKind: kind,
    subjectId,
    previousEpoch: current,
    newEpoch: next,
    reason: opts.reason,
    bumpedBy: opts.bumpedBy,
    bumpedAt: new Date().toISOString(),
  }
  const signature = getGatewayIdentity().sign(unsigned)
  const record: EpochBumpRecord = { ...unsigned, signature }

  emitRevocationEvent(
    tenantId,
    'epoch_bump',
    {
      subjectKind: kind,
      subjectId,
      previousEpoch: current,
      newEpoch: next,
      reason: opts.reason,
    },
    subjectId,
  )

  return record
}

/**
 * STUB seam: SDK Wave 2 W2-B3 ephemeral-token verifier.
 *
 * A token (or receipt) is carried with the epoch it was minted at. The sink
 * calls this to decide whether the token is still live with respect to its
 * subject's current epoch. Today it checks only the gateway_config epoch
 * counter, which is the source of truth. When W2-B3 lands, the ephemeral-token
 * signature/expiry verify is layered in front of this exact-epoch check.
 *
 * Returns true iff the token is NOT stale (tokenEpoch >= currentEpoch).
 * Zero false positives: a token is denied only when its epoch is strictly
 * older than the current epoch.
 *
 * TODO(W2-B3): wrap with SDK ephemeral-token signature + expiry verify.
 */
export function tokenEpochGuard(
  token: { tenantId: string; subjectKind: EpochSubjectKind; subjectId: string; epoch: number },
  // STUB: SDK Wave 2 W2-B3 ephemeral token verify will also check sig/expiry here.
): { allowed: boolean; currentEpoch: number; tokenEpoch: number; reason: string } {
  const currentEpoch = getCurrentEpoch(token.tenantId, token.subjectKind, token.subjectId)
  const allowed = token.epoch >= currentEpoch
  return {
    allowed,
    currentEpoch,
    tokenEpoch: token.epoch,
    reason: allowed
      ? 'token epoch current'
      : `stale epoch: token ${token.epoch} < current ${currentEpoch}`,
  }
}

/**
 * Stamp the current epoch onto a freshly minted token/receipt body. Sinks read
 * this back via tokenEpochGuard. Pure read; does not bump.
 */
export function stampEpoch(
  tenantId: string,
  kind: EpochSubjectKind,
  subjectId: string,
): { subjectKind: EpochSubjectKind; subjectId: string; epoch: number; stampedAt: string } {
  return {
    subjectKind: kind,
    subjectId,
    epoch: getCurrentEpoch(tenantId, kind, subjectId),
    stampedAt: new Date().toISOString(),
  }
}
