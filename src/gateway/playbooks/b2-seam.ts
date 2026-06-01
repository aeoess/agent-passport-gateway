// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Typed seam to the G-B2 revocation engine (GEMS).
 *
 * G-B2 is a SEPARATE local branch (gw-b2-revocation) NOT merged into this base
 * (main 5ccdac7). Build directive 5: read the dependency's PUBLIC surface from
 * its worktree, build against that interface, then stub the actual import behind
 * a typed seam. We depend on B2's public surface only, never its internals.
 *
 * B2 public surface consumed (from
 * gw-b2-revocation/src/gateway/revocation/index.ts):
 *   - getCurrentEpoch(tenantId, kind, subjectId): number
 *   - bumpEpoch(tenantId, kind, subjectId, { reason, bumpedBy }): EpochBumpRecord
 *   - tokenEpochGuard(token): { allowed, currentEpoch, tokenEpoch, reason }
 *   - type EpochSubjectKind = 'agent' | 'delegation'
 *
 * IMPORTANT seam-compatibility property: B2's epochs.ts stores counters in the
 * SHARED gateway_config k/v table under the EXACT keys reproduced below
 * (`epoch:agent:<tenant>:<subject>` and `epoch:delegation:<tenant>:<subject>`).
 * This shim reads/writes those identical keys. So when B2 merges and the real
 * import replaces this file's call sites, the epoch state is continuous: nothing
 * to migrate, no double-counting. The C2 module NEVER owns epoch logic; it only
 * reads/bumps via this seam, and the SINK (B2 tokenEpochGuard, offline) is what
 * actually enforces.
 *
 * TODO(G-B2 / gw-b2-revocation): replace the bodies below with direct calls to
 *   the merged module:
 *     import { getCurrentEpoch, bumpEpoch, tokenEpochGuard } from '../revocation/index.js'
 *   The signatures here are deliberately identical so the swap is mechanical.
 */

import { getDB } from '../../db/schema.js'
import { getGatewayIdentity } from '../identity.js'
import { emitRevocationEventSeam } from './revocation-seam.js'

export type EpochSubjectKindSeam = 'agent' | 'delegation'

// Same key namespace B2 epochs.ts uses. Keep byte-identical for continuity.
const AGENT_EPOCH_PREFIX = 'epoch:agent:'
const DELEGATION_EPOCH_PREFIX = 'epoch:delegation:'

function configKey(tenantId: string, kind: EpochSubjectKindSeam, subjectId: string): string {
  const prefix = kind === 'agent' ? AGENT_EPOCH_PREFIX : DELEGATION_EPOCH_PREFIX
  return `${prefix}${tenantId}:${subjectId}`
}

/** Mirror of B2 getCurrentEpoch. Absent counter = epoch 0. Monotonic, non-negative. */
export function getCurrentEpochSeam(
  tenantId: string,
  kind: EpochSubjectKindSeam,
  subjectId: string,
): number {
  const db = getDB()
  const row = db.prepare(`SELECT value FROM gateway_config WHERE key = ?`)
    .get(configKey(tenantId, kind, subjectId)) as { value?: string } | undefined
  if (!row?.value) return 0
  const n = parseInt(row.value, 10)
  return Number.isFinite(n) && n >= 0 ? n : 0
}

export interface EpochBumpRecordSeam {
  type: 'epoch_bump'
  tenantId: string
  subjectKind: EpochSubjectKindSeam
  subjectId: string
  previousEpoch: number
  newEpoch: number
  reason: string
  bumpedBy: string
  bumpedAt: string
  signature: string
}

/**
 * Mirror of B2 bumpEpoch. The kill primitive: after a bump, every token at the
 * prior epoch is stale at the sink. Wrapped in an IMMEDIATE transaction for the
 * read-then-write, exactly as B2 does. Signs the bump record with the gateway
 * identity so an auditor can verify the monotonic history.
 *
 * The CALLER supplies an authenticated bumpedBy (for the customer kill, that is
 * the customer principal). This shim does not invent an actor; it requires one.
 */
export function bumpEpochSeam(
  tenantId: string,
  kind: EpochSubjectKindSeam,
  subjectId: string,
  opts: { reason: string; bumpedBy: string },
): EpochBumpRecordSeam {
  if (!opts.bumpedBy) throw new Error('bumpEpoch requires an authenticated bumpedBy actor')
  const db = getDB()
  const key = configKey(tenantId, kind, subjectId)

  const txn = db.transaction(() => {
    const current = getCurrentEpochSeam(tenantId, kind, subjectId)
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

  // Dual-sink emit (in-process bus + SET stub), via the revocation-family seam.
  emitRevocationEventSeam(
    tenantId,
    'epoch_bump',
    { subjectKind: kind, subjectId, previousEpoch: current, newEpoch: next, reason: opts.reason },
    subjectId,
  )

  return { ...unsigned, signature }
}

/**
 * Mirror of B2 tokenEpochGuard. The OFFLINE sink check: a token is honored iff
 * its stamped epoch is not strictly older than the subject's current epoch. Zero
 * false positives. This is the function the SINK runs with NO gateway call.
 *
 * TODO(W2-B3): when the SDK ephemeral-token verifier lands, the token signature
 *   + expiry verify is layered in FRONT of this exact-epoch check (the same
 *   marker B2 epochs.ts carries). The epoch comparison stays the source of truth.
 */
export function tokenEpochGuardSeam(token: {
  tenantId: string
  subjectKind: EpochSubjectKindSeam
  subjectId: string
  epoch: number
}): { allowed: boolean; currentEpoch: number; tokenEpoch: number; reason: string } {
  const currentEpoch = getCurrentEpochSeam(token.tenantId, token.subjectKind, token.subjectId)
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
