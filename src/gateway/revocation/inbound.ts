// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Inbound signed-revocation verification: pure SDK pass-through.
 *
 * Protocol primitives (signature verification, revocation-policy delegation
 * checks) belong to the SDK, not the gateway. This module is a thin seam that
 * consumes the SDK so the gateway never reimplements a primitive:
 *
 *  - verifyInboundRevocation: validates a signed RevocationRecord submitted by
 *    a delegator. Pure signature check (SDK verifyRevocation), no DB lookup.
 *
 *  - checkDelegationWithEpoch: runs the SDK verifyDelegation with the gateway's
 *    own cached revoke/freeze state fed in via cachedRevocationState. The SDK
 *    does no lookup; the gateway supplies the state from its DB and the epoch
 *    engine. This is the integration seam where epoch/freeze state meets the
 *    SDK's revocation-check policy.
 */

import {
  verifyRevocation,
  verifyDelegation,
  type RevocationRecord,
  type Delegation,
  type DelegationStatus,
} from 'agent-passport-system'
import { getCurrentEpoch } from './epochs.js'
import { isFrozen } from './freeze.js'

/**
 * Verify a signed RevocationRecord from a delegator. Pure SDK signature check
 * against revokedBy. Returns false on any malformed or unsigned input.
 */
export function verifyInboundRevocation(record: RevocationRecord): boolean {
  try {
    return verifyRevocation(record)
  } catch {
    return false
  }
}

/**
 * Verify a delegation under a revocation-check policy, feeding the gateway's
 * own revoked/frozen state in as cachedRevocationState. The SDK performs the
 * signature / expiry / depth checks and applies the policy; the gateway owns
 * the lookup. fail_closed by default for revocation-sensitive paths.
 */
export function checkDelegationWithEpoch(opts: {
  delegation: Delegation
  tenantId: string
  childAgentId: string
  revocationCheckPolicy?: 'fail_open' | 'fail_closed' | 'cache_grace'
  cacheGraceMs?: number
}): DelegationStatus {
  const { delegation, tenantId, childAgentId } = opts
  // The gateway owns the lookup: an active freeze means the cached revocation
  // state is "revoked" for policy purposes. (A future bump-vs-mint epoch
  // comparison can refine this; the freeze flag is the current source.)
  const frozen = isFrozen(tenantId, childAgentId)

  return verifyDelegation(delegation, {
    revocationCheckPolicy: opts.revocationCheckPolicy ?? 'fail_closed',
    cachedRevocationState: {
      revoked: frozen,
      checkedAt: new Date().toISOString(),
    },
    cacheGraceMs: opts.cacheGraceMs,
  })
}
