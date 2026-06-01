// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Revocation engine (GEMS).
 *
 * Layered revocation that is real at the sink, not cosmetic at the control
 * plane:
 *
 *  - epochs.ts    Monotonic per-subject epoch counters. The source of truth.
 *                 Sinks deny stale-epoch tokens (tokenEpochGuard).
 *  - freeze.ts    Asymmetric panic-freeze (single admin, immediate) and
 *                 multi-sig thaw / destroy (distinct-signer quorum).
 *  - cascade.ts   Read-only blast-radius preview before a revoke, with
 *                 recommended action options.
 *  - inbound.ts   SDK pass-through for verifying signed revocations and
 *                 running revocation-policy delegation checks.
 *  - sinks.ts     Dual emit: in-process EventBus (works now) + SET push
 *                 (stubbed for SDK Wave 2 W2-B3).
 *
 * Epochs are exact and zero false positive; any filter is an edge optimization
 * only, never the source of truth. Propagation freshness is recorded, never
 * asserted as instant.
 */

import { initFreezeTables } from './freeze.js'

/** Initialize all revocation-engine tables. Call once at startup after DB init. */
export function initRevocationTables(): void {
  // gateway_config (epoch counters) is created by initLineageTables(); the
  // freeze/thaw state machine has its own tables.
  initFreezeTables()
}

export {
  getCurrentEpoch,
  bumpEpoch,
  tokenEpochGuard,
  stampEpoch,
  type EpochSubjectKind,
  type EpochBumpRecord,
} from './epochs.js'

export {
  panicFreeze,
  isFrozen,
  proposeThaw,
  addThawApproval,
  finalizeThaw,
  getThaw,
  initFreezeTables,
  type FreezeMode,
  type FreezeRecord,
  type ThawKind,
  type ThawState,
  type ThawProposal,
  type ThawApproval,
} from './freeze.js'

export {
  previewCascade,
  walkDescendants,
  type CascadePreview,
  type CascadeAction,
  type DelegationNode,
  type RevokeTargetType,
  type DerivationContext,
} from './cascade.js'

export {
  verifyInboundRevocation,
  checkDelegationWithEpoch,
} from './inbound.js'

export {
  emitRevocationEvent,
  pushSecurityEventToken,
  type SecurityEventToken,
  type RevocationEventType,
} from './sinks.js'
