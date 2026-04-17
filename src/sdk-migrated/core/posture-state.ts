// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Posture state machine — downgrade ratchet + manual upgrade
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). The SDK retains tier types,
// constraint shapes, DEFAULT_POSTURE_CONSTRAINTS, and the pure helpers
// (getPostureConstraints, isScopeBlocked, comparePostureTiers).
//
// What lives here:
//   - DEFAULT_DOWNGRADE_POLICY (gateway-tunable thresholds)
//   - createInitialPosture (factory)
//   - recordBehavioralFailure / recordBehavioralSuccess (downgrade ratchet)
//   - upgradePosture (manual restoration by principal)
//
// Posture is "trust easy to lose, hard to rebuild" — automatic downgrade
// after sustained failures, manual upgrade requires human principal.
// ══════════════════════════════════════════════════════════════════════

import type {
  PostureTier, PostureChange, GovernancePosture, PostureDowngradePolicy,
} from 'agent-passport-system'

export const DEFAULT_DOWNGRADE_POLICY: PostureDowngradePolicy = {
  fullToStandard: 3,
  standardToCautious: 5,
  cautiousToRestricted: 3,
  restrictedToQuarantine: 2,
}

/** Create initial posture for a newly registered agent */
export function createInitialPosture(tier: PostureTier = 'standard'): GovernancePosture {
  return {
    tier,
    changedAt: new Date().toISOString(),
    changedBy: 'system',
    consecutiveFailures: 0,
    failuresSinceChange: 0,
    history: [],
  }
}

/** Record a behavioral failure and check if downgrade is needed.
 *  Returns updated posture (may be downgraded). */
export function recordBehavioralFailure(
  posture: GovernancePosture,
  reason: string,
  policy: PostureDowngradePolicy = DEFAULT_DOWNGRADE_POLICY,
): GovernancePosture {
  const updated = { ...posture }
  updated.consecutiveFailures++
  updated.failuresSinceChange++

  const threshold = getDowngradeThreshold(posture.tier, policy)
  if (threshold !== null && updated.consecutiveFailures >= threshold) {
    const nextTier = getNextLowerTier(posture.tier)
    if (nextTier) {
      const change: PostureChange = {
        from: posture.tier, to: nextTier,
        reason: `Auto-downgrade: ${updated.consecutiveFailures} consecutive failures. ${reason}`,
        changedBy: 'system', changedAt: new Date().toISOString(),
      }
      updated.tier = nextTier
      updated.changedAt = change.changedAt
      updated.changedBy = 'system'
      updated.consecutiveFailures = 0
      updated.failuresSinceChange = 0
      updated.history = [...posture.history, change]
    }
  }
  return updated
}

/** Record a behavioral success — resets consecutive failure counter */
export function recordBehavioralSuccess(posture: GovernancePosture): GovernancePosture {
  return { ...posture, consecutiveFailures: 0 }
}

/** Manually upgrade posture — REQUIRES human principal action.
 *  Cannot skip tiers (must go one step at a time).
 *  Trust is easy to lose and hard to rebuild. */
export function upgradePosture(
  posture: GovernancePosture,
  principalDid: string,
  reason: string,
): GovernancePosture {
  const nextTier = getNextHigherTier(posture.tier)
  if (!nextTier) return posture

  const change: PostureChange = {
    from: posture.tier, to: nextTier,
    reason: `Manual upgrade by ${principalDid}: ${reason}`,
    changedBy: principalDid, changedAt: new Date().toISOString(),
  }

  return {
    ...posture,
    tier: nextTier,
    changedAt: change.changedAt,
    changedBy: principalDid,
    consecutiveFailures: 0,
    failuresSinceChange: 0,
    history: [...posture.history, change],
  }
}

// ── Internal helpers ──

const TIER_SEQUENCE: PostureTier[] = ['quarantine', 'restricted', 'cautious', 'standard', 'full_trust']

function getNextLowerTier(tier: PostureTier): PostureTier | null {
  const idx = TIER_SEQUENCE.indexOf(tier)
  return idx > 0 ? TIER_SEQUENCE[idx - 1] : null
}

function getNextHigherTier(tier: PostureTier): PostureTier | null {
  const idx = TIER_SEQUENCE.indexOf(tier)
  return idx < TIER_SEQUENCE.length - 1 ? TIER_SEQUENCE[idx + 1] : null
}

function getDowngradeThreshold(
  tier: PostureTier,
  policy: PostureDowngradePolicy,
): number | null {
  switch (tier) {
    case 'full_trust': return policy.fullToStandard
    case 'standard': return policy.standardToCautious
    case 'cautious': return policy.cautiousToRestricted
    case 'restricted': return policy.restrictedToQuarantine
    case 'quarantine': return null
  }
}
