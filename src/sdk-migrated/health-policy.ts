// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Agent Health Policy — gateway-owned threshold logic
// ══════════════════════════════════════════════════════════════════
// Migrated from agent-passport-system/src/types/health.ts as part of the
// AAIF boundary cleanup. The AgentHealthStatus SHAPE stays in the SDK
// (so monitoring consumers know the response format); the POLICY that
// decides when an agent is healthy/degraded/suspended/expired lives
// here, because the thresholds are product-level governance decisions,
// not protocol primitives.
//
// See aeoess_web/specs/AAIF-BOUNDARY-AUDIT.md.
// ══════════════════════════════════════════════════════════════════

import type { AgentHealthStatus } from 'agent-passport-system'

/** Spend utilization above this value degrades the agent. */
export const SPEND_UTILIZATION_DEGRADED_THRESHOLD = 0.95

/**
 * Derive an agent's health status from its current health components.
 *
 * Precedence (highest first):
 *   1. expired   — passport invalid
 *   2. suspended — behavioral drift detected
 *   3. degraded  — recent recovery events OR high spend utilization
 *   4. healthy   — none of the above
 */
export function deriveHealthStatus(
  health: Omit<AgentHealthStatus, 'status'>,
): AgentHealthStatus['status'] {
  if (!health.passport.valid) return 'expired'
  if (health.behavioral.driftDetected) return 'suspended'
  if (health.recovery.recentRecoveryEvents > 0) return 'degraded'
  if (health.delegation.spendUtilization > SPEND_UTILIZATION_DEGRADED_THRESHOLD) return 'degraded'
  return 'healthy'
}
