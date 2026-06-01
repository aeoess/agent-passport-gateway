// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - Per-tenant isolation switch (the D2 settled decision)
// ══════════════════════════════════════════════════════════════════
// D2 = isolation-by-default. Every tenant has an isolation_mode on the
// existing tenant model (db/schema.ts):
//   'hard'     → regulated tenant. NO cross-tenant path. The tenant can
//                neither contribute to nor consume any cross-tenant signal,
//                even de-identified and aggregated, regardless of opt-in.
//   'standard' → tenant MAY participate in de-identified, aggregated,
//                opt-in, above-k-floor cross-tenant signal.
//
// The switch is a pure resolver over the tenant row plus a small set of
// state-transition helpers that persist the mode and emit a lifecycle
// event. The actual cross-tenant emission gate (opt-in + k-floor over
// time-series) lives in cohort-gate.ts and consults this resolver first.
//
// THIN-GATEWAY: this resolver is a pre-check, not an enforcement brain.
// The hard-isolation guarantee is ultimately structural - an air-gapped
// or hard-isolated tenant has no cross-tenant code path reachable - and
// sink-enforced at the edge. The resolver makes the gateway refuse to
// participate; it is not the only thing standing between tenants.
// ══════════════════════════════════════════════════════════════════

import { getDB } from '../../db/schema.js'

export type IsolationMode = 'hard' | 'standard'

/** The isolation-relevant slice of a tenant row. */
export interface TenantIsolationState {
  tenantId: string
  isolationMode: IsolationMode
  cohortOptIn: boolean
  airGapped: boolean
  trustRootSource: 'gateway' | 'hsm' | 'kms'
}

/** Decision returned by the cross-tenant participation check. */
export interface CrossTenantDecision {
  allowed: boolean
  reason: string
  /** The settled-decision code that produced the verdict, for audit. */
  code:
    | 'hard_isolation_block'
    | 'air_gapped_block'
    | 'not_opted_in'
    | 'permitted'
}

/** Read the isolation state for a tenant. Returns null if the tenant is
 *  unknown. Defaults are isolation-by-default ('hard', not opted in). */
export function getTenantIsolationState(tenantId: string): TenantIsolationState | null {
  const db = getDB()
  const row = db.prepare(
    `SELECT id, isolation_mode, cohort_opt_in, air_gapped, trust_root_source
       FROM tenants WHERE id = ?`,
  ).get(tenantId) as
    | {
        id: string
        isolation_mode?: string
        cohort_opt_in?: number
        air_gapped?: number
        trust_root_source?: string
      }
    | undefined
  if (!row) return null
  return normalizeIsolationRow(row)
}

/** Coerce a raw tenant row to a fail-safe isolation state. Any unknown or
 *  missing isolation_mode resolves to 'hard' so a stale or malformed row is
 *  isolated, never accidentally cross-tenant. */
export function normalizeIsolationRow(row: {
  id: string
  isolation_mode?: string
  cohort_opt_in?: number
  air_gapped?: number
  trust_root_source?: string
}): TenantIsolationState {
  const mode: IsolationMode = row.isolation_mode === 'standard' ? 'standard' : 'hard'
  const trustSrc =
    row.trust_root_source === 'hsm' || row.trust_root_source === 'kms'
      ? row.trust_root_source
      : 'gateway'
  return {
    tenantId: row.id,
    isolationMode: mode,
    cohortOptIn: row.cohort_opt_in === 1,
    airGapped: row.air_gapped === 1,
    trustRootSource: trustSrc,
  }
}

/**
 * The core pre-check: may THIS tenant participate in a cross-tenant signal?
 *
 * Order is fail-safe: hard isolation and air-gap block unconditionally,
 * BEFORE opt-in is even consulted. A regulated ('hard') tenant can never
 * reach the cross-tenant path even if a buggy caller set cohort_opt_in.
 */
export function canParticipateCrossTenant(
  state: TenantIsolationState | null,
): CrossTenantDecision {
  if (!state) {
    return { allowed: false, reason: 'unknown tenant', code: 'hard_isolation_block' }
  }
  if (state.isolationMode === 'hard') {
    return {
      allowed: false,
      reason: 'regulated tenant in hard isolation: no cross-tenant path',
      code: 'hard_isolation_block',
    }
  }
  if (state.airGapped) {
    return {
      allowed: false,
      reason: 'air-gapped tenant: no outbound cross-tenant path exists',
      code: 'air_gapped_block',
    }
  }
  if (!state.cohortOptIn) {
    return {
      allowed: false,
      reason: 'tenant has not opted in to cross-tenant signal',
      code: 'not_opted_in',
    }
  }
  return { allowed: true, reason: 'standard mode, opted in', code: 'permitted' }
}

/** Convenience: resolve state then check, by tenant id. */
export function canTenantParticipateCrossTenant(tenantId: string): CrossTenantDecision {
  return canParticipateCrossTenant(getTenantIsolationState(tenantId))
}

/**
 * Persist a new isolation mode for a tenant. Returns the prior and new state.
 * Recording the lifecycle event + emitting on the bus is the router's job so
 * this stays a pure persistence helper testable without the event system.
 */
export function setIsolationMode(
  tenantId: string,
  mode: IsolationMode,
): { changed: boolean; from: IsolationMode | null; to: IsolationMode } {
  const db = getDB()
  const before = getTenantIsolationState(tenantId)
  if (!before) throw new Error(`unknown tenant: ${tenantId}`)
  if (before.isolationMode === mode) {
    return { changed: false, from: before.isolationMode, to: mode }
  }
  db.prepare(`UPDATE tenants SET isolation_mode = ? WHERE id = ?`).run(mode, tenantId)
  // Switching a tenant INTO hard isolation revokes any standing cross-tenant
  // opt-in so the two flags can never be left in a contradictory state.
  if (mode === 'hard') {
    db.prepare(`UPDATE tenants SET cohort_opt_in = 0 WHERE id = ?`).run(tenantId)
  }
  return { changed: true, from: before.isolationMode, to: mode }
}

/**
 * Set the cross-tenant opt-in flag. Opt-in is refused for a hard-isolated
 * tenant: you cannot opt a regulated tenant into the cohort without first
 * moving it to standard mode (an explicit, separately audited transition).
 */
export function setCohortOptIn(
  tenantId: string,
  optIn: boolean,
): { applied: boolean; reason: string } {
  const db = getDB()
  const state = getTenantIsolationState(tenantId)
  if (!state) throw new Error(`unknown tenant: ${tenantId}`)
  if (optIn && state.isolationMode === 'hard') {
    return {
      applied: false,
      reason: 'cannot opt a hard-isolated tenant into cross-tenant signal; move to standard first',
    }
  }
  db.prepare(`UPDATE tenants SET cohort_opt_in = ? WHERE id = ?`).run(optIn ? 1 : 0, tenantId)
  return { applied: true, reason: optIn ? 'opted in' : 'opted out' }
}
