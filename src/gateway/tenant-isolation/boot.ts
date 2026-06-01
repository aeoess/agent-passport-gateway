// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - In-tenant deployment boot hook
// ══════════════════════════════════════════════════════════════════
// An in-tenant deployment sets ISOLATION_MODE / TRUST_ROOT_SOURCE /
// TRUST_ROOT_KEY_REF at deploy time (Helm, Terraform, Docker, air-gap). This
// hook reads those env vars at boot and applies them as the DEFAULT for any
// tenant row that has not yet had an explicit isolation decision recorded.
//
// It is conservative: it only TIGHTENS, never loosens. If the env says
// 'hard' it forces every existing tenant to hard isolation (D2
// isolation-by-default). If the env says 'standard' it leaves existing rows
// alone (their column default is already 'hard'); a tenant must still opt in
// explicitly through the router. This way a misconfigured env can never
// silently widen a regulated tenant's exposure.
// ══════════════════════════════════════════════════════════════════

import { getDB } from '../../db/schema.js'

export interface DeploymentIsolationConfig {
  isolationMode: 'hard' | 'standard'
  trustRootSource: 'gateway' | 'hsm' | 'kms'
  trustRootKeyRef: string | null
  airGapped: boolean
}

/** Read the deployment isolation config from env, with safe defaults. */
export function readDeploymentConfig(env: NodeJS.ProcessEnv = process.env): DeploymentIsolationConfig {
  const mode = env.ISOLATION_MODE === 'standard' ? 'standard' : 'hard'
  const src =
    env.TRUST_ROOT_SOURCE === 'hsm' || env.TRUST_ROOT_SOURCE === 'kms'
      ? env.TRUST_ROOT_SOURCE
      : 'gateway'
  // An air-gapped deployment is one with no outbound path. We infer it from an
  // explicit AIR_GAPPED flag; network policy enforces the actual isolation.
  const airGapped = env.AIR_GAPPED === '1' || env.AIR_GAPPED === 'true'
  return {
    isolationMode: mode,
    trustRootSource: src,
    trustRootKeyRef: env.TRUST_ROOT_KEY_REF ? env.TRUST_ROOT_KEY_REF : null,
    airGapped,
  }
}

/**
 * Apply the deployment config as the isolation default. Tighten-only.
 * Idempotent: safe to call on every boot. Returns a small summary for logs.
 */
export function applyDeploymentIsolationDefault(
  config: DeploymentIsolationConfig = readDeploymentConfig(),
): { mode: string; tenantsForcedHard: number; airGapped: boolean } {
  const db = getDB()
  if (!db) return { mode: config.isolationMode, tenantsForcedHard: 0, airGapped: config.airGapped }

  let forced = 0
  if (config.isolationMode === 'hard') {
    // Tighten every active tenant to hard isolation and drop any cross-tenant
    // opt-in. Never loosen. This is the regulated-deployment default.
    const r = db.prepare(
      `UPDATE tenants SET isolation_mode = 'hard', cohort_opt_in = 0
        WHERE status = 'active' AND (isolation_mode != 'hard' OR cohort_opt_in != 0)`,
    ).run()
    forced = r.changes
  }

  if (config.airGapped) {
    db.prepare(`UPDATE tenants SET air_gapped = 1 WHERE status = 'active'`).run()
  }

  // Record the deployment trust-root source/ref as the default for tenants
  // still on the gateway-generated key. Stores the reference only.
  if (config.trustRootSource !== 'gateway') {
    db.prepare(
      `UPDATE tenants SET trust_root_source = ?, trust_root_key_ref = ?
        WHERE status = 'active' AND trust_root_source = 'gateway'`,
    ).run(config.trustRootSource, config.trustRootKeyRef)
  }

  return { mode: config.isolationMode, tenantsForcedHard: forced, airGapped: config.airGapped }
}
