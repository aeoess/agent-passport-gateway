// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Per-tenant and per-workflow enforcement mode configuration
// ══════════════════════════════════════════════════════════════════
// Resolution order for the active mode on a given request:
//   1. per-workflow override (mode_config row with a non-null workflow_id), else
//   2. per-tenant default (mode_config row with workflow_id IS NULL), else
//   3. DEFAULT_MODE ('observe').
//
// `observe` is the safe default on purpose: a freshly onboarded tenant must not
// have anything blocked until they have explicitly chosen to enforce. This is
// the migration-safety posture the whole module exists to support.
// ══════════════════════════════════════════════════════════════════

import { getDB } from '../../db/schema.js'
import { type EnforcementMode, isEnforcementMode } from './modes.js'

/** The posture every tenant starts in: evidence only, nothing blocked. */
export const DEFAULT_MODE: EnforcementMode = 'observe'

/**
 * Create the mode_config table. Idempotent. Called from schema init alongside
 * the other gateway module table initializers (initLineageTables, etc).
 *
 * One row per (tenant, workflow). A NULL workflow_id row is the tenant default.
 * The UNIQUE index treats NULL workflow_id as a single distinct default slot by
 * coalescing it to the sentinel '' in a generated expression-free way: we store
 * the tenant default with workflow_id = '' rather than NULL so the UNIQUE
 * constraint is enforceable in SQLite (which treats NULLs as distinct).
 */
export function initModeConfigTable(): void {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS mode_config (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      workflow_id TEXT NOT NULL DEFAULT '',
      mode TEXT NOT NULL DEFAULT 'observe',
      updated_by TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, workflow_id)
    );

    CREATE INDEX IF NOT EXISTS idx_mode_config_tenant ON mode_config(tenant_id);
  `)
}

interface ModeConfigRow {
  mode: string
  workflow_id: string
}

/**
 * Resolve the active mode for a request. workflow_id is optional; when present
 * a workflow-specific override wins over the tenant default.
 */
export function resolveMode(tenantId: string, workflowId?: string | null): EnforcementMode {
  // Fail safe to the shadow default if the table is missing or the query
  // throws. resolveMode sits on the hot /evaluate path; it must never throw
  // into enforcement. Falling back to `observe` also fails SAFE (nothing is
  // newly blocked by a config read error).
  try {
    const db = getDB()
    const wf = (workflowId || '').trim()

    // 1. workflow override
    if (wf) {
      const row = db.prepare(
        `SELECT mode, workflow_id FROM mode_config WHERE tenant_id = ? AND workflow_id = ?`
      ).get(tenantId, wf) as ModeConfigRow | undefined
      if (row && isEnforcementMode(row.mode)) return row.mode
    }

    // 2. tenant default (workflow_id = '')
    const def = db.prepare(
      `SELECT mode, workflow_id FROM mode_config WHERE tenant_id = ? AND workflow_id = ''`
    ).get(tenantId) as ModeConfigRow | undefined
    if (def && isEnforcementMode(def.mode)) return def.mode
  } catch (e) {
    console.error('[mode-config] resolveMode fell back to default:', (e as Error).message)
  }

  // 3. global default
  return DEFAULT_MODE
}

/**
 * Set the mode for a tenant (workflow_id omitted) or a specific workflow.
 * Upserts on the (tenant, workflow) slot. Returns the stored mode.
 */
export function setMode(opts: {
  tenantId: string
  mode: EnforcementMode
  workflowId?: string | null
  updatedBy?: string | null
}): { tenantId: string; workflowId: string; mode: EnforcementMode } {
  if (!isEnforcementMode(opts.mode)) {
    throw new Error(`invalid mode: ${String(opts.mode)}`)
  }
  const db = getDB()
  const wf = (opts.workflowId || '').trim()
  // Stable id per slot so repeat writes update in place.
  const id = `mode_${opts.tenantId}_${wf || 'default'}`
  db.prepare(
    `INSERT INTO mode_config (id, tenant_id, workflow_id, mode, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(tenant_id, workflow_id) DO UPDATE SET
       mode = excluded.mode,
       updated_by = excluded.updated_by,
       updated_at = datetime('now')`
  ).run(id, opts.tenantId, wf, opts.mode, opts.updatedBy || null)
  return { tenantId: opts.tenantId, workflowId: wf, mode: opts.mode }
}

/** List every configured mode slot for a tenant (default + workflow overrides). */
export function listModes(tenantId: string): Array<{ workflowId: string; mode: EnforcementMode; updatedAt: string }> {
  const db = getDB()
  const rows = db.prepare(
    `SELECT workflow_id, mode, updated_at FROM mode_config WHERE tenant_id = ? ORDER BY workflow_id`
  ).all(tenantId) as Array<{ workflow_id: string; mode: string; updated_at: string }>
  return rows
    .filter(r => isEnforcementMode(r.mode))
    .map(r => ({ workflowId: r.workflow_id, mode: r.mode as EnforcementMode, updatedAt: r.updated_at }))
}
