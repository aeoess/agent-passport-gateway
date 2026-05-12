// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway — Database Schema
 * SQLite for MVP, PostgreSQL migration path clear.
 */

import Database from 'better-sqlite3'
import { randomUUID } from 'node:crypto'

let db: Database.Database

export function initDB(path: string = './gateway.db'): Database.Database {
  db = new Database(path)
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')
  db.pragma('busy_timeout = 5000')
  createTables()
  return db
}

export function getDB(): Database.Database { return db }

function createTables() {
  db.exec(`
    -- Tenants (customers)
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      plan TEXT NOT NULL DEFAULT 'free',
      stripe_customer_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      status TEXT NOT NULL DEFAULT 'active'
    );

    -- API Keys (one tenant can have multiple)
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT 'default',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at TEXT,
      revoked_at TEXT
    );

    -- Agents (registered under each tenant)
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      did TEXT,
      name TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, agent_id)
    );

    -- Delegations
    CREATE TABLE IF NOT EXISTS delegations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      parent_agent_id TEXT NOT NULL,
      child_agent_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      spend_limit REAL,
      spend_used REAL DEFAULT 0,
      max_depth INTEGER DEFAULT 3,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT
    );

    -- Policy Evaluations (the billable unit)
    CREATE TABLE IF NOT EXISTS policy_evaluations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      action_target TEXT NOT NULL,
      scope_required TEXT NOT NULL,
      verdict TEXT NOT NULL,
      reason TEXT,
      duration_ms INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Action Receipts (signed proof of execution)
    CREATE TABLE IF NOT EXISTS receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      evaluation_id TEXT REFERENCES policy_evaluations(id),
      agent_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      verdict TEXT NOT NULL,
      execution_result TEXT NOT NULL,
      signature TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Usage (metered billing)
    CREATE TABLE IF NOT EXISTS usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      period TEXT NOT NULL,
      evaluations INTEGER DEFAULT 0,
      agents_active INTEGER DEFAULT 0,
      receipts_stored INTEGER DEFAULT 0,
      data_lineage_queries INTEGER DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, period)
    );

    -- Revocation Events
    CREATE TABLE IF NOT EXISTS revocations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      cascade_count INTEGER DEFAULT 0,
      revoked_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Alerts
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      alert_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      acknowledged_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Data Sources (Pixel: registered data with terms)
    CREATE TABLE IF NOT EXISTS data_sources (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source_id TEXT NOT NULL,
      source_name TEXT NOT NULL,
      source_url TEXT,
      data_terms TEXT NOT NULL DEFAULT '{}',
      owner_agent_id TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT,
      UNIQUE(tenant_id, source_id)
    );

    -- Access Receipts (Pixel: who accessed what data, when)
    CREATE TABLE IF NOT EXISTS access_receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      purpose TEXT NOT NULL DEFAULT 'read',
      terms_snapshot TEXT,
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Contribution Ledger (Pixel: aggregated usage per source per agent)
    CREATE TABLE IF NOT EXISTS contributions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      access_count INTEGER DEFAULT 0,
      amount REAL DEFAULT 0.0,
      currency TEXT DEFAULT 'usd',
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, source_id, agent_id)
    );

    -- Settlements (Pixel: Merkle-committed payment records)
    CREATE TABLE IF NOT EXISTS settlements (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      total_amount REAL DEFAULT 0.0,
      line_items TEXT NOT NULL DEFAULT '[]',
      merkle_root TEXT,
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_evals_tenant ON policy_evaluations(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_evals_agent ON policy_evaluations(tenant_id, agent_id);
    CREATE INDEX IF NOT EXISTS idx_receipts_tenant ON receipts(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_delegations_tenant ON delegations(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage(tenant_id, period);
    CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id, acknowledged_at);
    CREATE INDEX IF NOT EXISTS idx_data_sources_tenant ON data_sources(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_access_receipts_tenant ON access_receipts(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_access_receipts_source ON access_receipts(tenant_id, source_id);
    CREATE INDEX IF NOT EXISTS idx_contributions_tenant ON contributions(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_settlements_tenant ON settlements(tenant_id, period_start);

    -- Derivations (Pixel: agent declares "I used these sources to produce this output")
    CREATE TABLE IF NOT EXISTS derivations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      source_ids TEXT NOT NULL DEFAULT '[]',
      output_description TEXT,
      output_url TEXT,
      access_receipt_ids TEXT NOT NULL DEFAULT '[]',
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_derivations_tenant ON derivations(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_derivations_agent ON derivations(tenant_id, agent_id);

    -- Payment Transactions (Nano adapter + future rails)
    CREATE TABLE IF NOT EXISTS payment_transactions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      settlement_id TEXT REFERENCES settlements(id),
      rail TEXT NOT NULL DEFAULT 'nano',
      direction TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'XNO',
      destination TEXT,
      tx_proof TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      invoice_data TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      confirmed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payment_transactions(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_payments_settlement ON payment_transactions(settlement_id);
    CREATE INDEX IF NOT EXISTS idx_payments_rail ON payment_transactions(rail, status);

    -- Agent Wallets (Nano address per agent, delegation-gated)
    CREATE TABLE IF NOT EXISTS agent_wallets (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      nano_address TEXT NOT NULL,
      wallet_index INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      balance_raw TEXT NOT NULL DEFAULT '0',
      total_received_raw TEXT NOT NULL DEFAULT '0',
      total_sent_raw TEXT NOT NULL DEFAULT '0',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_agent_wallets_tenant ON agent_wallets(tenant_id, status);

    -- Wallet Transactions (every send/receive/denied, linked to delegations)
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      from_agent_id TEXT NOT NULL,
      to_agent_id TEXT,
      to_address TEXT NOT NULL,
      amount_raw TEXT NOT NULL,
      amount_xno TEXT NOT NULL,
      block_hash TEXT,
      delegation_id TEXT,
      scope_used TEXT,
      evaluation_id TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      denial_reason TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      confirmed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_tx_tenant ON wallet_transactions(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_wallet_tx_agent ON wallet_transactions(tenant_id, from_agent_id);
    CREATE INDEX IF NOT EXISTS idx_wallet_tx_status ON wallet_transactions(tenant_id, status);

    -- Issuance Dossiers (attestation evidence per passport)
    CREATE TABLE IF NOT EXISTS issuance_dossiers (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      passport_id TEXT NOT NULL,
      public_key_hash TEXT NOT NULL,
      passport_grade INTEGER NOT NULL DEFAULT 0,
      flags TEXT NOT NULL DEFAULT '[]',
      attestation_bundle_hash TEXT,
      observed_context TEXT NOT NULL DEFAULT '{}',
      runtime_attestations TEXT NOT NULL DEFAULT '[]',
      provider_attestations TEXT NOT NULL DEFAULT '[]',
      self_declared_signals TEXT NOT NULL DEFAULT '[]',
      derived_signals TEXT NOT NULL DEFAULT '[]',
      prior_passport_ref TEXT,
      transport_type TEXT,
      issuance_velocity INTEGER,
      connection_timing_ms INTEGER,
      request_payload_fingerprint TEXT,
      cluster_risk TEXT DEFAULT 'unknown',
      cluster_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, passport_id)
    );

    CREATE INDEX IF NOT EXISTS idx_dossiers_tenant ON issuance_dossiers(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_dossiers_pubkey ON issuance_dossiers(public_key_hash);
    CREATE INDEX IF NOT EXISTS idx_dossiers_grade ON issuance_dossiers(tenant_id, passport_grade);

    -- MCP Stats Snapshots (persistent counters across Railway restarts)
    CREATE TABLE IF NOT EXISTS mcp_stats_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      snapshot_at TEXT NOT NULL,
      uptime_seconds REAL NOT NULL DEFAULT 0,
      passports_issued INTEGER DEFAULT 0,
      sessions_total INTEGER DEFAULT 0,
      sessions_active INTEGER DEFAULT 0,
      tool_calls_total INTEGER DEFAULT 0,
      evaluations_total INTEGER DEFAULT 0,
      delegations_created INTEGER DEFAULT 0,
      receipts_stored INTEGER DEFAULT 0,
      version TEXT,
      tenant_id TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_mcp_stats_session ON mcp_stats_snapshots(session_id, snapshot_at);
    CREATE INDEX IF NOT EXISTS idx_mcp_stats_time ON mcp_stats_snapshots(snapshot_at);

    -- Key Rotations (identity continuity enforcement)
    CREATE TABLE IF NOT EXISTS key_rotations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      old_key TEXT NOT NULL,
      new_key TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('planned', 'emergency')),
      announced_at TEXT NOT NULL,
      activation_time TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('announced', 'revocation_in_progress', 'revocation_complete', 'activated')),
      completed_at TEXT,
      rotation_signature TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_rotations_agent ON key_rotations(tenant_id, agent_id);

    -- Evaluation Receipts (auto-minted from every policy evaluation)
    CREATE TABLE IF NOT EXISTS evaluation_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      evaluation_id TEXT,
      event_type TEXT NOT NULL CHECK(event_type IN ('authorization_permit', 'authorization_deny')),
      decision_stage TEXT NOT NULL DEFAULT 'gateway_authorization',
      action_type TEXT,
      scope_requested_json TEXT,
      verdict TEXT NOT NULL CHECK(verdict IN ('permit', 'deny')),
      reason_code TEXT,
      delegation_id TEXT,
      policy_hash TEXT,
      schema_version TEXT NOT NULL DEFAULT '1.0.0',
      receipt_hash TEXT,
      gateway_signature TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_eval_receipts_agent ON evaluation_receipts(tenant_id, agent_id);
    CREATE INDEX IF NOT EXISTS idx_eval_receipts_deny ON evaluation_receipts(verdict) WHERE verdict = 'deny';

    -- Posture Events (audit trail for agent status transitions)
    CREATE TABLE IF NOT EXISTS posture_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      old_status TEXT NOT NULL,
      new_status TEXT NOT NULL,
      restricted_scopes TEXT,
      reason TEXT NOT NULL,
      changed_by TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_posture_events_agent ON posture_events(agent_id);

    -- Receipt Window Seals (Merkle-committed batches of evaluation receipts)
    CREATE TABLE IF NOT EXISTS receipt_window_seals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seal_id TEXT NOT NULL UNIQUE,
      seq_start INTEGER NOT NULL,
      seq_end INTEGER NOT NULL,
      receipt_count INTEGER NOT NULL,
      permit_count INTEGER DEFAULT 0,
      deny_count INTEGER DEFAULT 0,
      commitment_hash TEXT NOT NULL,
      leaf_schema TEXT DEFAULT 'gateway_receipt_v1',
      scope_note TEXT DEFAULT 'gateway-issued evaluation receipts only',
      gateway_signature TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `)

  db.exec(`
    -- Recovery Policies (one per agent, consulted on denial)
    CREATE TABLE IF NOT EXISTS recovery_policies (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      policy_json TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(tenant_id, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_recovery_policies_agent ON recovery_policies(tenant_id, agent_id);

    -- Recovery Events (audit trail for recovery actions)
    CREATE TABLE IF NOT EXISTS recovery_events (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      delegation_id TEXT,
      evaluation_id TEXT,
      failure_type TEXT NOT NULL,
      strategy_applied TEXT NOT NULL,
      attempt_number INTEGER NOT NULL,
      recovery_succeeded INTEGER,
      timestamp TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_recovery_events_agent ON recovery_events(tenant_id, agent_id);

    -- Agent Sessions (crash-recovery checkpoint — Primitive #3)
    CREATE TABLE IF NOT EXISTS agent_sessions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      session_data TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT,
      UNIQUE(tenant_id, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_agent ON agent_sessions(tenant_id, agent_id);

    -- Behavioral Memory Objects (BMO — Bring Your Own Memory)
    CREATE TABLE IF NOT EXISTS behavioral_memory_objects (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      principal_id TEXT NOT NULL,
      issuer_id TEXT NOT NULL,
      pattern_category TEXT NOT NULL,
      pattern_description TEXT NOT NULL,
      confidence REAL NOT NULL DEFAULT 0.5,
      observation_count INTEGER NOT NULL DEFAULT 1,
      observation_window_start TEXT NOT NULL,
      observation_window_end TEXT NOT NULL,
      derivation_source TEXT NOT NULL,
      retention_ttl INTEGER,
      expires_at TEXT,
      relational_entities TEXT NOT NULL DEFAULT '[]',
      portable INTEGER NOT NULL DEFAULT 0,
      issuer_signature TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_bmo_principal ON behavioral_memory_objects(tenant_id, principal_id);
    CREATE INDEX IF NOT EXISTS idx_bmo_issuer ON behavioral_memory_objects(tenant_id, issuer_id);
    CREATE INDEX IF NOT EXISTS idx_bmo_expires ON behavioral_memory_objects(expires_at);

    -- Coordination (Nate Primitive #4: Workflow State)
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      title TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      created_by TEXT NOT NULL,
      assigned_to TEXT,
      scope TEXT,
      acceptance_criteria TEXT,
      deliverable TEXT,
      evidence TEXT,
      review_verdict TEXT,
      review_notes TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_tenant ON tasks(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(tenant_id, assigned_to);

    CREATE TABLE IF NOT EXISTS task_events (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      task_id TEXT NOT NULL REFERENCES tasks(id),
      event_type TEXT NOT NULL,
      agent_id TEXT,
      data TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_task_events ON task_events(tenant_id, task_id);
  `)

  // Add columns (idempotent via try/catch)
  try { db.exec(`ALTER TABLE evaluation_receipts ADD COLUMN seal_id TEXT`) } catch {}

  // Add posture columns to agents table (idempotent via try/catch)
  try { db.exec(`ALTER TABLE agents ADD COLUMN restricted_scopes TEXT`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN posture_reason TEXT`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN posture_updated_at TEXT`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN agent_type TEXT DEFAULT 'general'`) } catch {}
  try { db.exec(`ALTER TABLE receipt_window_seals ADD COLUMN tenant_id TEXT`) } catch {}
  try { db.exec(`ALTER TABLE policy_evaluations ADD COLUMN task_class TEXT DEFAULT ''`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN entity_id TEXT DEFAULT NULL`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN entity_verification_endpoint TEXT DEFAULT NULL`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN metadata TEXT DEFAULT NULL`) } catch {}

  // Security triage 2026-04-11 fix 1: tenant role column.
  // Decouples admin authorization from the `plan` billing concept.
  // role = 'admin'  → platform operator (can access /api/v1/admin/* routes)
  // role = 'user'   → regular tenant (default)
  // The AEOESS operator tenant is elevated to 'admin' by the idempotent
  // UPDATE below. The WHERE clause covers both the legacy signal@aeoess.com
  // (pre-2026-05-11) and the current operator@example.com login email — so a
  // fresh DB reset that recreates either tenant still gets admin.
  try { db.exec(`ALTER TABLE tenants ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`) } catch {}
  try {
    db.prepare(`UPDATE tenants SET role = 'admin'
                WHERE email IN ('operator@example.com', 'signal@aeoess.com')
                  AND role != 'admin'`).run()
  } catch {}

  db.exec(`CREATE TABLE IF NOT EXISTS stripe_events (event_id TEXT PRIMARY KEY, processed_at TEXT DEFAULT (datetime('now')))`)

  // ═══════════════════════════════════════
  // Email/password authentication (2026-05-11)
  //
  // password_hash is nullable: existing tenants created via GitHub OAuth
  // or via email-only signup do not have one. They authenticate via
  // existing API keys or GitHub OAuth until they opt into password auth
  // via the forgot-password flow.
  //
  // email_verified is a soft signal — does not gate login. Useful for
  // future-proofing sensitive ops (e.g. plan upgrades).
  // ═══════════════════════════════════════
  try { db.exec(`ALTER TABLE tenants ADD COLUMN password_hash TEXT`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN password_set_at TEXT`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN email_verified_at TEXT`) } catch {}

  // Password reset and email verification tokens.
  // Store SHA-256(token), never the raw token. Single-use (used_at).
  // Expires after 1 hour (password_reset) or 24 hours (email_verification).
  db.exec(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_password_reset_tenant ON password_reset_tokens(tenant_id);

    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      token_hash TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_email_verify_tenant ON email_verification_tokens(tenant_id);
  `)

  // ───────────────────────────────────────
  // 2026-05-11 operator-email rename (must run AFTER email_verified
  // columns have been added above — otherwise the UPDATE references
  // columns that do not exist yet and silently fails in the try/catch).
  //
  // Tima requested moving his login from signal@aeoess.com (public-support
  // alias) to operator@example.com (personal). Preserves tenant_id and every
  // foreign-keyed row (API keys, agents, delegations, receipts). Idempotent:
  // after the first deploy that runs this, no row matches the WHERE clause.
  //
  // email_verified is set to 1 because the rename is itself the verification
  // act (an admin operator authorizing the new address).
  //
  // First attempt (0c56a95) failed with `UNIQUE constraint failed: tenants.email`.
  // A non-operator tenant exists with email=operator@example.com — likely a stray
  // signup that was later soft-deleted (status='deleted'). The unique index
  // does not respect status, so its email still holds the slot. Step 1 below
  // tombstones that stray row's email so step 2 can claim the address.
  //
  // signal@aeoess.com remains the public support address in copy throughout
  // the site and in transactional emails — that is separate from the tenant
  // login email.
  // ───────────────────────────────────────

  // Step 1: tombstone any non-operator row that happens to hold operator@example.com.
  // The operator tenant is identified by the existing email signal@aeoess.com;
  // we only tombstone OTHER rows that block the rename. Idempotent: after the
  // first deploy the WHERE clause matches nothing.
  try {
    db.prepare(`UPDATE tenants
                SET email = 'tombstone-' || substr(id, 1, 8) || '@deleted.local'
                WHERE email = 'operator@example.com'
                  AND id != COALESCE((SELECT id FROM tenants WHERE email = 'signal@aeoess.com'), '')`).run()
  } catch (e: any) {
    console.error('[migration] tombstone of stray tima@ row failed:', e?.message || e)
  }

  // Step 2: the actual operator rename.
  try {
    db.prepare(`UPDATE tenants
                SET email = 'operator@example.com',
                    email_verified = 1,
                    email_verified_at = COALESCE(email_verified_at, datetime('now'))
                WHERE email = 'signal@aeoess.com'`).run()
  } catch (e: any) {
    console.error('[migration] operator-email rename failed:', e?.message || e)
  }
}

// ═══════════════════════════════════════
// Plan Limits
// ═══════════════════════════════════════

export const PLAN_LIMITS = {
  free:       { evaluationsPerMonth: 1000,   maxAgents: 3,    complianceReports: false, sla: false },
  pro:        { evaluationsPerMonth: 50000,  maxAgents: 25,   complianceReports: true,  sla: false },
  enterprise: { evaluationsPerMonth: -1,     maxAgents: -1,   complianceReports: true,  sla: true  },
} as const

export type Plan = keyof typeof PLAN_LIMITS
