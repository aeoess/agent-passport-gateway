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
  `)
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
