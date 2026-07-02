// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Re-verification of the B3 F1 replay fix. The table-level UNIQUE(tenant_id,
// receipt_id) is applied only when bilateral_receipts is CREATED. On a DB where
// the table already exists (created before the constraint), CREATE TABLE IF NOT
// EXISTS is a no-op, so the constraint is silently absent and concurrent replays
// on a multi-replica deployment can store multiple 'attested' rows. A CREATE
// UNIQUE INDEX IF NOT EXISTS applies to an existing table, so the backstop holds
// on upgraded DBs too.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { initDB, getDB } from '../../src/db/schema.js'

const UNIQ_DDL = `CREATE UNIQUE INDEX IF NOT EXISTS uq_bilateral_receipts_tenant_receipt ON bilateral_receipts(tenant_id, receipt_id)`
const insertReceipt = (db: Database.Database, id: string, tenant: string, receiptId: string) =>
  db.prepare(`INSERT INTO bilateral_receipts (id, tenant_id, receipt_id, requesting_agent_id, serving_agent_id, status, requesting_sig_valid, serving_sig_valid, outcome_consistent, timing_valid, payload) VALUES (?, ?, ?, 'a', 'b', 'attested', 1, 1, 1, 1, '{}')`)
    .run(id, tenant, receiptId)

describe('B3 F1 re-verification: replay backstop is a DB-level unique index', () => {
  it('initDB creates the uq_bilateral_receipts_tenant_receipt unique index', () => {
    initDB(':memory:')
    const idx = getDB().prepare(`SELECT name FROM sqlite_master WHERE type='index' AND name='uq_bilateral_receipts_tenant_receipt'`).get() as any
    assert.ok(idx, 'the replay-backstop unique index must exist after initDB')
  })

  it('the unique index rejects a duplicate (tenant_id, receipt_id) but allows the same receipt_id across tenants', () => {
    initDB(':memory:')
    const db = getDB()
    insertReceipt(db, 'r1', 't1', 'rid-1')
    assert.throws(() => insertReceipt(db, 'r2', 't1', 'rid-1'), /UNIQUE/, 'a replay within a tenant is rejected at the DB level')
    assert.doesNotThrow(() => insertReceipt(db, 'r3', 't2', 'rid-1'), 'the same receipt_id in a DIFFERENT tenant is allowed')
  })

  it('[UPGRADED DB] the unique index applies to a PRE-EXISTING table (created without the constraint)', () => {
    // Simulate a DB provisioned before the constraint existed: the table with NO unique.
    const db = new Database(':memory:')
    db.exec(`CREATE TABLE bilateral_receipts (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, receipt_id TEXT NOT NULL,
      requesting_agent_id TEXT, serving_agent_id TEXT, status TEXT,
      requesting_sig_valid INTEGER, serving_sig_valid INTEGER, outcome_consistent INTEGER,
      timing_valid INTEGER, payload TEXT, created_at TEXT DEFAULT (datetime('now')))`)
    // Before the migration index, a duplicate would be accepted (the table alone does not protect):
    insertReceipt(db, 'p1', 't1', 'rid-x')
    assert.doesNotThrow(() => insertReceipt(db, 'p2-tmp', 't1', 'rid-dupcheck'), 'sanity: table without index accepts distinct ids')
    // Apply the remediation's migration DDL (the exact statement initDB runs) to the EXISTING table.
    db.exec(UNIQ_DDL)
    // Now a duplicate (tenant_id, receipt_id) is rejected even though the table pre-existed.
    assert.throws(() => insertReceipt(db, 'p3', 't1', 'rid-x'), /UNIQUE/, 'the index protects the upgraded table')
    db.close()
  })
})
