// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Consilium hostile panel B5 Finding 3 (MED availability): on a multi-replica boot
// a concurrent replica can hold the write lock while running a large-fleet backfill
// for LONGER than busy_timeout, so BEGIN IMMEDIATE throws SQLITE_BUSY. The prior
// code let that propagate uncaught and CRASH the booting replica. The runner now
// re-checks the migration marker each round and retries a bounded number of times:
//   * winner already committed -> loser reads the marker and returns 'already'
//   * lock held + marker absent -> retry, then a controlled error (fail-closed),
//     NOT an uncaught crash; once the lock frees, a later call applies.
// ══════════════════════════════════════════════════════════════════
import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runIsRootOriginBackfill, IS_ROOT_MIGRATION_ID } from '../../src/db/schema.js'

const dir = mkdtempSync(join(tmpdir(), 'mig-busy-'))
after(() => { try { rmSync(dir, { recursive: true, force: true }) } catch {} })

function freshFileDb(name: string, withMarker: boolean) {
  const p = join(dir, name)
  const db = new Database(p)
  db.exec(`
    CREATE TABLE agents (id TEXT, tenant_id TEXT, agent_id TEXT, is_root INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE delegations (tenant_id TEXT, parent_agent_id TEXT, child_agent_id TEXT, status TEXT);
    CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, status TEXT NOT NULL, applied_at TEXT)
  `)
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES ('r','t','root',0)`).run()
  if (withMarker) db.prepare(`INSERT INTO schema_migrations (id, status, applied_at) VALUES (?, 'complete', '2026-01-01')`).run(IS_ROOT_MIGRATION_ID)
  db.close()
  return p
}
const rootOf = (db: Database.Database) => (db.prepare(`SELECT is_root FROM agents WHERE agent_id='root'`).get() as any).is_root

describe('B5 panel F3: SQLITE_BUSY tolerance on concurrent boot', () => {
  it('a loser whose winner already committed reads the marker and returns already (no crash)', () => {
    const p = freshFileDb('committed.db', true)
    const holder = new Database(p)
    holder.exec('BEGIN IMMEDIATE') // hold the write lock, as a slow concurrent replica would
    try {
      const b = new Database(p)
      // The marker is already 'complete'; the loser must short-circuit via the marker READ, never
      // attempt the write transaction, and never throw SQLITE_BUSY.
      assert.equal(runIsRootOriginBackfill(b, { busyMs: 100, maxAttempts: 2 }), 'already')
      b.close()
    } finally { holder.exec('ROLLBACK'); holder.close() }
  })

  it('a lock held with NO marker: retries then a controlled error (not an uncaught crash), and applies once free', () => {
    const p = freshFileDb('stuck.db', false)
    const holder = new Database(p)
    holder.exec('BEGIN IMMEDIATE')
    const b = new Database(p)
    // While the lock is held and the migration has not run, the runner retries and then surfaces a
    // clear error rather than crashing on the first SQLITE_BUSY. It must NOT apply while locked.
    assert.throws(() => runIsRootOriginBackfill(b, { busyMs: 30, maxAttempts: 2 }), /lock|retries|busy/i)
    assert.equal(rootOf(b), 0, 'nothing applied while the lock was held (fail-safe)')
    // Winner finishes and releases; a later boot attempt now succeeds.
    holder.exec('ROLLBACK'); holder.close()
    assert.equal(runIsRootOriginBackfill(b, { busyMs: 200, maxAttempts: 3 }), 'applied')
    assert.equal(rootOf(b), 1, 'origin root promoted once the lock frees')
    b.close()
  })
})
