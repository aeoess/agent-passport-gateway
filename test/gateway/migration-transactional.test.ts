// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B5 (Consilium): the is_root backfill must be TRANSACTIONAL + versioned.
// The prior gate keyed on column presence, so a crash after the ALTER but before
// the backfill committed would skip the backfill forever -> is_root=0 everywhere
// -> every root 403s. The migration is now gated on a schema_migrations marker
// written in the SAME transaction as the backfill, so an incomplete migration
// re-runs cleanly on the next boot.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { initDB, getDB, runIsRootOriginBackfill, IS_ROOT_MIGRATION_ID } from '../../src/db/schema.js'

// A DB where the ALTER has run (is_root column present, all 0) but the backfill has NOT committed and
// no migration marker exists -- exactly the "crashed after ALTER, before backfill commit" state.
function postAlterPreBackfill() {
  const db = new Database(':memory:')
  db.exec(`
    CREATE TABLE agents (id TEXT, tenant_id TEXT, agent_id TEXT, is_root INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE delegations (tenant_id TEXT, parent_agent_id TEXT, child_agent_id TEXT, status TEXT);
    CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, status TEXT NOT NULL, applied_at TEXT)
  `)
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES ('r','t','root',0)`).run()
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES ('c','t','child',0)`).run()
  db.prepare(`INSERT INTO delegations (tenant_id, parent_agent_id, child_agent_id, status) VALUES ('t','root','child','active')`).run()
  return db
}
const rootOf = (db: Database.Database, a: string) => (db.prepare(`SELECT is_root FROM agents WHERE agent_id = ?`).get(a) as any).is_root
const marker = (db: Database.Database) => db.prepare(`SELECT status FROM schema_migrations WHERE id = ?`).get(IS_ROOT_MIGRATION_ID) as any

describe('B5 transactional is_root migration', () => {
  it('a migration incomplete after the ALTER (no marker) re-runs and completes the backfill', () => {
    const db = postAlterPreBackfill()
    assert.equal(marker(db), undefined, 'precondition: no complete marker (crashed before backfill)')
    assert.equal(rootOf(db, 'root'), 0, 'precondition: backfill did not run yet')
    const r = runIsRootOriginBackfill(db)
    assert.equal(r, 'applied')
    assert.equal(rootOf(db, 'root'), 1, 'origin root promoted on the retry')
    assert.equal(rootOf(db, 'child'), 0)
    assert.equal(marker(db).status, 'complete', 'marker set in the same transaction')
  })

  it('is idempotent: a second run is a no-op and does not re-backfill', () => {
    const db = postAlterPreBackfill()
    assert.equal(runIsRootOriginBackfill(db), 'applied')
    // Manually flip a root back to 0 to prove the second run does NOT touch data once complete.
    db.prepare(`UPDATE agents SET is_root = 0 WHERE agent_id = 'root'`).run()
    assert.equal(runIsRootOriginBackfill(db), 'already')
    assert.equal(rootOf(db, 'root'), 0, 'a completed migration never re-runs the backfill')
  })

  it('a rolled-back migration (marker cleared) re-runs, proving marker-gating not column-gating', () => {
    const db = postAlterPreBackfill()
    runIsRootOriginBackfill(db)
    // Simulate a rollback: clear the marker and reset is_root (the column still exists).
    db.prepare(`DELETE FROM schema_migrations WHERE id = ?`).run(IS_ROOT_MIGRATION_ID)
    db.prepare(`UPDATE agents SET is_root = 0`).run()
    const r = runIsRootOriginBackfill(db)
    assert.equal(r, 'applied', 'no marker -> re-runs even though the column already exists')
    assert.equal(rootOf(db, 'root'), 1)
  })

  it('initDB creates the B5 delegation-graph indexes', () => {
    initDB(':memory:')
    const idx = getDB().prepare(`SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_delegations_%'`).all().map((r: any) => r.name)
    assert.ok(idx.includes('idx_delegations_parent'), 'parent index present')
    assert.ok(idx.includes('idx_delegations_child'), 'child index present')
  })
})
