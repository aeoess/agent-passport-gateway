// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R5-1 (final Consilium): cross-process TOCTOU on POST /delegations. The grant gate
// reads grantor authority (status, is_root, the parent delegation) as autocommit
// reads OUTSIDE the insert transaction. In-process the handler is fully synchronous
// (no race), but ACROSS processes (Railway rolling restart, multi-replica) a
// demotion / suspension / revocation can commit between the gate read and the insert,
// and the txn never re-reads the grantor, so a just-demoted root originates once on a
// stale flag. Fix: apply the grant inside a BEGIN IMMEDIATE transaction that RE-VERIFIES
// authority against the CURRENT rows at the top; on a mismatch throw AuthorityChangedError
// (the route maps it to 409). BEGIN IMMEDIATE takes the write lock up front, so the
// re-read is serialized against any concurrent authority-change commit.
//
// These unit-test the txn body directly (deterministic), using the B5-F3 two-connection
// pattern: seed valid state, commit the authority change via a SECOND connection to the
// same file DB, then run the insert txn and assert it throws with no row written.
// ══════════════════════════════════════════════════════════════════
import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDB, getDB } from '../../src/db/schema.js'
import { applyGrantWithReverify, AuthorityChangedError } from '../../src/gateway/enforce.js'

const dir = mkdtempSync(join(tmpdir(), 'toctou-'))
after(() => { try { rmSync(dir, { recursive: true, force: true }) } catch {} })

function freshDb(name: string) {
  const p = join(dir, name)
  initDB(p) // full schema (triggers, CHECKs) on the file DB
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES ('t','T','t@x.local')`).run()
  return { db, p }
}
const seedAgent = (db: Database.Database, id: string, isRoot = 0, status = 'active') =>
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, 't', ?, 'pk', ?, ?)`).run(`row-${id}`, id, status, isRoot)
const seedDel = (db: Database.Database, id: string, parent: string, child: string, status = 'active') =>
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit) VALUES (?, 't', ?, ?, 'commerce:checkout', ?, 100)`).run(id, parent, child, status)
const delCount = (db: Database.Database, child: string) => (db.prepare(`SELECT COUNT(*) c FROM delegations WHERE tenant_id='t' AND child_agent_id = ?`).get(child) as any).c
const opts = (over: Record<string, unknown> = {}) => ({
  tenantId: 't', grantorId: 'G', childId: 'C', delegationId: 'd-new', scope: 'commerce:checkout',
  spendLimit: 5, spendLimitCents: 500, maxDepth: 3, childDepth: 0, wasOrigination: true, parentDelId: null, ...over,
})

describe('R5-1 in-txn authority re-verify (cross-process TOCTOU)', () => {
  it('[TOCTOU] a root demoted between gate and commit -> throws, no delegation row', () => {
    const { db, p } = freshDb('demote.db')
    seedAgent(db, 'G', 1, 'active'); seedAgent(db, 'C', 0)
    const other = new Database(p); other.prepare(`UPDATE agents SET is_root = 0 WHERE tenant_id='t' AND agent_id='G'`).run(); other.close()
    assert.throws(() => applyGrantWithReverify(db, opts()), AuthorityChangedError)
    assert.equal(delCount(db, 'C'), 0, 'no delegation inserted for a just-demoted root')
  })

  it('[TOCTOU] a grantor suspended between gate and commit -> throws, no row', () => {
    const { db, p } = freshDb('suspend.db')
    seedAgent(db, 'G', 1, 'active'); seedAgent(db, 'C', 0)
    const other = new Database(p); other.prepare(`UPDATE agents SET status = 'suspended' WHERE tenant_id='t' AND agent_id='G'`).run(); other.close()
    assert.throws(() => applyGrantWithReverify(db, opts()), AuthorityChangedError)
    assert.equal(delCount(db, 'C'), 0)
  })

  it('[TOCTOU] the parentDel revoked between gate and commit (narrowing branch) -> throws, no row', () => {
    const { db, p } = freshDb('revoke.db')
    seedAgent(db, 'R', 1, 'active'); seedAgent(db, 'G', 0, 'active'); seedAgent(db, 'C', 0)
    seedDel(db, 'd-inb', 'R', 'G', 'active') // G has a live inbound -> narrowing branch at gate time
    const other = new Database(p); other.prepare(`UPDATE delegations SET status = 'revoked' WHERE id='d-inb'`).run(); other.close()
    assert.throws(() => applyGrantWithReverify(db, opts({ grantorId: 'G', wasOrigination: false, parentDelId: 'd-inb' })), AuthorityChangedError)
    assert.equal(delCount(db, 'C'), 0)
  })

  it('unchanged state commits normally (no double-deny of a legitimate grant)', () => {
    const { db } = freshDb('ok.db')
    seedAgent(db, 'G', 1, 'active'); seedAgent(db, 'C', 0)
    const r = applyGrantWithReverify(db, opts())
    assert.equal(delCount(db, 'C'), 1)
    assert.equal(r.demoted, false)
  })

  it('a legitimate grant to a root CHILD still demotes (reports demoted=true)', () => {
    const { db } = freshDb('childdemote.db')
    seedAgent(db, 'G', 1, 'active'); seedAgent(db, 'C', 1, 'active') // child is itself a designated root
    const r = applyGrantWithReverify(db, opts())
    assert.equal(r.demoted, true)
    assert.equal((db.prepare(`SELECT is_root FROM agents WHERE tenant_id='t' AND agent_id='C'`).get() as any).is_root, 0)
  })
})
