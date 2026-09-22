// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// C1 (Day 217): the in-transaction re-verify inside applyGrantWithReverify must run the FULL bound-chain
// check on parentDelId, not just "is the immediate parentDel row still active". Before this fix, a
// revocation of an ANCESTOR two-or-more hops above the immediate grantor -- landing in the gap between
// the route's autocommit gate read and this transaction's insert -- would NOT have been caught, because
// the old re-check only re-read the single parentDel row. Same B5-F3 two-connection race pattern as
// test/gateway/grant-toctou.test.ts: seed valid state, commit the ancestor revocation via a SECOND
// connection to the same file DB between the gate read and the txn, then run the insert txn and assert
// it throws (mapped to 409 by the route) with no row written.
// ══════════════════════════════════════════════════════════════════
import { describe, it, after } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDB, getDB } from '../../src/db/schema.js'
import { applyGrantWithReverify, AuthorityChangedError, checkBoundAuthorityChain } from '../../src/gateway/enforce.js'

const dir = mkdtempSync(join(tmpdir(), 'c1-toctou-'))
after(() => { try { rmSync(dir, { recursive: true, force: true }) } catch {} })

function freshDb(name: string) {
  const p = join(dir, name)
  initDB(p)
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES ('t','T','t@x.local')`).run()
  return { db, p }
}
const seedAgent = (db: Database.Database, id: string, isRoot = 0, status = 'active') =>
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, 't', ?, 'pk', ?, ?)`).run(`row-${id}`, id, status, isRoot)
const seedDel = (db: Database.Database, id: string, parent: string, child: string, parentDelId: string | null) =>
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, parent_delegation_id) VALUES (?, 't', ?, ?, 'data:read', 'active', 100, ?)`)
    .run(id, parent, child, parentDelId)
const delCount = (db: Database.Database, child: string) => (db.prepare(`SELECT COUNT(*) c FROM delegations WHERE tenant_id='t' AND child_agent_id = ?`).get(child) as any).c

describe('C1 ancestor-level race: the in-txn re-verify walks the FULL bound chain', () => {
  it('an ancestor revoked between gate and commit (two hops above the immediate parentDel) -> throws, no row', () => {
    const { db, p } = freshDb('ancestor-race.db')
    seedAgent(db, 'R', 1, 'active')   // terminal root grantor
    seedAgent(db, 'G1', 0, 'active')  // intermediate grantor
    seedAgent(db, 'G2', 0, 'active')  // immediate grantor for the new grant
    seedAgent(db, 'C', 0, 'active')   // new child
    seedDel(db, 'd-R-G1', 'R', 'G1', null)       // origination
    seedDel(db, 'd-G1-G2', 'G1', 'G2', 'd-R-G1') // G2's inbound, bound to d-R-G1

    // Gate-equivalent read: the chain is fully valid before the race.
    assert.deepEqual(checkBoundAuthorityChain(db, 't', 'd-G1-G2'), { ok: true })

    // A second connection revokes the ANCESTOR (d-R-G1), not the immediate parentDel (d-G1-G2), in the
    // gap between the gate read and the transaction below. The immediate row is still 'active'.
    const other = new Database(p)
    other.prepare(`UPDATE delegations SET status = 'revoked' WHERE id = 'd-R-G1'`).run()
    other.close()

    const opts = {
      tenantId: 't', grantorId: 'G2', childId: 'C', delegationId: 'd-new', scope: 'data:read',
      spendLimit: 5, spendLimitCents: 500, maxDepth: 3, childDepth: 2, wasOrigination: false,
      parentDelId: 'd-G1-G2',
    }
    assert.throws(() => applyGrantWithReverify(db, opts), AuthorityChangedError)
    assert.equal(delCount(db, 'C'), 0, 'no delegation inserted; the ancestor-level revoke was caught inside the write lock')
  })

  it('unchanged ancestor state still commits normally through the full chain re-verify', () => {
    const { db } = freshDb('ancestor-ok.db')
    seedAgent(db, 'R', 1, 'active'); seedAgent(db, 'G1', 0, 'active'); seedAgent(db, 'G2', 0, 'active'); seedAgent(db, 'C', 0, 'active')
    seedDel(db, 'd-R-G1', 'R', 'G1', null)
    seedDel(db, 'd-G1-G2', 'G1', 'G2', 'd-R-G1')
    const opts = {
      tenantId: 't', grantorId: 'G2', childId: 'C', delegationId: 'd-new', scope: 'data:read',
      spendLimit: 5, spendLimitCents: 500, maxDepth: 3, childDepth: 2, wasOrigination: false,
      parentDelId: 'd-G1-G2',
    }
    const r = applyGrantWithReverify(db, opts)
    assert.equal(r.demoted, false)
    assert.equal(delCount(db, 'C'), 1)
    assert.equal((db.prepare(`SELECT parent_delegation_id FROM delegations WHERE id = 'd-new'`).get() as any).parent_delegation_id, 'd-G1-G2', 'the new row is permanently bound to the exact inbound that authorized it')
  })
})
