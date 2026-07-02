// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// B1 (Consilium): is_root is an ORIGIN property, derived from history.
// The prior backfill promoted "active outbound AND no active inbound", which
//   - OVER-promotes a severed child (revoked inbound + active outbound) into a
//     fresh-budget root, and
//   - UNDER-promotes an idle legitimate root (no grants yet) -> is_root=0 -> 403.
// Correct rule: is_root=1 iff the agent has NEVER appeared as child_agent_id in
// delegations under ANY status. Ever-inbound (even revoked/expired) => is_root=0.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { backfillAgentRoots } from '../../src/db/schema.js'

function seedDb() {
  const db = new Database(':memory:')
  db.exec(`
    CREATE TABLE agents (id TEXT, tenant_id TEXT, agent_id TEXT, is_root INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE delegations (tenant_id TEXT, parent_agent_id TEXT, child_agent_id TEXT, status TEXT)
  `)
  const A = db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES (?, 't', ?, 0)`)
  const D = db.prepare(`INSERT INTO delegations (tenant_id, parent_agent_id, child_agent_id, status) VALUES ('t', ?, ?, ?)`)
  return { db, A, D }
}
const rootOf = (db: Database.Database, a: string) => (db.prepare(`SELECT is_root FROM agents WHERE agent_id = ?`).get(a) as any).is_root

describe('B1 origin is_root backfill', () => {
  it('a SEVERED child (revoked inbound + active outbound) is NOT promoted to root', () => {
    const { db, A, D } = seedDb()
    A.run('rSev', 'severed')  // was delegated to (revoked), then grants onward
    A.run('rGChild', 'gchild')
    D.run('someRoot', 'severed', 'revoked')   // severed HAS appeared as child (revoked)
    D.run('severed', 'gchild', 'active')       // and now grants onward
    backfillAgentRoots(db)
    assert.equal(rootOf(db, 'severed'), 0, 'a severed child must never become a fresh-budget root')
  })

  it('an IDLE legitimate root (never a child, has not granted yet) IS promoted', () => {
    const { db, A } = seedDb()
    A.run('rIdle', 'idleRoot')   // exists, no delegations at all
    backfillAgentRoots(db)
    assert.equal(rootOf(db, 'idleRoot'), 1, 'an idle origin root must be preserved')
  })

  it('an agent with an ACTIVE inbound is not a root', () => {
    const { db, A, D } = seedDb()
    A.run('rMid', 'mid')
    D.run('root', 'mid', 'active')
    backfillAgentRoots(db)
    assert.equal(rootOf(db, 'mid'), 0)
  })

  it('a self-delegation A->A makes A a child, so A is NOT a root', () => {
    const { db, A, D } = seedDb()
    A.run('rSelf', 'selfy')
    D.run('selfy', 'selfy', 'active')
    backfillAgentRoots(db)
    assert.equal(rootOf(db, 'selfy'), 0, 'self-delegation makes A appear as child_agent_id')
  })

  it('an active grantor that was never a child IS a root; a pure receiver is not', () => {
    const { db, A, D } = seedDb()
    A.run('rGr', 'grantor'); A.run('rRc', 'receiver')
    D.run('grantor', 'receiver', 'active')
    backfillAgentRoots(db)
    assert.equal(rootOf(db, 'grantor'), 1)
    assert.equal(rootOf(db, 'receiver'), 0)
  })

  it('expired/pending/suspended inbound also counts as ever-a-child (not a root)', () => {
    const { db, A, D } = seedDb()
    for (const s of ['expired', 'pending', 'suspended']) {
      const a = `child_${s}`
      A.run(`r_${s}`, a)
      D.run('root', a, s)
    }
    backfillAgentRoots(db)
    for (const s of ['expired', 'pending', 'suspended']) assert.equal(rootOf(db, `child_${s}`), 0, `${s} inbound counts`)
  })

  it('idempotent: a second run promotes nobody new', () => {
    const { db, A } = seedDb()
    A.run('r1', 'a1'); A.run('r2', 'a2')
    assert.equal(backfillAgentRoots(db), 2)
    assert.equal(backfillAgentRoots(db), 0)
  })

  it('per-tenant: a root in tenant t does not leak to a same-named child in another tenant', () => {
    const { db } = seedDb()
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES ('x1','t','shared',0)`).run()
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, is_root) VALUES ('x2','u','shared',0)`).run()
    db.prepare(`INSERT INTO delegations (tenant_id, parent_agent_id, child_agent_id, status) VALUES ('u','root','shared','active')`).run()
    backfillAgentRoots(db)
    assert.equal((db.prepare(`SELECT is_root FROM agents WHERE tenant_id='t' AND agent_id='shared'`).get() as any).is_root, 1)
    assert.equal((db.prepare(`SELECT is_root FROM agents WHERE tenant_id='u' AND agent_id='shared'`).get() as any).is_root, 0)
  })
})
