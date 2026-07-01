// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// R3-2 (round-2 Consilium): agents.status had no DB-level value domain. A typo or
// an endpoint that skips validation could write an out-of-domain status that the
// authz reads (status === 'active', status === 'suspended', etc.) then mis-handle.
// tenants.status/plan already pin their enums with BEFORE INSERT/UPDATE triggers;
// mirror that exactly for agents.status. The legitimate set is every value the code
// writes: active (default/register/thaw), restricted + suspended (posture route),
// revoked (revoke cascade / panic zero_authority), frozen (panic read_only).
// ══════════════════════════════════════════════════════════════════
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../../src/db/schema.js'

const T = 'tnt_status_dom'
before(() => {
  initDB(':memory:')
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(T, 'SD', 'sd@test.local')
})
const insertAgent = (id: string, status: string) =>
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status) VALUES (?, ?, ?, 'pk', ?)`).run(`row-${id}`, T, id, status)

describe('R3-2 agents.status DB-level value domain', () => {
  it('accepts every legitimate status the code writes', () => {
    for (const s of ['active', 'restricted', 'suspended', 'revoked', 'frozen']) {
      assert.doesNotThrow(() => insertAgent(`ok-${s}`, s), `${s} must be allowed`)
    }
  })

  it('[ATTACK] rejects an out-of-domain status on INSERT', () => {
    assert.throws(() => insertAgent('bad-insert', 'Active'), /invalid.*status|CHECK|ABORT/i, 'case variant rejected')
    assert.throws(() => insertAgent('bad-insert2', 'gold'), /invalid.*status|CHECK|ABORT/i)
    assert.throws(() => insertAgent('bad-insert3', ''), /invalid.*status|CHECK|ABORT/i)
  })

  it('[ATTACK] rejects an out-of-domain status on UPDATE', () => {
    insertAgent('upd', 'active')
    assert.throws(() => getDB().prepare(`UPDATE agents SET status = 'deleted' WHERE tenant_id = ? AND agent_id = 'upd'`).run(T), /invalid.*status|CHECK|ABORT/i)
    // a legitimate transition still works
    assert.doesNotThrow(() => getDB().prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = 'upd'`).run(T))
  })
})
