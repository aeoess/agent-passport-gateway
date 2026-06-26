// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Regression: trust-profile risk grading must count real deny verdicts
// ══════════════════════════════════════════════════════════════════
// The denial-rate query matched verdict = 'DENY', but the evaluate path stores
// verdicts lowercase ('deny'), so deniedCount was always 0 and every agent
// graded low-risk regardless of how many actions were denied. This inserts a
// 50% deny history and asserts the agent grades above low. Fails before the fix.
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { initDB, getDB } from '../../src/db/schema.js'
import { createTenant } from '../../src/auth/api-keys.js'
import { buildAgentTrustProfile } from '../../src/gateway/trust-profile.js'

describe('trust-profile denial-rate (lowercase verdict)', () => {
  before(() => { initDB(join(tmpdir(), `tp-${randomUUID()}.db`)) })

  it('grades an agent with a 50% deny history above low risk', () => {
    const db = getDB()
    const { tenant } = createTenant({ name: 'tp', email: `tp-${randomUUID()}@example.com` })
    const agentId = 'agent-tp-1'
    const ins = db.prepare(
      `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    for (let i = 0; i < 6; i++) {
      ins.run(randomUUID(), tenant.id, agentId, 'x', '', 's', i < 3 ? 'deny' : 'permit', 'r', 1, '')
    }
    const agent = { tenant_id: tenant.id, agent_id: agentId, status: 'active', created_at: new Date().toISOString() }
    const profile = buildAgentTrustProfile({ db, agent, agentId, computeContinuityScore: () => 0 } as never)
    assert.notEqual((profile as { risk_level: string }).risk_level, 'low', 'a 50% deny rate must not grade low')
  })
})
