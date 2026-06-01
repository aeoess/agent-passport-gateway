// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-C2 layer (b): post-flight governance automations.
//
// Tests: an automation acts ONLY inside its narrowed delegation; each emits a
// signed self-receipt; the revocation-recommendation automation calls
// previewCascade ONLY and never revokes; evidence-bundle composition is
// read-only; policy-drift recommends only; integration-health escalates a summary.

import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
// Route the email queue to a temp file so the alert-routing automation's
// queue-first sendEmail does not attempt to write to /data in tests.
process.env.EMAIL_QUEUE_PATH = join(tmpdir(), `gc2-email-queue-${process.pid}.jsonl`)
import { initDB, getDB } from '../src/db/schema.js'
import { initLineageTables } from '../src/gateway/lineage.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import {
  routeAlert,
  generateEvidenceBundle,
  detectPolicyDrift,
  recommendRevocation,
  checkIntegrationHealth,
} from '../src/gateway/automations/index.js'
import {
  getAutomationDelegation,
  automationMayAct,
  emitSelfReceipt,
  AUTOMATION_SCOPE,
  GOVERNANCE_ROOT_SCOPES,
  _resetGovernanceForTest,
} from '../src/gateway/automations/governance-delegation.js'

const TENANT = 'tenant-automation-test'

before(() => {
  initDB(':memory:')
  initLineageTables()
  initGatewayIdentity()
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`)
    .run(TENANT, 'Automation Test', 'auto@example.com')
})

beforeEach(() => {
  _resetGovernanceForTest()
  const db = getDB()
  db.exec(`DELETE FROM policy_evaluations; DELETE FROM delegations;`)
})

function seedEvaluations(agentId: string, permits: number, denials: number) {
  const db = getDB()
  const stmt = db.prepare(
    `INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
  let i = 0
  for (; i < permits; i++) stmt.run(`e-p-${agentId}-${i}`, TENANT, agentId, 'tool:x', '', 'tool:x', 'permit', 'ok', 1)
  for (let j = 0; j < denials; j++, i++) stmt.run(`e-d-${agentId}-${j}`, TENANT, agentId, 'tool:x', '', 'tool:x', 'deny', 'no', 1)
}

function seedDelegation(parent: string, child: string, scope = 'tool:x') {
  const db = getDB()
  db.prepare(
    `INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status) VALUES (?, ?, ?, ?, ?, 'active')`,
  ).run(`del-${parent}-${child}`, TENANT, parent, child, scope)
}

describe('G-C2 automations - narrowed delegation harness', () => {
  it('each automation narrows to exactly its single benign scope (subset of the root)', async () => {
    for (const automation of Object.keys(AUTOMATION_SCOPE) as Array<keyof typeof AUTOMATION_SCOPE>) {
      const del = await getAutomationDelegation(automation)
      assert.ok(del, `expected a delegation for ${automation}`)
      assert.equal(del!.scope, AUTOMATION_SCOPE[automation])
      // The narrowed scope must be one of the governance root scopes (monotonic
      // narrowing: never widens past the root).
      assert.ok(GOVERNANCE_ROOT_SCOPES.includes(del!.scope), `${del!.scope} not in governance root`)
    }
  })

  it('automationMayAct refuses an action outside the automation scope', async () => {
    const del = await getAutomationDelegation('alert_routing')
    assert.ok(del)
    assert.equal(automationMayAct(del!, 'governance:route_alert'), true)
    // Trying to act as a different (even benign) verb is refused - no widening.
    assert.equal(automationMayAct(del!, 'governance:recommend'), false)
    assert.equal(automationMayAct(del!, 'revocation:execute'), false)
  })

  it('emits a gateway-signed self-receipt scoped to the delegation', async () => {
    const del = await getAutomationDelegation('alert_routing')
    assert.ok(del)
    const receipt = emitSelfReceipt({ delegation: del!, action: 'route_alert', payload: { a: 1 } })
    assert.equal(receipt.automation, 'alert_routing')
    assert.equal(receipt.scope, 'governance:route_alert')
    assert.equal(receipt.delegationId, del!.delegationId)
    // Signature is a compact JWS (header.payload.signature).
    assert.equal(receipt.signature.split('.').length, 3)
  })
})

describe('G-C2 automations - alert routing summarizes, never auto-acts', () => {
  it('routes within its delegation and returns a signed self-receipt', async () => {
    const result = await routeAlert({
      tenantId: TENANT,
      recipientEmail: 'ops@customer',
      recipientName: 'Ops',
      signal: 'integration_health:degraded',
      severity: 'critical',
      summary: 'No throughput in the last hour.',
      recommendation: 'Check the connector.',
    })
    assert.equal(result.acted, true)
    assert.equal(result.automation, 'alert_routing')
    assert.ok(result.selfReceipt, 'self-receipt required')
    assert.equal(result.selfReceipt!.scope, 'governance:route_alert')
  })
})

describe('G-C2 automations - evidence bundle is read-only composition', () => {
  it('composes a bundle from audit serializers without mutating evidence', async () => {
    seedEvaluations('agent-ev', 3, 1)
    const before = getDB().prepare(`SELECT COUNT(*) AS c FROM policy_evaluations WHERE tenant_id = ?`).get(TENANT) as any
    const from = '2000-01-01T00:00:00Z'
    const to = '2999-01-01T00:00:00Z'
    const result = await generateEvidenceBundle({ tenantId: TENANT, from, to })
    assert.equal(result.acted, true)
    assert.ok(result.output)
    assert.equal(result.output!.recordCount, 4)
    assert.ok(result.output!.jsonl.length > 0)
    assert.ok(result.output!.bundleHash.length === 64)
    // Evidence row count is unchanged: composition is read-only.
    const after = getDB().prepare(`SELECT COUNT(*) AS c FROM policy_evaluations WHERE tenant_id = ?`).get(TENANT) as any
    assert.equal(after.c, before.c)
    assert.ok(result.selfReceipt)
  })
})

describe('G-C2 automations - policy drift recommends only', () => {
  it('surfaces a high-drift agent with a recommendation, never an action', async () => {
    seedEvaluations('agent-drift', 2, 8) // 80% denial rate over 10 evals
    const result = await detectPolicyDrift({ tenantId: TENANT, windowHours: 24, minEvaluations: 5 })
    assert.equal(result.acted, true)
    const signals = result.output!
    const drift = signals.find(s => s.agentId === 'agent-drift')
    assert.ok(drift, 'expected a drift signal for the high-denial agent')
    assert.equal(drift!.drift, 'high')
    assert.ok(drift!.recommendation.length > 0)
    // No policy change happened: the agent/delegation tables are untouched by the
    // recommendation. (We seeded no delegation; nothing to mutate, and nothing did.)
    assert.ok(result.selfReceipt)
  })

  it('ignores agents below the minimum-evaluations floor (no single-sample noise)', async () => {
    seedEvaluations('agent-quiet', 0, 2) // only 2 evals, below floor 5
    const result = await detectPolicyDrift({ tenantId: TENANT, windowHours: 24, minEvaluations: 5 })
    const signals = result.output!
    assert.equal(signals.find(s => s.agentId === 'agent-quiet'), undefined)
  })
})

describe('G-C2 automations - revocation RECOMMENDATION calls previewCascade ONLY, never revokes', () => {
  it('returns a read-only preview with recommended actions and willExecute=false', async () => {
    // Build a small delegation tree: root -> child.
    seedDelegation('root-agent', 'child-agent')
    const result = await recommendRevocation({ tenantId: TENANT, targetType: 'agent', targetId: 'root-agent' })
    assert.equal(result.acted, true)
    const rec = result.output!
    assert.equal(rec.willExecute, false)
    assert.ok(Array.isArray(rec.recommendedActions))
    assert.ok(rec.preview.totalRevoked >= 1, 'preview should reach the child delegation')
    // CRITICAL: the recommendation must NOT have revoked anything. The delegation
    // is still active and the subject epoch is unchanged (no bumpEpoch/panicFreeze).
    const del = getDB().prepare(`SELECT status FROM delegations WHERE tenant_id = ? AND parent_agent_id = ?`).get(TENANT, 'root-agent') as any
    assert.equal(del.status, 'active', 'recommendation must not revoke the delegation')
    const epochRow = getDB().prepare(`SELECT value FROM gateway_config WHERE key = ?`).get(`epoch:agent:${TENANT}:root-agent`) as any
    assert.equal(epochRow, undefined, 'recommendation must not bump any epoch (no silent revoke)')
    assert.ok(result.selfReceipt)
  })
})

describe('G-C2 automations - integration health escalates a summary', () => {
  it('reports degraded with an escalation when there is no recent throughput', async () => {
    // No evaluations seeded in the window => degraded.
    const result = await checkIntegrationHealth({ tenantId: TENANT, integrationNames: ['slack', 'pagerduty'], windowHours: 1 })
    assert.equal(result.acted, true)
    assert.equal(result.output!.overall, 'degraded')
    assert.ok(result.output!.escalation)
    assert.ok(result.selfReceipt)
  })

  it('reports healthy when there is recent throughput', async () => {
    seedEvaluations('agent-live', 5, 0)
    const result = await checkIntegrationHealth({ tenantId: TENANT, integrationNames: ['slack'], windowHours: 1 })
    assert.equal(result.output!.overall, 'healthy')
    assert.equal(result.output!.escalation, null)
  })
})
