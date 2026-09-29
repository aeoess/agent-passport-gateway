// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - tests
// ══════════════════════════════════════════════════════════════════
// Covers the mandated cases:
//   - signed delivery verifies (HMAC + freshness)
//   - replay is rejected (nonce reuse and stale timestamp)
//   - retry + dead-letter work (failing sink exhausts and dead-letters; a
//     recovered sink redelivers from the dead-letter log)
//   - OCSF format is valid (structural validator passes on every event type)
//   - identity offboard maps to a revoke (agent + delegations cascade-revoked)
// plus: schema versioning, subscription filtering, SSRF rejection at register,
// OTLP/OCSF wrapping, chat/ticket/email adapter shaping.
//
// PROOF / CLAIMS BOX
// Supports: a delivered envelope whose HMAC and timestamp verify shows the
//   gateway emitted exactly those bytes within the freshness window. An
//   offboard that maps to a revoke shows the agent's delegations were set
//   revoked in the gateway's own store.
// Does NOT support: any claim about what the customer's downstream does after
//   receiving the envelope. Reaction logic is customer-run; the gateway emits.
// ══════════════════════════════════════════════════════════════════

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'

import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'

import {
  buildConnectorEvent,
  validateConnectorEvent,
  CONNECTOR_SCHEMA_VERSION,
  type ConnectorEvent,
  type ConnectorEventType,
} from '../src/notifications/connectors/event-schema.js'
import {
  buildSignedWebhook,
  verifyWebhookSignature,
  makeWebhookSink,
  HDR_NONCE,
  HDR_TIMESTAMP,
  type SignedWebhookRequest,
} from '../src/notifications/connectors/webhook-sink.js'
import {
  checkAndRecordNonce,
  registerEndpoint,
  listEndpoints,
} from '../src/notifications/connectors/subscription-store.js'
import {
  ConnectorDispatcher,
  deadLetterCount,
  listDeadLetters,
} from '../src/notifications/connectors/dispatcher.js'
import { initConnectorTables } from '../src/notifications/connectors/init.js'
import { toOcsf, validateOcsf } from '../src/notifications/connectors/ocsf.js'
import { toOtlpLogs } from '../src/notifications/connectors/adapters/otel-ocsf.js'
import { toSlackMessage } from '../src/notifications/connectors/adapters/slack.js'
import { toTeamsMessage } from '../src/notifications/connectors/adapters/teams.js'
import { toJiraIssue } from '../src/notifications/connectors/adapters/jira.js'
import { toServiceNowIncident } from '../src/notifications/connectors/adapters/servicenow.js'
import { makeEmailSink } from '../src/notifications/connectors/adapters/email-sink.js'
import { makePagerDutySink, toPagerDutyEvent } from '../src/notifications/connectors/adapters/pagerduty.js'
import {
  verifyInboundOffboard,
  applyOffboard,
  resolveTargetFromOffboard,
  type NormalizedOffboard,
} from '../src/notifications/connectors/identity-bridge.js'
import { createHmac } from 'node:crypto'

const TENANT = 'tenant-c1-test'

function sampleEvent(eventType: ConnectorEventType = 'batch_committed'): ConnectorEvent {
  return buildConnectorEvent({
    eventType,
    eventId: `evt-${randomUUID()}`,
    tenantId: TENANT,
    data: { hello: 'world', severity: 'high' },
  })
}

before(() => {
  // In-memory DB so the suite does not touch a real gateway.db.
  initDB(':memory:')
  initGatewayIdentity()
  initConnectorTables()
})

// ── versioned event schema ────────────────────────────────────────

describe('connectors - versioned event schema', () => {
  it('stamps the current schema_version and validates', () => {
    const e = sampleEvent()
    assert.equal(e.schema_version, CONNECTOR_SCHEMA_VERSION)
    assert.equal(validateConnectorEvent(e), null)
  })

  it('rejects an envelope with an unknown schema_version', () => {
    const e = { ...sampleEvent(), schema_version: 'connector_event_v999' }
    assert.match(String(validateConnectorEvent(e)), /unsupported schema_version/)
  })
})

// ── signed delivery verifies ──────────────────────────────────────

describe('connectors - signed webhook delivery verifies', () => {
  it('a freshly signed webhook verifies against its secret', () => {
    const secret = 'shared-secret-abcdef0123456789'
    const event = sampleEvent('alert')
    const req = buildSignedWebhook({ url: 'https://hook.example/in', secret, event })
    const result = verifyWebhookSignature({ secret, body: req.body, headers: req.headers })
    assert.equal(result.ok, true, result.reason)
  })

  it('rejects a tampered body', () => {
    const secret = 'shared-secret-abcdef0123456789'
    const event = sampleEvent('alert')
    const req = buildSignedWebhook({ url: 'https://hook.example/in', secret, event })
    const tampered = req.body.replace('world', 'evil')
    const result = verifyWebhookSignature({ secret, body: tampered, headers: req.headers })
    assert.equal(result.ok, false)
    assert.match(String(result.reason), /HMAC signature mismatch/)
  })

  it('rejects the wrong secret', () => {
    const event = sampleEvent('alert')
    const req = buildSignedWebhook({ url: 'https://hook.example/in', secret: 'right-secret-000000000000', event })
    const result = verifyWebhookSignature({ secret: 'wrong-secret-111111111111', body: req.body, headers: req.headers })
    assert.equal(result.ok, false)
  })

  it('carries a gateway JWS and key id for JWKS-based verification', () => {
    const req = buildSignedWebhook({ url: 'https://hook.example/in', secret: 'secret-aaaaaaaaaaaaaaaa', event: sampleEvent() })
    assert.ok(req.headers['x-aeoess-connector-jws'].split('.').length === 3, 'JWS compact has three parts')
    assert.equal(req.headers['x-aeoess-connector-kid'], 'gateway-v1')
  })
})

// ── replay is rejected ────────────────────────────────────────────

describe('connectors - replay protection', () => {
  it('rejects a reused nonce inside the window', () => {
    const now = Date.now()
    const first = checkAndRecordNonce({ scope: 'test', nonce: 'nonce-aaaaaaaa', timestampMs: now, nowMs: now })
    assert.equal(first.ok, true)
    const replay = checkAndRecordNonce({ scope: 'test', nonce: 'nonce-aaaaaaaa', timestampMs: now, nowMs: now })
    assert.equal(replay.ok, false)
    assert.match(String(replay.reason), /replay/)
  })

  it('rejects a stale timestamp outside the window', () => {
    const now = Date.now()
    const stale = checkAndRecordNonce({ scope: 'test', nonce: 'nonce-bbbbbbbb', timestampMs: now - 10 * 60 * 1000, nowMs: now })
    assert.equal(stale.ok, false)
    assert.match(String(stale.reason), /replay window/)
  })

  it('a captured signed webhook fails freshness once stale', () => {
    const secret = 'secret-cccccccccccccccc'
    const t0 = Date.now() - 10 * 60 * 1000
    const req = buildSignedWebhook({ url: 'https://hook.example/in', secret, event: sampleEvent(), nowMs: t0 })
    const result = verifyWebhookSignature({ secret, body: req.body, headers: req.headers, nowMs: Date.now() })
    assert.equal(result.ok, false)
    assert.match(String(result.reason), /tolerance/)
  })

  it('the same nonce in a different scope is not a false replay', () => {
    const now = Date.now()
    const a = checkAndRecordNonce({ scope: 'scopeA', nonce: 'nonce-shared01', timestampMs: now, nowMs: now })
    const b = checkAndRecordNonce({ scope: 'scopeB', nonce: 'nonce-shared01', timestampMs: now, nowMs: now })
    assert.equal(a.ok, true)
    assert.equal(b.ok, true)
  })
})

// ── retry + dead-letter ───────────────────────────────────────────

describe('connectors - retry and dead-letter', () => {
  it('retries a transient failure then succeeds', async () => {
    let attempts = 0
    const sink = async () => {
      attempts++
      if (attempts < 3) throw new Error('transient')
    }
    const dispatcher = new ConnectorDispatcher({ waitFn: async () => {} })
    const result = await dispatcher.deliver(TENANT, 'webhook', sink, sampleEvent())
    assert.equal(result.delivered, true)
    assert.equal(result.attempts, 3)
    assert.equal(result.deadLetterId, null)
  })

  it('exhausts retries and dead-letters a persistent failure', async () => {
    const before = deadLetterCount(TENANT)
    const sink = async () => {
      throw new Error('always down')
    }
    const dispatcher = new ConnectorDispatcher({ waitFn: async () => {} })
    const event = sampleEvent('alert')
    const result = await dispatcher.deliver(TENANT, 'webhook', sink, event, 'endpoint-1')
    assert.equal(result.delivered, false)
    assert.equal(result.attempts, 4) // DEFAULT_RETRY_POLICY.maxAttempts
    assert.ok(result.deadLetterId)
    assert.equal(deadLetterCount(TENANT), before + 1)
    const letters = listDeadLetters(TENANT)
    assert.ok(letters.some((l) => l.event_id === event.event_id))
  })

  it('redelivers a dead letter once the sink recovers', async () => {
    const failing = async () => {
      throw new Error('down')
    }
    const dispatcher = new ConnectorDispatcher({ waitFn: async () => {} })
    const event = sampleEvent('revocation')
    const dead = await dispatcher.deliver(TENANT, 'internal-http', failing, event)
    assert.ok(dead.deadLetterId)

    let delivered = false
    const recovered = async () => {
      delivered = true
    }
    const redeliver = await dispatcher.redeliver(TENANT, dead.deadLetterId!, recovered)
    assert.ok(redeliver)
    assert.equal(redeliver!.delivered, true)
    assert.equal(delivered, true)
    // The redelivered letter is no longer in the undrained list.
    assert.ok(!listDeadLetters(TENANT).some((l) => l.id === dead.deadLetterId))
  })

  it('uses exponential backoff with the G-A1 default policy', async () => {
    const waits: number[] = []
    let n = 0
    const sink = async () => {
      n++
      throw new Error('down')
    }
    const dispatcher = new ConnectorDispatcher({ waitFn: async (ms) => { waits.push(ms) } })
    await dispatcher.deliver(TENANT, 'webhook', sink, sampleEvent())
    // base 200, attempts 1..3 wait before the 4th: 200, 400, 800
    assert.deepEqual(waits, [200, 400, 800])
  })
})

// ── webhook sink end-to-end via dispatcher ────────────────────────

describe('connectors - webhook sink through dispatcher', () => {
  it('delivers a signed envelope that the receiver verifies', async () => {
    const secret = 'secret-dddddddddddddddd'
    let captured: SignedWebhookRequest | null = null
    const httpPost = async (req: SignedWebhookRequest) => {
      captured = req
      return { status: 200 }
    }
    const sink = makeWebhookSink({ url: 'https://hook.example/in', secret, httpPost })
    const dispatcher = new ConnectorDispatcher({ waitFn: async () => {} })
    const result = await dispatcher.deliver(TENANT, 'webhook', sink, sampleEvent())
    assert.equal(result.delivered, true)
    assert.ok(captured)
    const verify = verifyWebhookSignature({ secret, body: captured!.body, headers: captured!.headers })
    assert.equal(verify.ok, true, verify.reason)
    // Nonce + timestamp headers are present for the receiver's replay window.
    assert.ok(captured!.headers[HDR_NONCE])
    assert.ok(captured!.headers[HDR_TIMESTAMP])
  })
})

// ── OCSF format is valid ──────────────────────────────────────────

describe('connectors - OCSF formatting', () => {
  const types: ConnectorEventType[] = [
    'batch_committed',
    'revocation',
    'alert',
    'approval_requested',
    'ticket_requested',
    'identity_offboard',
    'connector_test',
  ]
  for (const t of types) {
    it(`produces a valid OCSF record for ${t}`, () => {
      const record = toOcsf(sampleEvent(t))
      assert.equal(validateOcsf(record), null)
    })
  }

  it('maps identity offboard to the IAM Account Change class', () => {
    const record = toOcsf(sampleEvent('identity_offboard'))
    assert.equal(record.class_uid, 3001)
    assert.equal(record.category_uid, 3)
  })

  it('carries the batch root and counts but no leaves in unmapped', () => {
    const event = buildConnectorEvent({
      eventType: 'batch_committed',
      eventId: 'evt-batch',
      tenantId: TENANT,
      batch: {
        batchId: 'b1',
        merkleRoot: 'sha256:deadbeef',
        epoch: 7,
        previousBatchId: null,
        previousMerkleRoot: null,
        receiptCount: 42,
        committedAt: new Date().toISOString(),
        summary: { total: 42, byVerdict: { permit: 40, deny: 2 }, byActionType: { read: 42 } },
      },
    })
    const record = toOcsf(event)
    const batch = (record.unmapped as any).batch
    assert.equal(batch.merkle_root, 'sha256:deadbeef')
    assert.equal(batch.receipt_count, 42)
    assert.ok(!('leaves' in batch), 'no granular leaves in the OCSF record')
  })

  it('wraps an OCSF record into an OTLP logs payload', () => {
    const otlp = toOtlpLogs(sampleEvent('alert')) as any
    assert.ok(Array.isArray(otlp.resourceLogs))
    const logRecord = otlp.resourceLogs[0].scopeLogs[0].logRecords[0]
    const ocsfStr = logRecord.body.kvlistValue.values.find((v: any) => v.key === 'ocsf').value.stringValue
    assert.equal(validateOcsf(JSON.parse(ocsfStr)), null)
  })
})

// ── chat / ticket / email adapter shaping ─────────────────────────

describe('connectors - adapter shaping', () => {
  it('slack message has header + section blocks', () => {
    const msg = toSlackMessage(sampleEvent('approval_requested')) as any
    assert.equal(msg.blocks[0].type, 'header')
    assert.equal(msg.blocks[1].type, 'section')
  })

  it('teams message is a MessageCard', () => {
    const msg = toTeamsMessage(sampleEvent('alert')) as any
    assert.equal(msg['@type'], 'MessageCard')
  })

  it('jira issue targets the configured project', () => {
    const issue = toJiraIssue(sampleEvent('ticket_requested'), 'SEC') as any
    assert.equal(issue.fields.project.key, 'SEC')
    assert.equal(issue.fields.issuetype.name, 'Task')
  })

  it('servicenow incident sets urgency from severity', () => {
    const inc = toServiceNowIncident(sampleEvent('alert')) as any
    assert.equal(inc.urgency, 1) // severity 'high' -> urgency 1
    assert.equal(inc.u_source, 'aeoess-gateway')
  })

  it('email sink resolves when the message is queued', async () => {
    const sink = makeEmailSink({ to: 'ops@example.com', send: async () => ({ sent: false, queued: true }) })
    await sink(sampleEvent('alert')) // resolves without throwing
  })

  it('email sink throws when neither sent nor queued so the dispatcher retries', async () => {
    const sink = makeEmailSink({ to: 'ops@example.com', send: async () => ({ sent: false, queued: false }) })
    await assert.rejects(() => sink(sampleEvent('alert')))
  })
})

describe('connectors - PagerDuty Events API v2', () => {
  const ROUTING_KEY = 'pagerduty-routing-key-must-not-leak'

  function pagerDutyEvent(severity?: string, batch?: ConnectorEvent['batch']): ConnectorEvent {
    return buildConnectorEvent({
      eventType: 'alert',
      eventId: 'evt-pagerduty',
      tenantId: TENANT,
      emittedAt: '2026-01-02T03:04:05.000Z',
      data: severity ? { severity } : {},
      ...(batch ? { batch } : {}),
    })
  }

  it('maps an event to the exact deterministic PagerDuty payload', () => {
    assert.deepEqual(toPagerDutyEvent(pagerDutyEvent('high'), ROUTING_KEY), {
      routing_key: ROUTING_KEY,
      event_action: 'trigger',
      dedup_key: 'evt-pagerduty',
      payload: {
        summary: 'Gateway event: alert',
        source: 'aeoess-gateway',
        severity: 'error',
        custom_details: {
          event_type: 'alert',
          event_id: 'evt-pagerduty',
          tenant_id: TENANT,
          emitted_at: '2026-01-02T03:04:05.000Z',
        },
      },
    })
    const event = pagerDutyEvent('high')
    assert.equal(toPagerDutyEvent(event, ROUTING_KEY).dedup_key, toPagerDutyEvent(event, ROUTING_KEY).dedup_key)
  })

  it('maps every supported severity and defaults unknown or absent values to info', () => {
    for (const [input, expected] of [['critical', 'critical'], ['high', 'error'], ['medium', 'warning'], ['warning', 'warning'], ['low', 'info'], [undefined, 'info']] as const) {
      assert.equal(toPagerDutyEvent(pagerDutyEvent(input), ROUTING_KEY).payload.severity, expected)
    }
  })

  it('includes the optional batch reference in custom details', () => {
    const batch = { batchId: 'batch-1', merkleRoot: 'sha256:abc', epoch: 1, previousBatchId: null, previousMerkleRoot: null, receiptCount: 2, committedAt: '2026-01-02T03:00:00.000Z', summary: { total: 2, byVerdict: { permit: 2 }, byActionType: { read: 2 } } }
    assert.deepEqual(toPagerDutyEvent(pagerDutyEvent('medium', batch), ROUTING_KEY).payload.custom_details.batch, batch)
  })

  it('resolves only when PagerDuty accepts the event and honors default and override endpoints', async () => {
    let request: { url: string; body: string; headers: Record<string, string> } | undefined
    const httpPost = async (req: { url: string; body: string; headers: Record<string, string> }) => {
      request = req
      return { status: 202 }
    }
    await makePagerDutySink({ routingKey: ROUTING_KEY, httpPost })(pagerDutyEvent('critical'))
    assert.equal(request!.url, 'https://events.pagerduty.com/v2/enqueue')
    const sink = makePagerDutySink({ endpoint: 'https://pagerduty.example/enqueue', routingKey: ROUTING_KEY, httpPost })
    await sink(pagerDutyEvent('critical'))
    assert.equal(request!.url, 'https://pagerduty.example/enqueue')
    assert.equal(request!.headers['content-type'], 'application/json')
  })

  for (const status of [400, 429, 500]) {
    it(`rejects PagerDuty status ${status} without exposing the routing key`, async () => {
      const sink = makePagerDutySink({ routingKey: ROUTING_KEY, httpPost: async () => ({ status }) })
      await assert.rejects(() => sink(pagerDutyEvent()), (error: Error) => {
        assert.equal(error.name, 'ConnectorDeliveryError')
        assert.match(error.message, new RegExp(String(status)))
        assert.ok(!error.message.includes(ROUTING_KEY))
        return true
      })
    })
  }
})

// ── endpoint registration + filtering ─────────────────────────────

describe('connectors - endpoint registration and filtering', () => {
  it('rejects an SSRF target at registration', () => {
    const result = registerEndpoint({ tenantId: TENANT, targetUrl: 'https://169.254.169.254/latest/meta-data' })
    assert.equal(result.ok, false)
    assert.match(String(result.error), /metadata service|private/)
  })

  it('rejects a non-https target', () => {
    const result = registerEndpoint({ tenantId: TENANT, targetUrl: 'http://hook.example/in' })
    assert.equal(result.ok, false)
  })

  it('registers a safe endpoint and lists it', () => {
    const result = registerEndpoint({ tenantId: TENANT, targetUrl: 'https://hook.example/safe', eventTypes: ['alert'] })
    assert.equal(result.ok, true)
    assert.ok(result.endpoint!.secret.length >= 16)
    const all = listEndpoints(TENANT)
    assert.ok(all.some((e) => e.id === result.endpoint!.id))
  })

  it('subscription filtering returns only endpoints subscribed to the event type', () => {
    const alertOnly = registerEndpoint({ tenantId: TENANT, targetUrl: 'https://hook.example/alerts', eventTypes: ['alert'] })
    const revocations = listEndpoints(TENANT, 'revocation')
    assert.ok(!revocations.some((e) => e.id === alertOnly.endpoint!.id), 'alert-only endpoint excluded from revocation fan-out')
    const alerts = listEndpoints(TENANT, 'alert')
    assert.ok(alerts.some((e) => e.id === alertOnly.endpoint!.id))
  })
})

// ── identity offboard maps to a revoke ────────────────────────────

describe('connectors - identity offboard maps to a revoke', () => {
  const OFFBOARD_TENANT = 'tenant-offboard'

  before(() => {
    const db = getDB()
    db.prepare(`INSERT INTO tenants (id, name, email, plan, status) VALUES (?, ?, ?, ?, ?)`)
      .run(OFFBOARD_TENANT, 'Offboard Co', 'off@example.com', 'pro', 'active')
    // An agent bound to an Okta identity, with two delegations under it.
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), OFFBOARD_TENANT, 'agent-okta-1', 'pk', 'active', JSON.stringify({ okta_user_id: 'okta-user-42' }))
    db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), OFFBOARD_TENANT, 'agent-okta-1', 'agent-child-a', 'read', 'active')
    db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), OFFBOARD_TENANT, 'agent-parent', 'agent-okta-1', 'read', 'active')
  })

  it('resolves the agent owned by an offboarded Okta identity', () => {
    const offboard: NormalizedOffboard = { provider: 'okta', externalUserId: 'okta-user-42', action: 'deprovision' }
    const target = resolveTargetFromOffboard(OFFBOARD_TENANT, offboard)
    assert.deepEqual(target, { targetType: 'agent', targetId: 'agent-okta-1' })
  })

  it('applies the offboard and cascade-revokes the agent and its delegations', async () => {
    const db = getDB()
    let revokeCalled = false
    const offboard: NormalizedOffboard = { provider: 'okta', externalUserId: 'okta-user-42', action: 'deprovision' }
    const outcome = await applyOffboard({
      tenantId: OFFBOARD_TENANT,
      offboard,
      revoke: async ({ targetId }) => {
        revokeCalled = true
        // Mirror the gateway cascade for the assertion.
        db.prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`).run(OFFBOARD_TENANT, targetId)
        const r = db
          .prepare(
            `UPDATE delegations SET status = 'revoked', revoked_at = datetime('now')
               WHERE tenant_id = ? AND (child_agent_id = ? OR parent_agent_id = ?)`,
          )
          .run(OFFBOARD_TENANT, targetId, targetId)
        return { cascadeCount: (r.changes as number) || 0 }
      },
    })
    assert.equal(revokeCalled, true)
    assert.equal(outcome.mapped, true)
    assert.equal(outcome.targetId, 'agent-okta-1')
    assert.equal(outcome.event.event_type, 'identity_offboard')

    const agent = db.prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(OFFBOARD_TENANT, 'agent-okta-1') as any
    assert.equal(agent.status, 'revoked')
    const live = db.prepare(`SELECT COUNT(*) AS c FROM delegations WHERE tenant_id = ? AND status = 'active'`).get(OFFBOARD_TENANT) as any
    assert.equal(live.c, 0, 'both delegations under the agent revoked')
  })

  it('a suspend (not deprovision) does not map to a revoke', async () => {
    const offboard: NormalizedOffboard = { provider: 'okta', externalUserId: 'okta-user-42', action: 'suspend' }
    const outcome = await applyOffboard({
      tenantId: OFFBOARD_TENANT,
      offboard,
      revoke: async () => {
        throw new Error('revoke must not be called for a suspend')
      },
    })
    assert.equal(outcome.mapped, false)
  })

  it('an offboard of an unknown identity is a no-op', async () => {
    const offboard: NormalizedOffboard = { provider: 'entra', externalUserId: 'nobody-here', action: 'delete' }
    const outcome = await applyOffboard({
      tenantId: OFFBOARD_TENANT,
      offboard,
      revoke: async () => {
        throw new Error('revoke must not be called for an unmapped identity')
      },
    })
    assert.equal(outcome.mapped, false)
  })
})

// ── inbound offboard verification ─────────────────────────────────

describe('connectors - inbound offboard verification', () => {
  it('verifies a correctly signed inbound offboard, then rejects its replay', () => {
    const secret = 'idp-secret-eeeeeeeeeeeeeeee'
    const rawBody = JSON.stringify({ external_user_id: 'okta-user-99', action: 'deprovision' })
    const nonce = 'inbound-nonce-001'
    const ts = Date.now()
    const signature = createHmac('sha256', secret).update(rawBody).digest('hex')
    const first = verifyInboundOffboard({ provider: 'okta', rawBody, secret, signature, nonce, timestampMs: ts, tenantId: 'tenant-ib' })
    assert.equal(first.ok, true, first.reason)
    // Same nonce again -> replay rejected.
    const replay = verifyInboundOffboard({ provider: 'okta', rawBody, secret, signature, nonce, timestampMs: ts, tenantId: 'tenant-ib' })
    assert.equal(replay.ok, false)
    assert.match(String(replay.reason), /replay/)
  })

  it('rejects a bad inbound signature', () => {
    const secret = 'idp-secret-ffffffffffffffff'
    const rawBody = JSON.stringify({ external_user_id: 'x', action: 'delete' })
    const result = verifyInboundOffboard({
      provider: 'entra',
      rawBody,
      secret,
      signature: 'deadbeef',
      nonce: 'n-002',
      timestampMs: Date.now(),
      tenantId: 'tenant-ib',
    })
    assert.equal(result.ok, false)
    assert.match(String(result.reason), /signature mismatch/)
  })
})
