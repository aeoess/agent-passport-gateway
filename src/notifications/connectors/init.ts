// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Table bootstrap
// ══════════════════════════════════════════════════════════════════
// Mirrors the initLeafOutbox() style: an idempotent CREATE TABLE IF NOT EXISTS
// bootstrap called once at server startup. Creates the tables for webhook
// endpoint registration, the replay-protection seen-nonce window, and the
// delivery dead-letter log. No webhook/subscription/connector tables existed
// in the base schema, so all of these are net-new and namespaced with a
// connector_ prefix to avoid colliding with Stripe's webhook tables.
// ══════════════════════════════════════════════════════════════════

import { getDB } from '../../db/schema.js'

/** Create the connector tables. Idempotent. Call once at bootstrap. */
export function initConnectorTables(): void {
  const db = getDB()

  // Registered outbound signed-webhook endpoints. "endpoint" not "subscription"
  // to avoid colliding with Stripe subscriptions and the SSE EventBus
  // subscribe/unsubscribe vocabulary.
  db.exec(`
    CREATE TABLE IF NOT EXISTS connector_webhook_endpoints (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      target_url TEXT NOT NULL,
      secret TEXT NOT NULL,
      event_types TEXT NOT NULL DEFAULT '*',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_delivery_at TEXT,
      last_status TEXT
    )
  `)
  db.exec(
    `CREATE INDEX IF NOT EXISTS idx_connector_webhook_endpoints_tenant
       ON connector_webhook_endpoints(tenant_id, status)`,
  )

  // Replay-protection window: nonces the gateway has already issued (outbound)
  // or already accepted (inbound identity-bridge). A nonce seen inside the
  // freshness window is rejected as a replay.
  db.exec(`
    CREATE TABLE IF NOT EXISTS connector_seen_nonces (
      nonce TEXT NOT NULL,
      scope TEXT NOT NULL,
      tenant_id TEXT,
      seen_at_ms INTEGER NOT NULL,
      PRIMARY KEY (scope, nonce)
    )
  `)
  db.exec(
    `CREATE INDEX IF NOT EXISTS idx_connector_seen_nonces_seen_at
       ON connector_seen_nonces(seen_at_ms)`,
  )

  // Durable dead-letter log. The in-memory dispatcher DLQ is bounded; this
  // table is the persistent operator-drainable record so an outage does not
  // lose the fact that an envelope failed. The granular leaves remain safe in
  // the G-A1 outbox regardless.
  db.exec(`
    CREATE TABLE IF NOT EXISTS connector_dead_letters (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      endpoint_id TEXT,
      connector_kind TEXT NOT NULL,
      event_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      attempts INTEGER NOT NULL,
      last_error TEXT,
      dead_lettered_at TEXT NOT NULL DEFAULT (datetime('now')),
      redelivered_at TEXT
    )
  `)
  db.exec(
    `CREATE INDEX IF NOT EXISTS idx_connector_dead_letters_tenant
       ON connector_dead_letters(tenant_id, redelivered_at)`,
  )
}
