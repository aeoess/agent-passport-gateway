// APS Regulated Action Profile v0: gateway state store (private).
//
// Holds the per-action lifecycle state and the replay seen-sets (authority jti and intent
// gateway_nonce uniqueness, per tenant). Replay detection is the gateway concern the public
// verifier defers (authority_replay: not_evaluated). better-sqlite3 with WAL, tenant_id mandatory.
// Defaults to an in-memory database; pass a path for a Railway Volume deployment.

import Database from 'better-sqlite3'

export type LifecycleState =
  | 'intent_reserved'
  | 'executed'
  | 'reconciled'
  | 'intent_precommitted'
  | 'voided'
  | 'incomplete'

export interface RaStore {
  setState(tenantId: string, receiptId: string, state: LifecycleState): void
  getState(tenantId: string, receiptId: string): LifecycleState | null
  /**
   * Bind (scope_key, kind, value) to the first receipt that claims it and return the OWNING
   * receipt id. The same receipt re-binding is a no-op; a DIFFERENT receipt reusing the value is a
   * replay (the returned owner differs from the caller's receiptId). scope_key controls the replay
   * partition: an IdP-issued authority jti is bound GLOBALLY by issuer (scope_key "idp:<issuer>")
   * so reuse is caught across tenants of the same operator; a gateway-issued nonce is bound
   * per tenant (scope_key "tenant:<id>").
   */
  bindOwner(scopeKey: string, kind: 'jti' | 'nonce', value: string, receiptId: string): string
  close(): void
}

export function openRaStore(path = ':memory:'): RaStore {
  const db = new Database(path)
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')
  db.pragma('busy_timeout = 5000')
  db.exec(`
    CREATE TABLE IF NOT EXISTS ra_lifecycle (
      tenant_id  TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      state      TEXT NOT NULL,
      updated_ms INTEGER NOT NULL,
      PRIMARY KEY (tenant_id, receipt_id)
    );
    CREATE TABLE IF NOT EXISTS ra_seen (
      scope_key     TEXT NOT NULL,
      kind          TEXT NOT NULL,
      value         TEXT NOT NULL,
      owner_receipt TEXT NOT NULL,
      PRIMARY KEY (scope_key, kind, value)
    );
  `)
  const upsert = db.prepare(
    `INSERT INTO ra_lifecycle (tenant_id, receipt_id, state, updated_ms) VALUES (?, ?, ?, ?)
     ON CONFLICT(tenant_id, receipt_id) DO UPDATE SET state = excluded.state, updated_ms = excluded.updated_ms`,
  )
  const get = db.prepare(`SELECT state FROM ra_lifecycle WHERE tenant_id = ? AND receipt_id = ?`)
  const insertSeen = db.prepare(`INSERT OR IGNORE INTO ra_seen (scope_key, kind, value, owner_receipt) VALUES (?, ?, ?, ?)`)
  const getOwner = db.prepare(`SELECT owner_receipt FROM ra_seen WHERE scope_key = ? AND kind = ? AND value = ?`)

  return {
    setState(tenantId, receiptId, state) {
      upsert.run(tenantId, receiptId, state, Date.now())
    },
    getState(tenantId, receiptId) {
      const row = get.get(tenantId, receiptId) as { state: LifecycleState } | undefined
      return row?.state ?? null
    },
    bindOwner(scopeKey, kind, value, receiptId) {
      insertSeen.run(scopeKey, kind, value, receiptId)
      const row = getOwner.get(scopeKey, kind, value) as { owner_receipt: string }
      return row.owner_receipt
    },
    close() { db.close() },
  }
}
