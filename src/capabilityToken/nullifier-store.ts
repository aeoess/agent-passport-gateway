// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Persistent capability-token nullifier store (audit item 5, HIGH replay)
// ══════════════════════════════════════════════════════════════════
// The MCP capability-token sink consults a NullifierStore on every M3 redemption
// to reject a replayed token preimage. The reference store (InMemoryNullifierSet
// in agent-passport-mcp) is process-local, so on the remote deployment -- where
// each /mcp request may spawn a fresh subprocess and the server can restart --
// the nullifier set is always empty and replay always passes.
//
// This is the durable store the audit specified: backed by the gateway's
// better-sqlite3 DB, so a consumed nullifier survives restarts and is shared
// across processes that open the same DB. It implements the SAME NullifierStore
// interface shape the MCP defines (isConsumed / consume / size / clear), so a
// co-located deployment injects it behind the existing interface without changing
// the MCP redemption logic. The in-memory impl below stays for the stateless
// reference path and for tests.
//
// GATEWAY-ONLY: this adds a gateway store. Wiring the MCP subprocess to inject it
// (when co-located with the gateway) is a deploy-time step documented in the memo.
import type Database from 'better-sqlite3'

/** Same shape as agent-passport-mcp's NullifierStore. `consume` throws on replay. */
export interface NullifierStore {
  isConsumed(preimage: string): boolean
  consume(preimage: string, expiresAt?: string | null): void
  size(): number
  clear(): void
}

/**
 * SQLite-backed nullifier store. Check-and-consume is a single atomic statement
 * (INSERT ... ON CONFLICT DO NOTHING; changes()===0 means the preimage was already
 * present -> replay). Optional expires_at enables a TTL sweep so the table does not
 * grow without bound. Durable and shared: any process opening the same DB sees a
 * consumed nullifier, so replay is rejected across restarts and processes.
 */
/** Default maximum capability-token lifetime the nullifier store will retain a row for (24h). */
export const DEFAULT_MAX_CAPABILITY_TTL_MS = 24 * 60 * 60 * 1000

export class SqliteNullifierStore implements NullifierStore {
  private readonly maxTtlMs: number
  constructor(private readonly db: Database.Database, opts: { maxCapabilityTtlMs?: number } = {}) {
    this.maxTtlMs = Number.isFinite(opts.maxCapabilityTtlMs as number) && (opts.maxCapabilityTtlMs as number) > 0
      ? (opts.maxCapabilityTtlMs as number)
      : DEFAULT_MAX_CAPABILITY_TTL_MS
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS capability_nullifiers (
        nullifier  TEXT PRIMARY KEY,
        expires_at TEXT,
        created_at TEXT NOT NULL
      )
    `)
  }

  isConsumed(preimage: string): boolean {
    return !!this.db.prepare(`SELECT 1 FROM capability_nullifiers WHERE nullifier = ?`).get(preimage)
  }

  /**
   * Atomic check-and-consume. Throws on replay, mirroring InMemoryNullifierSet.consume.
   *
   * R3-3: clamp the STORED expires_at to now + MAX_CAPABILITY_TTL. sweepExpired can never evict a
   * far-future expiry, so an attacker minting tokens with expires_at=9999 would grow this table
   * unbounded (disk DoS). MAX is the maximum capability-token lifetime; a token cannot be validly
   * presented after now+MAX, so clamping the nullifier to now+MAX keeps full replay protection for the
   * entire window the token can be honored while bounding growth. An unparseable expiry is left as-is
   * (sweepExpired keeps it, fail-safe); a null expiry (no declared TTL) is unchanged.
   */
  consume(preimage: string, expiresAt: string | null = null): void {
    let effectiveExpiresAt = expiresAt
    if (expiresAt != null) {
      const parsed = Date.parse(expiresAt)
      if (Number.isFinite(parsed)) {
        const horizon = Date.now() + this.maxTtlMs
        if (parsed > horizon) effectiveExpiresAt = new Date(horizon).toISOString()
      }
    }
    const info = this.db.prepare(
      `INSERT INTO capability_nullifiers (nullifier, expires_at, created_at) VALUES (?, ?, ?)
       ON CONFLICT(nullifier) DO NOTHING`,
    ).run(preimage, effectiveExpiresAt, new Date().toISOString())
    if (info.changes === 0) {
      throw new Error(`nullifier replay: token preimage ${preimage.slice(0, 12)}... already consumed`)
    }
  }

  size(): number {
    return (this.db.prepare(`SELECT COUNT(*) AS c FROM capability_nullifiers`).get() as { c: number }).c
  }

  clear(): void {
    this.db.exec(`DELETE FROM capability_nullifiers`)
  }

  /**
   * Remove nullifiers whose expires_at has passed. Returns the number swept.
   *
   * Panel B4 F1/F2: compare EPOCHS, not raw strings. expires_at is supplied by the caller (the token's
   * own exp) and may be any valid ISO-8601 form -- 'Z', a numeric offset ('-05:00'), or no milliseconds.
   * A lexicographic `expires_at < now` mis-sorts those forms: an offset expiry ('...-05:00') sorts
   * before a 'Z' now, so a STILL-VALID nullifier would be swept early and its token could be replayed.
   * julianday(...) normalizes the timezone to a UTC instant (sub-second precise) on both sides. A
   * value SQLite cannot parse yields NULL, so `< ?` is NULL and the row is NOT deleted -- fail-safe
   * (keep the nullifier; never reopen replay). Sweeping late is harmless; only sweeping EARLY (the
   * lexicographic bug) could reopen replay.
   */
  sweepExpired(nowIso: string = new Date().toISOString()): number {
    return this.db.prepare(
      `DELETE FROM capability_nullifiers
       WHERE expires_at IS NOT NULL
         AND julianday(expires_at) IS NOT NULL
         AND julianday(expires_at) < julianday(?)`,
    ).run(nowIso).changes
  }
}

/** Process-local store for tests and the stateless stdio reference path. */
export class InMemoryNullifierStore implements NullifierStore {
  private readonly seen = new Set<string>()
  isConsumed(preimage: string): boolean { return this.seen.has(preimage) }
  consume(preimage: string): void {
    if (this.seen.has(preimage)) {
      throw new Error(`nullifier replay: token preimage ${preimage.slice(0, 12)}... already consumed`)
    }
    this.seen.add(preimage)
  }
  size(): number { return this.seen.size }
  clear(): void { this.seen.clear() }
}
