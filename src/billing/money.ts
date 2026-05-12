/**
 * Money helpers — C4 (audit 2026-05-12) phase A.
 *
 * Background: the gateway has historically stored money in REAL columns
 * (delegations.spend_limit, contributions.amount, settlements.total_amount,
 * payment_transactions.amount). SQLite REAL is IEEE 754 double, and cents
 * arithmetic on doubles drifts under repeated additions. This module is the
 * forward-compatible side of the move to INTEGER cents:
 *
 *   - toCents(usd) converts a dollar value to cents, rounded half-away-from-zero.
 *   - dualWriteMoney(usd) returns { usd, cents } so call sites can dual-write
 *     during the migration window.
 *
 * Reads still come from the REAL column today; this is purely about not
 * corrupting the new INTEGER column while the read switch is pending.
 *
 * Phase B (later, behind a separate migration):
 *   1. Backfill *_cents from REAL for rows where cents IS NULL.
 *   2. Switch all reads to *_cents.
 *   3. Drop the REAL columns.
 */

/**
 * Convert a USD value to integer cents using bankers'-safe rounding away from
 * zero (so 1.005 → 101, -1.005 → -101). Math.round breaks on negatives in JS
 * (Math.round(-0.5) is 0); we use the more predictable variant.
 *
 * Returns null when the input is null/undefined — callers that pass a real
 * value get a real integer back. NaN input returns null.
 */
export function toCents(usd: number | null | undefined): number | null {
  if (usd == null) return null
  if (typeof usd !== 'number' || !Number.isFinite(usd)) return null
  const sign = usd < 0 ? -1 : 1
  return sign * Math.round(Math.abs(usd) * 100)
}

/**
 * Return both representations for a dual-write. Call sites pattern looks like:
 *
 *   const m = dualWriteMoney(delegation.spend_limit)
 *   db.prepare(
 *     `INSERT INTO delegations (..., spend_limit, spend_limit_cents) VALUES (..., ?, ?)`
 *   ).run(..., m.usd, m.cents)
 */
export function dualWriteMoney(
  usd: number | null | undefined,
): { usd: number | null; cents: number | null } {
  if (usd == null || typeof usd !== 'number' || !Number.isFinite(usd)) {
    return { usd: null, cents: null }
  }
  return { usd, cents: toCents(usd) }
}
