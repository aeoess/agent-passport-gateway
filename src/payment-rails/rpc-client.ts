// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Shared Nano RPC client — used by both nano.ts and wallet-crypto.ts
 *
 * Security triage 2026-04-11 fix 3: every call has a 5-second timeout.
 * Before this fix, the nanoRpc function used fetch() with no AbortSignal,
 * meaning a hanging Nano RPC endpoint would hold the calling request
 * handler (and any open DB transaction) indefinitely. Payment rails
 * should have the tightest timeouts in the system, not the loosest.
 * Reference: CODE-AUDIT-2026-04-11.md §2.10.
 */

/** Default per-request timeout for Nano RPC calls, in milliseconds.
 *  5 seconds is generous for a single RPC hop and still bounded. */
export const NANO_RPC_TIMEOUT_MS = 5000

export async function nanoRpc(
  url: string,
  body: Record<string, unknown>,
  opts?: { timeoutMs?: number },
): Promise<any> {
  const timeoutMs = opts?.timeoutMs ?? NANO_RPC_TIMEOUT_MS
  let res: Response
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    // Translate AbortError / TimeoutError into a clear Nano RPC error so
    // callers can distinguish network-level timeouts from RPC-level errors.
    const e = err as Error
    if (e.name === 'TimeoutError' || e.name === 'AbortError') {
      throw new Error(`Nano RPC timeout after ${timeoutMs}ms: ${url}`)
    }
    throw new Error(`Nano RPC network error: ${e.message}`)
  }
  if (!res.ok) throw new Error(`Nano RPC error: ${res.status} ${res.statusText}`)
  const data = await res.json()
  if (data.error) throw new Error(`Nano RPC: ${data.error}`)
  return data
}
