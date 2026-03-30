// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Shared Nano RPC client — used by both nano.ts and wallet-crypto.ts
 */

export async function nanoRpc(url: string, body: Record<string, unknown>): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`Nano RPC error: ${res.status} ${res.statusText}`)
  const data = await res.json()
  if (data.error) throw new Error(`Nano RPC: ${data.error}`)
  return data
}
