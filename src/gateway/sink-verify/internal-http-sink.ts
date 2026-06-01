// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Internal-HTTP-sink verifier
// ══════════════════════════════════════════════════════════════════
// When the gateway fans an authorized action out to an internal tool
// over HTTP, the internal tool is itself a SINK. It should not trust the
// caller just because the call came from inside the perimeter - an
// attacker on the internal network can hit the tool directly, around the
// gateway. This verifier is what the internal tool runs on the forwarded
// receipt.
//
// Two key-resolution modes, both anchored offline:
//   1. inline  - the caller hands a key store (Map agentId → publicKey).
//                No I/O at all. This is the default and recommended mode.
//   2. fetched - the tool resolves an agent key from a key-distribution
//                URL. The URL is SSRF-guarded with validateExternalUrl
//                (reused from the evaluate path) so the resolver cannot
//                be steered at internal metadata services. Verification
//                itself still runs offline once the key is in hand.
//
// The verdict shape mirrors verifySinkOffline. A reject from an internal
// sink is a bypass-trail event just like an edge reject.
// ══════════════════════════════════════════════════════════════════

import type { ActionReceipt } from 'agent-passport-system'
import { validateExternalUrl } from '../url-safety.js'
import {
  verifySinkOffline,
  type SinkTrustSet,
  type SinkAction,
  type SinkVerdict,
} from './verifier.js'
import {
  MemoryBypassSink,
  bypassEventFromVerdict,
  type BypassSink,
} from './bypass-log.js'

/** Offline key store the internal tool already holds. */
export interface InlineKeyStore {
  mode: 'inline'
  /** agentId → Ed25519 public key (hex). */
  keys: Map<string, string>
  /** Scopes the tool grants per agent (optional; omit to skip scope
   *  re-check for that agent). */
  grantedScopes?: Map<string, string[]>
}

/** Key resolver that fetches the agent key from a distribution URL.
 *  Used only when an inline store cannot hold the key ahead of time. */
export interface FetchedKeyStore {
  mode: 'fetched'
  /** Build the key-distribution URL for an agentId. The returned URL is
   *  SSRF-validated before any fetch. */
  keyUrl: (agentId: string) => string
  /** Parse the agent public key (hex) out of the fetched body. */
  parseKey: (body: unknown) => string | null
  /** Scopes the tool grants per agent (optional). */
  grantedScopes?: Map<string, string[]>
  /** Fetch timeout in ms. Default 3000. */
  timeoutMs?: number
}

export type InternalKeyStore = InlineKeyStore | FetchedKeyStore

export interface InternalSinkOptions {
  keyStore: InternalKeyStore
  bypassSink?: BypassSink
  /** Locator recorded with bypass events. */
  context?: string
}

export interface InternalSinkVerifier {
  /** Verify a forwarded receipt for an internal tool call. */
  verify(receipt: ActionReceipt, action?: SinkAction): Promise<SinkVerdict>
  /** The bypass sink in use (for the tool to inspect / forward). */
  bypassSink: BypassSink
}

async function resolveInline(
  store: InlineKeyStore,
  receipt: ActionReceipt,
): Promise<SinkTrustSet | null> {
  const key = store.keys.get(receipt.agentId)
  if (!key) return null
  return {
    agentPublicKey: key,
    grantedScopes: store.grantedScopes?.get(receipt.agentId),
  }
}

async function resolveFetched(
  store: FetchedKeyStore,
  receipt: ActionReceipt,
): Promise<SinkTrustSet | null> {
  const url = store.keyUrl(receipt.agentId)
  // SSRF guard: the same validator the evaluate path uses. An internal
  // key-distribution URL must not be steerable at loopback or cloud
  // metadata endpoints.
  const safe = validateExternalUrl(url)
  if (!safe.safe) return null
  try {
    const res = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(store.timeoutMs ?? 3000),
    })
    if (!res.ok) return null
    const body = await res.json()
    const key = store.parseKey(body)
    if (!key) return null
    return {
      agentPublicKey: key,
      grantedScopes: store.grantedScopes?.get(receipt.agentId),
    }
  } catch {
    return null
  }
}

/**
 * Build an internal-HTTP-sink verifier. The returned object exposes a
 * single verify() that an internal tool calls on each forwarded receipt
 * before it does any work.
 */
export function createInternalSinkVerifier(opts: InternalSinkOptions): InternalSinkVerifier {
  const sink: BypassSink = opts.bypassSink ?? new MemoryBypassSink()
  const store = opts.keyStore

  async function verify(receipt: ActionReceipt, action: SinkAction = {}): Promise<SinkVerdict> {
    if (!receipt || typeof receipt !== 'object') {
      const v: SinkVerdict = {
        verdict: 'reject',
        reason: 'Malformed receipt',
        violations: ['malformed_receipt'],
        agent_id: '',
        receipt_id: '',
        signature_valid: false,
        duration_ms: 0,
      }
      sink.record(bypassEventFromVerdict({
        reason: 'rejected', violations: v.violations, context: opts.context,
      }))
      return v
    }

    const trust = store.mode === 'inline'
      ? await resolveInline(store, receipt)
      : await resolveFetched(store, receipt)

    if (!trust) {
      const v: SinkVerdict = {
        verdict: 'reject',
        reason: 'Internal sink could not resolve a trusted key for the agent',
        violations: ['untrusted_agent'],
        agent_id: receipt.agentId ?? '',
        receipt_id: receipt.receiptId ?? '',
        signature_valid: false,
        duration_ms: 0,
      }
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        agent_id: v.agent_id,
        receipt_id: v.receipt_id,
        scope_required: action.scopeRequired ?? receipt.action?.scopeUsed,
        violations: v.violations,
        context: opts.context,
      }))
      return v
    }

    const verdict = await verifySinkOffline(receipt, trust, action)
    if (verdict.verdict === 'reject') {
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        agent_id: verdict.agent_id,
        receipt_id: verdict.receipt_id,
        scope_required: action.scopeRequired ?? receipt.action?.scopeUsed,
        violations: verdict.violations,
        context: opts.context,
      }))
    }
    return verdict
  }

  return { verify, bypassSink: sink }
}
