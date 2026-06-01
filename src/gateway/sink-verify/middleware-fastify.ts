// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Fastify reference preHandler for the sink verifier
// ══════════════════════════════════════════════════════════════════
// Same contract as the Express middleware, expressed as a Fastify
// preHandler hook. Fastify is not a dependency of the gateway, so this
// reference targets a minimal STRUCTURAL interface (the subset of the
// Fastify request/reply API the verifier touches). A real Fastify app
// passes its own FastifyRequest/FastifyReply, which satisfy this shape.
// Keeping it structural means the reference compiles and runs offline
// here, and drops into a Fastify service without a version pin.
// ══════════════════════════════════════════════════════════════════

import type { ActionReceipt } from 'agent-passport-system'
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

/** Minimal request shape this reference reads. FastifyRequest satisfies it. */
export interface FastifyLikeRequest {
  method?: string
  url?: string
  headers: Record<string, string | string[] | undefined>
  body?: unknown
  /** Per-request scratch space the hook stamps on accept. */
  [key: string]: unknown
}

/** Minimal reply shape this reference writes. FastifyReply satisfies it. */
export interface FastifyLikeReply {
  code(statusCode: number): FastifyLikeReply
  send(payload: unknown): unknown
  /** Set by the hook on accept so the route handler can read the verdict. */
  sinkVerdict?: SinkVerdict
}

export interface FastifySinkOptions {
  /** Extract the receipt. Default: body.receipt, else `aps-receipt`
   *  header as base64url JSON. */
  extractReceipt?: (req: FastifyLikeRequest) => ActionReceipt | null
  /** Resolve the offline trust set. Null → reject (untrusted agent). */
  resolveTrust: (receipt: ActionReceipt, req: FastifyLikeRequest) => SinkTrustSet | null | Promise<SinkTrustSet | null>
  /** What the sink is about to do. Default: derived from the receipt. */
  resolveAction?: (req: FastifyLikeRequest) => SinkAction
  /** Where bypass/reject events go. Default: bounded in-memory sink. */
  bypassSink?: BypassSink
  /** Locator recorded with bypass events. */
  context?: (req: FastifyLikeRequest) => string
}

const VERIFIED_KEY = '__apsSinkVerified'

function defaultExtractReceipt(req: FastifyLikeRequest): ActionReceipt | null {
  const body = req.body as any
  if (body && typeof body === 'object' && body.receipt && typeof body.receipt === 'object') {
    return body.receipt as ActionReceipt
  }
  const header = req.headers['aps-receipt']
  const raw = Array.isArray(header) ? header[0] : header
  if (typeof raw === 'string' && raw.length > 0) {
    try {
      const json = Buffer.from(raw, 'base64url').toString('utf8')
      const parsed = JSON.parse(json)
      if (parsed && typeof parsed === 'object') return parsed as ActionReceipt
    } catch { /* malformed → no receipt */ }
  }
  return null
}

/**
 * Build the Fastify preHandler. Returns a hook (request, reply) => Promise.
 * On accept it stamps the request and sets reply.sinkVerdict; on reject it
 * records a bypass event and replies 403 (verdict shape mirrors the
 * source-side pre-check).
 */
export function fastifySinkVerifier(opts: FastifySinkOptions) {
  const sink: BypassSink = opts.bypassSink ?? new MemoryBypassSink()
  const extract = opts.extractReceipt ?? defaultExtractReceipt

  return async function sinkPreHandler(req: FastifyLikeRequest, reply: FastifyLikeReply): Promise<void> {
    const context = opts.context ? opts.context(req) : `${req.method ?? ''} ${req.url ?? ''}`.trim()

    const receipt = extract(req)
    if (!receipt) {
      sink.record(bypassEventFromVerdict({ reason: 'rejected', violations: ['no_receipt'], context }))
      reply.code(403).send({
        verdict: 'reject',
        reason: 'No APS receipt presented to sink',
        violations: ['no_receipt'],
      })
      return
    }

    const trust = await opts.resolveTrust(receipt, req)
    if (!trust) {
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        agent_id: receipt.agentId,
        receipt_id: receipt.receiptId,
        violations: ['untrusted_agent'],
        context,
      }))
      reply.code(403).send({
        verdict: 'reject',
        reason: 'Sink does not trust the executing agent',
        violations: ['untrusted_agent'],
        agent_id: receipt.agentId,
      })
      return
    }

    const action: SinkAction = opts.resolveAction ? opts.resolveAction(req) : {}
    let verdict: SinkVerdict
    try {
      verdict = await verifySinkOffline(receipt, trust, action)
    } catch {
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        agent_id: receipt.agentId,
        receipt_id: receipt.receiptId,
        scope_required: action.scopeRequired ?? receipt.action?.scopeUsed,
        violations: ['verifier_error'],
        context,
      }))
      reply.code(403).send({
        verdict: 'reject',
        reason: 'Sink verifier error',
        violations: ['verifier_error'],
        agent_id: receipt.agentId,
      })
      return
    }

    if (verdict.verdict === 'reject') {
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        agent_id: verdict.agent_id,
        receipt_id: verdict.receipt_id,
        scope_required: action.scopeRequired ?? receipt.action?.scopeUsed,
        violations: verdict.violations,
        context,
      }))
      reply.code(403).send({
        verdict: 'reject',
        reason: verdict.reason,
        violations: verdict.violations,
        agent_id: verdict.agent_id,
        receipt_id: verdict.receipt_id,
      })
      return
    }

    req[VERIFIED_KEY] = true
    reply.sinkVerdict = verdict
  }
}

export { VERIFIED_KEY as FASTIFY_SINK_VERIFIED_KEY }
