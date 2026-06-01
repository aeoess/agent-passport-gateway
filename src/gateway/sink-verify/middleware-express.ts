// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Express reference middleware for the sink verifier
// ══════════════════════════════════════════════════════════════════
// Drop this in front of any protected Express handler on the RECEIVING
// API. It runs the offline sink verifier before the handler sees the
// request, rejects unauthorized actions with 403, logs every reject as a
// bypass-trail event, and attaches the verdict for the handler to read.
//
// The verifier is offline: the trust set (agent public key, granted
// scopes, expected delegation, remaining spend) is resolved by a caller-
// supplied function from whatever the sink already holds. The middleware
// makes NO network call.
//
// Bypass detection: the middleware stamps the request with a private
// marker. installBypassGuard() can wrap the protected handler so that if
// it is ever reached without that marker (the handler was mounted around
// the verifier, or the verifier was removed), the call is logged as a
// missing_verdict bypass.
// ══════════════════════════════════════════════════════════════════

import type { Request, Response, NextFunction, RequestHandler } from 'express'
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

/** Private marker key. A handler reached without this set on the request
 *  was not gated by the verifier. Symbol keeps it off the JSON surface. */
const VERIFIED = Symbol('aps.sink.verified')

export interface ExpressSinkOptions {
  /** Extract the APS receipt from the request. Default: req.body.receipt,
   *  else the `aps-receipt` header as base64url JSON. Return null when no
   *  receipt is present (treated as unauthorized, logged as bypass). */
  extractReceipt?: (req: Request) => ActionReceipt | null
  /** Resolve the offline trust set for the receipt. The sink owns this:
   *  it looks up the agent public key and granted scopes it already
   *  trusts. Returning null means "I do not trust this agent" → reject. */
  resolveTrust: (receipt: ActionReceipt, req: Request) => SinkTrustSet | null | Promise<SinkTrustSet | null>
  /** What action the sink is about to perform. Default: derived from the
   *  receipt. Pin scopeRequired here to assert intent independently. */
  resolveAction?: (req: Request) => SinkAction
  /** Where bypass/reject events go. Default: a bounded in-memory sink. */
  bypassSink?: BypassSink
  /** Locator recorded with bypass events (route name, etc.). */
  context?: (req: Request) => string
}

function defaultExtractReceipt(req: Request): ActionReceipt | null {
  const body = (req as any).body
  if (body && typeof body === 'object' && body.receipt && typeof body.receipt === 'object') {
    return body.receipt as ActionReceipt
  }
  const header = req.headers['aps-receipt']
  if (typeof header === 'string' && header.length > 0) {
    try {
      const json = Buffer.from(header, 'base64url').toString('utf8')
      const parsed = JSON.parse(json)
      if (parsed && typeof parsed === 'object') return parsed as ActionReceipt
    } catch { /* malformed header → treated as no receipt below */ }
  }
  return null
}

/**
 * Build the Express sink-verification middleware.
 *
 * On accept: stamps the request, sets res.locals.sinkVerdict, calls next().
 * On reject: records a bypass-trail event and responds 403 with the
 * verdict (verdict shape mirrors the source-side pre-check).
 */
export function expressSinkVerifier(opts: ExpressSinkOptions): RequestHandler {
  const sink: BypassSink = opts.bypassSink ?? new MemoryBypassSink()
  const extract = opts.extractReceipt ?? defaultExtractReceipt

  return async function sinkVerifierMiddleware(req: Request, res: Response, next: NextFunction) {
    const context = opts.context ? opts.context(req) : `${req.method} ${req.path}`

    const receipt = extract(req)
    if (!receipt) {
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        violations: ['no_receipt'],
        context,
      }))
      res.status(403).json({
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
      res.status(403).json({
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
    } catch (e) {
      // FAIL CLOSED: a verifier crash rejects the action.
      sink.record(bypassEventFromVerdict({
        reason: 'rejected',
        agent_id: receipt.agentId,
        receipt_id: receipt.receiptId,
        scope_required: action.scopeRequired ?? receipt.action?.scopeUsed,
        violations: ['verifier_error'],
        context,
      }))
      res.status(403).json({
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
      res.status(403).json({
        verdict: 'reject',
        reason: verdict.reason,
        violations: verdict.violations,
        agent_id: verdict.agent_id,
        receipt_id: verdict.receipt_id,
      })
      return
    }

    ;(req as any)[VERIFIED] = true
    res.locals.sinkVerdict = verdict
    next()
  }
}

/**
 * Wrap a protected handler so that reaching it WITHOUT a verified verdict
 * is logged as a missing_verdict bypass. Defense in depth: if the
 * verifier middleware was removed or mounted around this handler, the
 * direct call still leaves a trail rather than silently succeeding.
 */
export function installBypassGuard(
  handler: RequestHandler,
  bypassSink: BypassSink,
  context?: (req: Request) => string,
): RequestHandler {
  return function guarded(req: Request, res: Response, next: NextFunction) {
    if (!(req as any)[VERIFIED]) {
      bypassSink.record(bypassEventFromVerdict({
        reason: 'missing_verdict',
        violations: ['handler_reached_without_verification'],
        context: context ? context(req) : `${req.method} ${req.path}`,
      }))
      res.status(403).json({
        verdict: 'reject',
        reason: 'Protected handler reached without sink verification',
        violations: ['missing_verdict'],
      })
      return
    }
    return (handler as any)(req, res, next)
  }
}

export { VERIFIED as SINK_VERIFIED_MARKER }
