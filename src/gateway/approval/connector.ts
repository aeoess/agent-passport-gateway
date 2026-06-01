// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - connector routing seam.
 *
 * Approver notification and the sample-for-review pull are meant to route
 * through the G-C1 connectors module. As of this build the C1 worktree
 * (gw-c1-connectors) is at the SAME base commit as ours with a
 * clean tree and NO src/gateway/connectors/ directory - there is no public
 * connector/router surface to import yet. Importing any C1 connectors path
 * would fail the build.
 *
 * So this file defines a LOCAL typed seam (ApprovalConnectorRouter) and
 * backs it with the existing sendEmail() queue-first transport as the
 * interim channel. When C1 ships its public router surface, swap the
 * interim transport for the connectors route at the single TODO below.
 * We depend only on C1's (future) PUBLIC surface, never its internals.
 */

import { sendEmail } from '../../notifications/email.js'

export type ApprovalChannel = 'notify_approver' | 'sample_for_review'

export interface ApprovalRoutePayload {
  /** Recipient address / handle for the interim email channel. */
  to: string
  /** Approval request id this routing concerns. */
  requestId: string
  /** Action class under approval (no PII, no reason text). */
  actionClass: string
  /** Risk tier label. */
  riskTier: string
  /** Short, claims-clean human summary line. */
  summary: string
}

export interface DeliveryReceipt {
  channel: ApprovalChannel
  /** Whether the underlying transport reports the message sent. */
  sent: boolean
  /** Whether the message was durably queued (crash-safe). */
  queued: boolean
  /** Which transport actually handled it. 'connectors' once C1 lands. */
  transport: 'email_interim' | 'connectors'
  routedAt: string
}

/** The seam G-C1 connectors will satisfy. The gateway depends on THIS
 *  interface, not on any concrete C1 module. */
export interface ApprovalConnectorRouter {
  route(channel: ApprovalChannel, payload: ApprovalRoutePayload): Promise<DeliveryReceipt>
}

/**
 * Interim implementation: route everything over email (queue-first via
 * sendEmail). Copy is claims-clean - it supports evidence for a scoped
 * approval step, it does not assert compliance or instant anything.
 */
class EmailInterimConnectorRouter implements ApprovalConnectorRouter {
  async route(channel: ApprovalChannel, payload: ApprovalRoutePayload): Promise<DeliveryReceipt> {
    // TODO(G-C1 / gw-c1-connectors): replace this interim email transport
    // with connectors routing once C1 exports its public router/connector
    // surface (e.g. connectorRouter.route(approvalRequest, channel)).
    // Depend only on the public surface; do not reach into C1 internals.
    const subject = channel === 'notify_approver'
      ? `Approval requested: ${payload.actionClass} (${payload.riskTier})`
      : `Review sample pulled: ${payload.actionClass} (${payload.riskTier})`

    const textBody = [
      payload.summary,
      '',
      `Action class: ${payload.actionClass}`,
      `Risk tier: ${payload.riskTier}`,
      `Request: ${payload.requestId}`,
      '',
      'This message supports evidence for a scoped approval step.',
      'Assurance is verifier-derived from the gateway JWKS, not asserted here.',
    ].join('\n')

    const result = await sendEmail({ to: payload.to, subject, textBody })
    return {
      channel,
      sent: result.sent,
      queued: result.queued,
      transport: 'email_interim',
      routedAt: new Date().toISOString(),
    }
  }
}

let _router: ApprovalConnectorRouter | null = null

/** Resolve the active connector router. Returns the interim email router
 *  until C1's public surface is wired at the TODO above. A test or a future
 *  integration may override via setApprovalConnectorRouter(). */
export function getApprovalConnectorRouter(): ApprovalConnectorRouter {
  if (!_router) _router = new EmailInterimConnectorRouter()
  return _router
}

/** Override the connector router (used by tests and the future C1 wiring). */
export function setApprovalConnectorRouter(router: ApprovalConnectorRouter | null): void {
  _router = router
}
