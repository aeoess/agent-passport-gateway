// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - Email adapter
// ══════════════════════════════════════════════════════════════════
// Brings the existing email primitive under the ONE connector interface so an
// email notification composes with the same retry + dead-letter path as every
// other adapter. It REUSES src/notifications/email.ts sendEmail rather than
// re-implementing delivery: email.ts already does queue-first JSONL then Resend
// then SMTP. This adapter only maps a ConnectorEvent into an EmailOptions and
// adapts the {sent, queued} result to the EgressSink throw-on-failure contract.
// ══════════════════════════════════════════════════════════════════

import { sendEmail, type EmailOptions } from '../../email.js'
import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'

/** Render a connector event into an email body. */
export function toEmail(event: ConnectorEvent, to: string): EmailOptions {
  const lines = [
    `Event type: ${event.event_type}`,
    `Tenant: ${event.tenant_id}`,
    `Emitted at: ${event.emitted_at}`,
    `Event ID: ${event.event_id}`,
  ]
  if (event.batch) {
    lines.push(`Merkle root: ${event.batch.merkleRoot}`)
    lines.push(`Receipt count: ${event.batch.receiptCount}`)
  }
  const textBody = lines.join('\n')
  return {
    to,
    subject: `AEOESS Gateway: ${event.event_type}`,
    textBody,
  }
}

/**
 * Build an email ConnectorSink. Resolves when the message is sent OR durably
 * queued (queue-first is an accepted delivery for email, the same contract
 * email.ts already implements). Throws only when email.ts reports neither sent
 * nor queued, which the dispatcher then retries.
 */
export function makeEmailSink(opts: {
  to: string
  send?: typeof sendEmail
}): ConnectorSink {
  const sender = opts.send ?? sendEmail
  return async (event: ConnectorEvent) => {
    const result = await sender(toEmail(event, opts.to))
    if (!result.sent && !result.queued) {
      throw new ConnectorDeliveryError('email neither sent nor queued')
    }
  }
}
