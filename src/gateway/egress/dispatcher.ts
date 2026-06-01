// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// GEM (G-A1) - Egress Dispatcher (retry + dead-letter)
// ══════════════════════════════════════════════════════════════════
// Delivers the small root-plus-summary envelope to a downstream sink (a
// customer SIEM, a webhook, an object store). Thin gateway: the sink is
// injected and is the party that verifies the envelope. The gateway does not
// hold a central enforcement brain; it dispatches, retries a bounded number
// of times with backoff, and dead-letters on exhaustion so nothing is lost
// silently. Every outcome is emitted on the event bus.
// ══════════════════════════════════════════════════════════════════

import { getEventBus } from '../events.js'
import type { SummaryMatrix } from './summary-matrix.js'

/** The downstream envelope. Carries the root and structural summary only,
 *  never the granular leaves. */
export interface EgressEnvelope {
  batchId: string
  merkleRoot: string
  epoch: number
  previousBatchId: string | null
  previousMerkleRoot: string | null
  receiptCount: number
  committedAt: string
  summary: SummaryMatrix
  /** Out-of-band handle for fetching leaves if an anomaly is flagged. */
  leafFetchRef: string
}

/** A downstream sink. Resolves on accepted delivery, rejects (or returns a
 *  non-accepting result) to trigger retry. Injected so the gateway pushes
 *  verification and persistence to the edge. */
export type EgressSink = (envelope: EgressEnvelope) => Promise<void>

export interface RetryPolicy {
  /** Total delivery attempts before dead-lettering (>= 1). */
  maxAttempts: number
  /** Base backoff in milliseconds; attempt N waits base * 2^(N-1). */
  baseDelayMs: number
  /** Cap on a single backoff wait. */
  maxDelayMs: number
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 200,
  maxDelayMs: 5000,
}

export interface DeadLetter {
  envelope: EgressEnvelope
  attempts: number
  lastError: string
  deadLetteredAt: string
}

export interface DispatchResult {
  delivered: boolean
  attempts: number
  deadLetter: DeadLetter | null
}

/** Backoff for a given attempt number (1-based), capped. Exposed for tests. */
export function backoffDelay(attempt: number, policy: RetryPolicy): number {
  const raw = policy.baseDelayMs * Math.pow(2, Math.max(0, attempt - 1))
  return Math.min(raw, policy.maxDelayMs)
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * The egress dispatcher. Holds a bounded in-memory dead-letter queue so a sink
 * outage does not lose batches; operators drain it out of band. The dead-letter
 * queue is bounded; the granular leaves remain safe in the outbox regardless.
 */
export class EgressDispatcher {
  private readonly policy: RetryPolicy
  private readonly deadLetters: DeadLetter[] = []
  private readonly deadLetterLimit: number
  private readonly waitFn: (ms: number) => Promise<void>

  constructor(opts?: {
    policy?: RetryPolicy
    deadLetterLimit?: number
    /** Override the backoff wait, primarily for deterministic tests. */
    waitFn?: (ms: number) => Promise<void>
  }) {
    this.policy = opts?.policy ?? DEFAULT_RETRY_POLICY
    this.deadLetterLimit = opts?.deadLetterLimit ?? 1000
    this.waitFn = opts?.waitFn ?? sleep
  }

  /**
   * Dispatch one envelope to the sink with bounded retry. Emits
   * egress_dispatched on success, egress_retry per failed attempt that will be
   * retried, and egress_dead_lettered on exhaustion.
   */
  async dispatch(tenantId: string, sink: EgressSink, envelope: EgressEnvelope): Promise<DispatchResult> {
    let lastError = ''
    for (let attempt = 1; attempt <= this.policy.maxAttempts; attempt++) {
      try {
        await sink(envelope)
        emit(tenantId, 'egress_dispatched', {
          batch_id: envelope.batchId,
          merkle_root: envelope.merkleRoot,
          attempts: attempt,
          receipt_count: envelope.receiptCount,
        })
        return { delivered: true, attempts: attempt, deadLetter: null }
      } catch (e: unknown) {
        lastError = e instanceof Error ? e.message : String(e)
        const willRetry = attempt < this.policy.maxAttempts
        emit(tenantId, 'egress_retry', {
          batch_id: envelope.batchId,
          attempt,
          will_retry: willRetry,
          error: lastError,
        })
        if (willRetry) {
          await this.waitFn(backoffDelay(attempt, this.policy))
        }
      }
    }

    const dead: DeadLetter = {
      envelope,
      attempts: this.policy.maxAttempts,
      lastError,
      deadLetteredAt: new Date().toISOString(),
    }
    this.recordDeadLetter(dead)
    emit(tenantId, 'egress_dead_lettered', {
      batch_id: envelope.batchId,
      merkle_root: envelope.merkleRoot,
      attempts: dead.attempts,
      error: lastError,
    })
    return { delivered: false, attempts: this.policy.maxAttempts, deadLetter: dead }
  }

  private recordDeadLetter(dead: DeadLetter): void {
    this.deadLetters.push(dead)
    if (this.deadLetters.length > this.deadLetterLimit) {
      this.deadLetters.splice(0, this.deadLetters.length - this.deadLetterLimit)
    }
  }

  /** Snapshot the dead-letter queue (for an operator drain endpoint). */
  listDeadLetters(): readonly DeadLetter[] {
    return [...this.deadLetters]
  }

  deadLetterCount(): number {
    return this.deadLetters.length
  }

  /** Re-dispatch a dead-lettered batch by id. Removes it from the queue first
   *  so a redelivery failure re-enqueues a fresh dead letter rather than
   *  duplicating. Returns null if the id is not dead-lettered. */
  async redeliver(tenantId: string, sink: EgressSink, batchId: string): Promise<DispatchResult | null> {
    const idx = this.deadLetters.findIndex((d) => d.envelope.batchId === batchId)
    if (idx < 0) return null
    const [dead] = this.deadLetters.splice(idx, 1)
    return this.dispatch(tenantId, sink, dead.envelope)
  }
}

function emit(tenantId: string, type: 'egress_dispatched' | 'egress_retry' | 'egress_dead_lettered', data: Record<string, unknown>): void {
  try { getEventBus().emit(tenantId, { type, data }) } catch { /* bus failure must not break egress */ }
}
