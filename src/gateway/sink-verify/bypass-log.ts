// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Sink bypass log - append-only record of rejected / bypassed actions
// ══════════════════════════════════════════════════════════════════
// Sink verification supports evidence that the receiving API checked the
// receipt before accepting the action. It does NOT, by itself, show that
// nothing happened before the check if the sink was bypassed (an attacker
// calling the underlying tool directly, around the verifier). That gap is
// why every reject - and every call that reached the protected handler
// WITHOUT a verified verdict - is logged here. The log is the trail a
// bypass leaves.
//
// This is deliberately storage-agnostic. The receiving API plugs in its
// own sink (SIEM, append-only table, Sigstore/rekor). The default is a
// bounded in-memory ring so the drop-in works with zero wiring, and so a
// flood of rejects cannot exhaust memory.
// ══════════════════════════════════════════════════════════════════

export type BypassReason =
  /** A receipt was presented and the verifier rejected it. */
  | 'rejected'
  /** The protected handler was reached with no verified verdict at all
   *  (no receipt header, or the verifier never ran). This is the
   *  direct-call / bypass case. */
  | 'missing_verdict'

export interface BypassEvent {
  /** ISO-8601 UTC. */
  at: string
  reason: BypassReason
  agent_id: string
  receipt_id: string
  /** Scope the sink was asked to act on, when known. */
  scope_required: string
  /** Violation codes from the verdict, or a single bypass marker. */
  violations: string[]
  /** Free-form locator the sink controls (route, source ip ref, etc.).
   *  The verifier never populates this with anything it cannot see; the
   *  caller decides what is safe to record. */
  context?: string
}

/** Where bypass events go. The receiving API supplies its own. */
export interface BypassSink {
  record(event: BypassEvent): void
}

/** Bounded in-memory ring buffer. Default sink when the caller provides
 *  none. Keeps the most recent `capacity` events; never grows unbounded. */
export class MemoryBypassSink implements BypassSink {
  private readonly buf: BypassEvent[] = []
  constructor(private readonly capacity = 1000) {}

  record(event: BypassEvent): void {
    this.buf.push(event)
    if (this.buf.length > this.capacity) this.buf.shift()
  }

  /** Snapshot for tests and for an operator pulling recent events. */
  recent(limit?: number): BypassEvent[] {
    if (limit === undefined || limit >= this.buf.length) return [...this.buf]
    return this.buf.slice(this.buf.length - limit)
  }

  get size(): number {
    return this.buf.length
  }
}

/** Build a bypass event from a sink verdict-like object. Used by both the
 *  reference middleware and direct drop-in callers so the recorded shape
 *  is identical everywhere. */
export function bypassEventFromVerdict(opts: {
  reason: BypassReason
  agent_id?: string
  receipt_id?: string
  scope_required?: string
  violations?: string[]
  context?: string
}): BypassEvent {
  return {
    at: new Date().toISOString(),
    reason: opts.reason,
    agent_id: opts.agent_id ?? '',
    receipt_id: opts.receipt_id ?? '',
    scope_required: opts.scope_required ?? '',
    violations: opts.violations ?? [],
    context: opts.context,
  }
}
