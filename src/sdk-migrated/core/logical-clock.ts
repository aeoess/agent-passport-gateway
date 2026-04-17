// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// LogicalClock — per-instance counter wrapper around SDK time math
// ══════════════════════════════════════════════════════════════════════
// Migrated from SDK to gateway (2026-04-17). The SDK retains pure
// timestamp math primitives. The legacy module-scope counter still
// lives in SDK time.ts as a backward-compat path for callers that
// don't pass an explicit logical time, but new gateway code should
// prefer instances of this class so each enforcement context owns
// its own causal-ordering counter.
//
// Each LogicalClock instance is independent — no shared global state.
// ══════════════════════════════════════════════════════════════════════

import {
  createHybridTimestampAt, createTemporalBound,
  DEFAULT_NTP_DRIFT_MS,
} from 'agent-passport-system'
import type { HybridTimestamp, TemporalBound } from 'agent-passport-system'

export interface LogicalClockOptions {
  /** Initial counter value. Defaults to 0; first tick yields 1. */
  initial?: number
  /** Default NTP drift in ms applied to bounds. */
  driftMs?: number
}

export class LogicalClock {
  private counter: number
  private readonly driftMs: number

  constructor(opts: LogicalClockOptions = {}) {
    this.counter = opts.initial ?? 0
    this.driftMs = opts.driftMs ?? DEFAULT_NTP_DRIFT_MS
  }

  /** Current counter value without advancing. */
  current(): number {
    return this.counter
  }

  /** Reset to a specific value (default 0) — primarily for tests. */
  reset(to: number = 0): void {
    this.counter = to
  }

  /** Advance the counter and produce a hybrid timestamp. */
  tick(gatewayId: string, driftMs: number = this.driftMs): HybridTimestamp {
    this.counter++
    return createHybridTimestampAt(gatewayId, this.counter, driftMs)
  }

  /** Advance the counter and produce a temporal bound (timestamp + TTL). */
  bound(gatewayId: string, ttlMs: number, driftMs: number = this.driftMs): TemporalBound {
    return createTemporalBound(gatewayId, ttlMs, driftMs)
  }

  /** Observe an external timestamp and pull our counter forward to at
   *  least its logical time + 1 (Lamport-style merge). Returns the new
   *  counter value. */
  observe(other: HybridTimestamp): number {
    if (other.logicalTime >= this.counter) {
      this.counter = other.logicalTime + 1
    }
    return this.counter
  }
}
