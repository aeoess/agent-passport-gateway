// APS Regulated Action Profile v0: completeness / orphan layer (private gateway).
//
// The verifier answers "is THIS receipt reconciled?". Completeness answers the dual question
// "is every resource effect IN SCOPE backed by a reconciled receipt?". A resource event inside
// the declared coverage scope with no reconciled correlation id is an ORPHAN (an unreceipted
// effect). Events OUTSIDE the coverage scope are not orphans: the gateway does not claim coverage
// it does not have. This is the difference between "no orphans found" and "we are not looking".

export interface CoverageScope {
  resource: string
  tenant: string
}

export interface ResourceEvent {
  resource: string
  tenant: string
  resource_transaction_id: string
  timestamp_ms: number
  correlation_id?: string
}

export interface Orphan {
  resource_transaction_id: string
  timestamp_ms: number
}

export interface CompletenessInput {
  coverage_scope: CoverageScope
  resource_events: ResourceEvent[]
  // Reconciled-receipt identifiers. Per contract section E the left-join supports BOTH keys: an
  // event is covered if its correlation_id OR its resource_transaction_id matches a reconciled
  // receipt. reconciled_transaction_ids is optional for backward compatibility.
  reconciled_correlation_ids: string[]
  reconciled_transaction_ids?: string[]
}

/**
 * Detect orphans: in-scope resource events with no reconciled correlation id. Out-of-scope
 * events are filtered out (explicitly NOT reported as orphans, and NOT silently counted as
 * covered). The scope filter is what makes "0 orphans" an honest statement rather than a blind one.
 */
export function detectOrphans(input: CompletenessInput): { orphans: Orphan[]; out_of_scope: number; in_scope: number } {
  const reconciledCorr = new Set(input.reconciled_correlation_ids)
  const reconciledTx = new Set(input.reconciled_transaction_ids ?? [])
  const orphans: Orphan[] = []
  let inScope = 0
  let outOfScope = 0
  for (const ev of input.resource_events) {
    const isInScope = ev.resource === input.coverage_scope.resource && ev.tenant === input.coverage_scope.tenant
    if (!isInScope) { outOfScope++; continue }
    inScope++
    // Left-join on correlation_id OR resource_transaction_id (contract section E).
    const covered =
      (ev.correlation_id !== undefined && reconciledCorr.has(ev.correlation_id)) ||
      reconciledTx.has(ev.resource_transaction_id)
    if (!covered) orphans.push({ resource_transaction_id: ev.resource_transaction_id, timestamp_ms: ev.timestamp_ms })
  }
  return { orphans, out_of_scope: outOfScope, in_scope: inScope }
}
