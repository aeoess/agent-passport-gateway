// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Connector source-label seam (G-C1 dependency)
// ══════════════════════════════════════════════════════════════════
// Classification reads a LABELED source descriptor emitted by a
// connector (a Salesforce field, an Epic record type, a connector
// label). It NEVER scans the gateway payload to derive a class. The
// label is the only input to the class.
//
// G-C1 (gw-c1-connectors) is an A+B branch whose connector source-label
// surface does not exist yet (verified: that branch has no committed and
// no uncommitted connector code). So we depend on its INTENDED public
// shape only and stub the import. When G-C1 lands its emitted-label
// surface, swap the local interface for the real import and delete this
// local definition. Never reach into G-C1 internals; depend only on the
// emitted-label public shape below.
//
// TODO(G-C1 / gw-c1-connectors): import { ConnectorSourceLabel } from the
//   connectors module and remove this local definition. Integration point:
//   classifySource() in source-class.ts consumes a ConnectorSourceLabel,
//   never a raw payload.
// ══════════════════════════════════════════════════════════════════

/** How a connector arrived at the class it reports for a source. This is
 *  a SOURCE-SUPPLIED input, not a gateway verdict. The assurance grade
 *  derived from it is the verdict. */
export type SourceConfidence = 'declared' | 'detected' | 'inferred'

/** A labeled source descriptor emitted by a connector. Mirrors the
 *  intended G-C1 public shape. The connector is the labeling authority;
 *  the gateway records what the connector asserts and derives a grade. */
export interface ConnectorSourceLabel {
  /** Stable connector identifier, e.g. 'salesforce', 'epic'. */
  connectorId: string
  /** The source the label applies to. Matches data_sources.source_id. */
  sourceId: string
  /** The class the source declares for itself, e.g. 'phi', 'pii',
   *  'public'. The vocabulary is owned by the classification module
   *  behind the W2-classification seam (see data-class.ts). */
  declaredClass: string
  /** How the connector arrived at declaredClass. */
  confidence: SourceConfidence
  /** Optional record-type context, e.g. an Epic record type. */
  recordType?: string
  /** Optional field reference, e.g. a Salesforce field path. */
  fieldRef?: string
}

/** Type guard for a well-formed connector label. Used at the registration
 *  boundary so a malformed label is rejected rather than silently
 *  producing an unclassified source. */
export function isConnectorSourceLabel(value: unknown): value is ConnectorSourceLabel {
  if (value === null || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  const confidenceOk = v.confidence === 'declared' || v.confidence === 'detected' || v.confidence === 'inferred'
  return (
    typeof v.connectorId === 'string' && v.connectorId.length > 0 &&
    typeof v.sourceId === 'string' && v.sourceId.length > 0 &&
    typeof v.declaredClass === 'string' && v.declaredClass.length > 0 &&
    confidenceOk &&
    (v.recordType === undefined || typeof v.recordType === 'string') &&
    (v.fieldRef === undefined || typeof v.fieldRef === 'string')
  )
}
