// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - G-A1 batch egress -> connector fan-out
// ══════════════════════════════════════════════════════════════════
// The integration seam between G-A1's committed-batch egress and this module's
// connector fan-out. G-A1 emits a small EgressEnvelope (root + summary, no
// leaves) per committed batch; this adapts that envelope into a versioned
// ConnectorEvent and fans it out to every endpoint subscribed to
// 'batch_committed', each delivery going through the dispatcher's retry + DLQ.
//
// This keeps the cost-at-scale property G-A1 designed for: only the small
// envelope travels to each connector, never the granular leaves. Customers
// fetch leaves out of band on anomaly via the G-A1 leaf-fetch surface.
// ══════════════════════════════════════════════════════════════════

import { buildConnectorEvent, type ConnectorEvent } from './event-schema.js'
import type { EgressEnvelope, EgressSink } from '../../gateway/egress/index.js'
import type { ConnectorKind, ConnectorSink } from './connector.js'
import { ConnectorDispatcher } from './dispatcher.js'

// G-A1 egress is now merged. We take G-A1's real EgressEnvelope directly (its
// alias ConnectorBatchRef is identical) and expose makeBatchEgressSink, which
// returns a real G-A1 EgressSink so egressCommittedBatch can drive the
// connector fan-out: each committed batch envelope is adapted to a versioned
// ConnectorEvent and delivered through the connector dispatcher's retry + DLQ.

/** Adapt a G-A1 batch envelope into a versioned connector event. The envelope
 *  carries the root and a structural summary only, never the granular leaves. */
export function batchToConnectorEvent(tenantId: string, batch: EgressEnvelope): ConnectorEvent {
  return buildConnectorEvent({
    eventType: 'batch_committed',
    eventId: `batch-${batch.batchId}`,
    tenantId,
    emittedAt: batch.committedAt,
    batch,
    data: {
      merkle_root: batch.merkleRoot,
      epoch: batch.epoch,
      receipt_count: batch.receiptCount,
      previous_batch_id: batch.previousBatchId,
    },
  })
}

/**
 * Compose the connector fan-out as a real G-A1 EgressSink. The returned sink
 * has the exact ({@link EgressEnvelope}) => Promise<void> shape G-A1's
 * egressCommittedBatch / EgressDispatcher expect, so the batch egress path can
 * drive a connector delivery directly: it adapts the committed envelope into a
 * versioned ConnectorEvent and hands it to the supplied ConnectorSink through
 * the connector dispatcher (retry + durable dead-letter). The sink rejects on
 * exhaustion so G-A1's own retry/DLQ still observes the failure.
 */
export function makeBatchEgressSink(opts: {
  tenantId: string
  kind: ConnectorKind
  sink: ConnectorSink
  dispatcher?: ConnectorDispatcher
  endpointId?: string | null
}): EgressSink {
  const dispatcher = opts.dispatcher ?? new ConnectorDispatcher()
  return async (envelope: EgressEnvelope): Promise<void> => {
    const event = batchToConnectorEvent(opts.tenantId, envelope)
    const result = await dispatcher.deliver(
      opts.tenantId,
      opts.kind,
      opts.sink,
      event,
      opts.endpointId ?? null,
    )
    if (!result.delivered) {
      throw new Error(`connector fan-out exhausted for batch ${envelope.batchId}`)
    }
  }
}
