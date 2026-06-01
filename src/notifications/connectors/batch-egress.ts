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

import { buildConnectorEvent, type ConnectorBatchRef, type ConnectorEvent } from './event-schema.js'

// TODO(G-A1 / gw-a1-event-merkle): import type { EgressEnvelope } from
//   '../../gateway/egress/index.js'. egress/ is not merged into base 5ccdac7,
//   so the input type is the locally-mirrored ConnectorBatchRef (field-identical
//   to EgressEnvelope). When egress/ lands, accept EgressEnvelope directly and
//   register this adapter as a G-A1 EgressSink so egressCommittedBatch drives it.

/** Adapt a G-A1 batch envelope (mirrored here as ConnectorBatchRef) into a
 *  versioned connector event. */
export function batchToConnectorEvent(tenantId: string, batch: ConnectorBatchRef): ConnectorEvent {
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
