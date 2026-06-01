// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - OpenTelemetry adapter with OCSF formatting
// ══════════════════════════════════════════════════════════════════
// Transport: OpenTelemetry logs (OTLP/HTTP). Format: OCSF (see ../ocsf.ts).
// A connector event is mapped to an OCSF record and wrapped as an OTLP log
// record body so a customer's OTel collector ingests it into their SIEM with a
// standard schema. The HTTP POST is injected so production wires the OTLP
// endpoint and tests assert the emitted shape without a network.
//
// Thin gateway: the gateway emits the OCSF/OTLP payload; the customer's
// collector and SIEM run their own reaction logic. No enforcement here.
// ══════════════════════════════════════════════════════════════════

import { toOcsf, type OcsfRecord } from '../ocsf.js'
import { ConnectorDeliveryError } from '../connector.js'
import type { ConnectorSink } from '../connector.js'
import type { ConnectorEvent } from '../event-schema.js'

export interface OtlpPostRequest {
  url: string
  body: string
  headers: Record<string, string>
}

/** Wrap an OCSF record as a minimal OTLP/HTTP logs payload (resourceLogs ->
 *  scopeLogs -> logRecords). The OCSF record is carried as the structured log
 *  body so the collector preserves the schema. */
export function toOtlpLogs(event: ConnectorEvent): Record<string, unknown> {
  const ocsf = toOcsf(event)
  const timeUnixNano = String((Date.parse(event.emitted_at) || Date.now()) * 1_000_000)
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: 'aeoess-gateway' } },
            { key: 'aeoess.tenant_id', value: { stringValue: event.tenant_id } },
          ],
        },
        scopeLogs: [
          {
            scope: { name: 'aeoess.connectors', version: event.schema_version },
            logRecords: [
              {
                timeUnixNano,
                severityNumber: ocsf.severity_id,
                body: { kvlistValue: { values: ocsfToOtlpKv(ocsf) } },
                attributes: [
                  { key: 'ocsf.class_uid', value: { intValue: ocsf.class_uid } },
                  { key: 'ocsf.activity_id', value: { intValue: ocsf.activity_id } },
                  { key: 'event.id', value: { stringValue: event.event_id } },
                ],
              },
            ],
          },
        ],
      },
    ],
  }
}

function ocsfToOtlpKv(ocsf: OcsfRecord): Array<{ key: string; value: { stringValue: string } }> {
  // OTLP body as a kvlist of stringified OCSF fields keeps the collector mapping
  // simple and lossless; the full OCSF JSON is also included for fidelity.
  return [{ key: 'ocsf', value: { stringValue: JSON.stringify(ocsf) } }]
}

/** Build an OTel+OCSF ConnectorSink. */
export function makeOtelOcsfSink(opts: {
  url: string
  httpPost: (req: OtlpPostRequest) => Promise<{ status: number }>
  headers?: Record<string, string>
}): ConnectorSink {
  return async (event: ConnectorEvent) => {
    const body = JSON.stringify(toOtlpLogs(event))
    const res = await opts.httpPost({
      url: opts.url,
      body,
      headers: { 'content-type': 'application/json', ...(opts.headers ?? {}) },
    })
    if (res.status < 200 || res.status >= 300) {
      throw new ConnectorDeliveryError(`OTLP export returned ${res.status}`, res.status)
    }
  }
}
