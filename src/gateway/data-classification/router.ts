// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Data classification router (G-D3)
// ══════════════════════════════════════════════════════════════════
// Attaches a class + confidence + verifier-derived grade to an existing
// data source FROM A CONNECTOR LABEL. The label is the only input; there
// is no payload-scanning path. The class is attached at/after source
// registration via a SIBLING endpoint on this NEW router, so we never
// edit the enforce.ts POST /data-sources internals and the worktree
// boundary stays clean.
//
//   PUT /api/v1/data-sources/:source_id/classification
//        body: a connector source label (ConnectorSourceLabel). The
//        gateway derives the grade, signs the classification with the
//        existing gateway identity, persists class columns on the
//        existing data_sources row, and emits 'source_classified'.
//
//   GET /api/v1/data-sources/:source_id/classification
//        returns the recorded classification for the source.
//
// Thin: this router coordinates, checks-before (source exists and is
// active), persists, signs, and emits. It is not the trusted brain.
// ══════════════════════════════════════════════════════════════════

import { Router } from 'express'
import { createHash } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import type { Tenant } from '../../auth/api-keys.js'
import { getEventBus } from '../events.js'
import { getGatewayIdentity } from '../identity.js'
import { classifyFromLabel } from './source-class.js'
import { isConnectorSourceLabel } from './connector-label.js'
import type { ConnectorSourceLabel } from './connector-label.js'

export const dataClassificationRouter = Router()

const CLASSIFICATION_SCHEMA_VERSION = '1.0'

// PUT /api/v1/data-sources/:source_id/classification
// Attach a class to a source from a connector label.
dataClassificationRouter.put('/data-sources/:source_id/classification', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { source_id } = req.params

  // The body IS the connector label. Classification reads ONLY this
  // label, never the source payload. A malformed label is rejected so we
  // never silently produce an unclassified-but-asserted source.
  const label = req.body as unknown
  if (!isConnectorSourceLabel(label)) {
    return res.status(400).json({
      error: 'Body must be a connector source label { connectorId, sourceId, declaredClass, confidence: declared|detected|inferred, recordType?, fieldRef? }',
    })
  }
  // TODO(G-C1 / gw-c1-connectors): the label will arrive as a typed
  //   ConnectorSourceLabel emitted by the connector module rather than as
  //   a raw request body. Until G-C1 lands, the customer/connector posts
  //   the label shape directly and we validate it here.
  const sourceLabel = label as ConnectorSourceLabel

  // The path source_id is authoritative; the label must agree.
  if (sourceLabel.sourceId !== source_id) {
    return res.status(400).json({ error: 'Label sourceId does not match path source_id' })
  }

  const db = getDB()
  const src = db
    .prepare(`SELECT * FROM data_sources WHERE tenant_id = ? AND source_id = ? AND status = 'active'`)
    .get(tenant.id, source_id) as any
  if (!src) {
    return res.status(404).json({ error: `Data source "${source_id}" not found or revoked` })
  }

  // Derive the classification (verifier-derived grade, thin + pure).
  const classification = classifyFromLabel(sourceLabel)

  const evidenceJson = JSON.stringify(classification.evidence)
  const classifiedAt = new Date().toISOString()

  // Hashes for the public receipt body - we never expose the raw label
  // or source content. source_hash binds the receipt to the source id;
  // evidence_hash binds it to the label provenance.
  const sourceHash = createHash('sha256').update(`${tenant.id}:${source_id}`).digest('hex')
  const evidenceHash = createHash('sha256').update(evidenceJson).digest('hex')

  // Sign the classification attestation with the EXISTING gateway key.
  // We do not generate new keys. The signed payload is the graded claim.
  // TODO(W2-set): emit a SET (Security Event Token) for this
  //   classification decision via the SDK SET emitter once Wave 2 lands.
  const attestation = getGatewayIdentity().sign({
    kind: 'source_classification',
    schema_version: CLASSIFICATION_SCHEMA_VERSION,
    tenant_id: tenant.id,
    source_id,
    data_class: classification.dataClass,
    confidence: classification.confidence,
    grade: classification.grade,
    evidence_quality: classification.evidenceQuality,
    source_hash: sourceHash,
    evidence_hash: evidenceHash,
    classified_at: classifiedAt,
  })

  db.prepare(
    `UPDATE data_sources
       SET data_class = ?, class_confidence = ?, class_grade = ?,
           class_evidence = ?, class_source_label = ?, classified_at = ?
     WHERE tenant_id = ? AND source_id = ?`,
  ).run(
    classification.dataClass,
    classification.confidence,
    classification.grade,
    evidenceJson,
    JSON.stringify(sourceLabel),
    classifiedAt,
    tenant.id,
    source_id,
  )

  try {
    getEventBus().emit(tenant.id, {
      type: 'source_classified',
      data: {
        source_id,
        data_class: classification.dataClass,
        confidence: classification.confidence,
        grade: classification.grade,
      },
    })
  } catch {}

  return res.status(200).json({
    source_id,
    data_class: classification.dataClass,
    confidence: classification.confidence,
    grade: classification.grade,
    evidence_quality: classification.evidenceQuality,
    classified_at: classifiedAt,
    attestation,
  })
})

// GET /api/v1/data-sources/:source_id/classification
dataClassificationRouter.get('/data-sources/:source_id/classification', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { source_id } = req.params
  const db = getDB()
  const src = db
    .prepare(`SELECT * FROM data_sources WHERE tenant_id = ? AND source_id = ?`)
    .get(tenant.id, source_id) as any
  if (!src) {
    return res.status(404).json({ error: `Data source "${source_id}" not found` })
  }
  if (!src.data_class) {
    return res.status(200).json({ source_id, classified: false })
  }
  return res.status(200).json({
    source_id,
    classified: true,
    data_class: src.data_class,
    confidence: src.class_confidence,
    grade: src.class_grade,
    evidence: src.class_evidence ? JSON.parse(src.class_evidence) : null,
    classified_at: src.classified_at,
  })
})
