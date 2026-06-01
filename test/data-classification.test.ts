// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D3 source-based data classification + destination control - unit tests
// ══════════════════════════════════════════════════════════════════
// These exercise the pure evaluators directly, no DB. They prove:
//   - the source LABEL is honored (class + confidence come from the label)
//   - there is NO payload-scanning path (classifyFromLabel takes only a
//     label; it has no payload parameter to scan)
//   - confidence is recorded as declared | detected | inferred
//   - the class is an assurance-GRADED claim (grade is verifier-derived,
//     not issuer-set: a higher-confidence label yields a higher grade)
//   - destination policy is enforced before-the-fact (class/role/purpose/
//     training gates), with the sink performing the actual confirmation.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { classifyFromLabel } from '../src/gateway/data-classification/source-class.js'
import type { ConnectorSourceLabel } from '../src/gateway/data-classification/connector-label.js'
import { isConnectorSourceLabel } from '../src/gateway/data-classification/connector-label.js'
import { checkDestination } from '../src/gateway/destinations/destination-policy.js'
import type { DestinationPolicy } from '../src/gateway/destinations/destination-policy.js'

function label(overrides: Partial<ConnectorSourceLabel> = {}): ConnectorSourceLabel {
  return {
    connectorId: 'salesforce',
    sourceId: 'src-001',
    declaredClass: 'pii',
    confidence: 'declared',
    recordType: 'Contact',
    fieldRef: 'Contact.Email',
    ...overrides,
  }
}

function destination(overrides: Partial<DestinationPolicy> = {}): DestinationPolicy {
  return {
    destinationId: 'dst-001',
    destinationName: 'Marketing Warehouse',
    placement: 'external',
    allowedDataClasses: ['public', 'internal'],
    allowedAgentRoles: [],
    allowedPurposes: [],
    storagePolicy: { persists: true, retentionLimit: 'P90D' },
    trainingPolicy: { allowsTraining: false },
    sinkConfirmationSupport: 'supported',
    riskTier: 'medium',
    ...overrides,
  }
}

describe('classifyFromLabel - source label is honored', () => {
  it('records the class verbatim from the connector label', () => {
    const c = classifyFromLabel(label({ declaredClass: 'phi' }))
    assert.equal(c.dataClass, 'phi')
    assert.equal(c.sourceId, 'src-001')
  })

  it('records confidence as declared | detected | inferred', () => {
    assert.equal(classifyFromLabel(label({ confidence: 'declared' })).confidence, 'declared')
    assert.equal(classifyFromLabel(label({ confidence: 'detected' })).confidence, 'detected')
    assert.equal(classifyFromLabel(label({ confidence: 'inferred' })).confidence, 'inferred')
  })

  it('carries the label provenance as evidence, never source content', () => {
    const c = classifyFromLabel(label())
    assert.equal(c.evidence.connectorId, 'salesforce')
    assert.equal(c.evidence.recordType, 'Contact')
    assert.equal(c.evidence.fieldRef, 'Contact.Email')
    // The classification never holds source payload bytes.
    assert.equal((c as any).payload, undefined)
    assert.equal((c as any).content, undefined)
  })

  it('honors a class outside the known vocabulary verbatim', () => {
    const c = classifyFromLabel(label({ declaredClass: 'export_controlled' }))
    assert.equal(c.dataClass, 'export_controlled')
  })
})

describe('classifyFromLabel - class is an assurance-graded claim (verifier-derived)', () => {
  it('a declared label with a field/record binding grades higher than an inferred one', () => {
    const declared = classifyFromLabel(label({ confidence: 'declared', fieldRef: 'Contact.SSN', recordType: 'Contact' }))
    const inferred = classifyFromLabel(label({ confidence: 'inferred', fieldRef: undefined, recordType: undefined }))
    assert.ok(declared.grade > inferred.grade, 'declared+bound must out-grade inferred')
  })

  it('grade is derived, not taken from the label (label has no grade field)', () => {
    const l = label()
    assert.equal((l as any).grade, undefined, 'label must not carry a grade')
    const c = classifyFromLabel(l)
    assert.equal(typeof c.grade, 'number')
    assert.ok(c.grade >= 0 && c.grade <= 3)
  })

  it('detected ranks at or above inferred (more system signal, more assurance)', () => {
    const detected = classifyFromLabel(label({ confidence: 'detected', fieldRef: undefined, recordType: undefined }))
    const inferred = classifyFromLabel(label({ confidence: 'inferred', fieldRef: undefined, recordType: undefined }))
    assert.ok(detected.grade >= inferred.grade)
  })

  it('surfaces the SDK evidence-quality bucket for audit', () => {
    const c = classifyFromLabel(label({ confidence: 'inferred', fieldRef: undefined, recordType: undefined }))
    assert.equal(c.evidenceQuality, 'none')
  })
})

describe('isConnectorSourceLabel - only a well-formed label classifies', () => {
  it('accepts a complete label', () => {
    assert.equal(isConnectorSourceLabel(label()), true)
  })
  it('rejects a missing connectorId', () => {
    assert.equal(isConnectorSourceLabel({ sourceId: 's', declaredClass: 'pii', confidence: 'declared' }), false)
  })
  it('rejects an invalid confidence value', () => {
    assert.equal(isConnectorSourceLabel({ ...label(), confidence: 'guessed' }), false)
  })
  it('rejects a non-object (no raw-payload coercion)', () => {
    assert.equal(isConnectorSourceLabel('phi'), false)
    assert.equal(isConnectorSourceLabel(null), false)
  })
})

describe('checkDestination - destination policy enforced before-the-fact', () => {
  it('denies a class the destination does not allow', () => {
    const r = checkDestination({ sourceClass: 'phi' }, destination(), true)
    assert.equal(r.decision, 'deny')
    assert.equal(r.reason, 'class_not_allowed')
  })

  it('permits a class the destination allows', () => {
    const r = checkDestination({ sourceClass: 'public' }, destination(), true)
    assert.equal(r.decision, 'permit')
    assert.equal(r.reason, 'destination_permits')
  })

  it('denies a revoked destination regardless of class', () => {
    const r = checkDestination({ sourceClass: 'public' }, destination(), false)
    assert.equal(r.decision, 'deny')
    assert.equal(r.reason, 'destination_revoked')
  })

  it('enforces allowed agent roles when set', () => {
    const d = destination({ allowedDataClasses: ['pii'], allowedAgentRoles: ['analyst'] })
    assert.equal(checkDestination({ sourceClass: 'pii', agentRole: 'intern' }, d, true).reason, 'role_not_allowed')
    assert.equal(checkDestination({ sourceClass: 'pii', agentRole: 'analyst' }, d, true).decision, 'permit')
  })

  it('enforces allowed purposes when set', () => {
    const d = destination({ allowedDataClasses: ['pii'], allowedPurposes: ['analyze'] })
    assert.equal(checkDestination({ sourceClass: 'pii', purpose: 'train' }, d, true).reason, 'purpose_not_allowed')
    assert.equal(checkDestination({ sourceClass: 'pii', purpose: 'analyze' }, d, true).decision, 'permit')
  })

  it('blocks training when the destination training policy forbids it', () => {
    const d = destination({ allowedDataClasses: ['pii'], trainingPolicy: { allowsTraining: false } })
    assert.equal(checkDestination({ sourceClass: 'pii', forTraining: true }, d, true).reason, 'training_not_allowed')
  })

  it('an internal destination cleared for a more sensitive class clears a less sensitive one', () => {
    const d = destination({ placement: 'internal', allowedDataClasses: ['secret'] })
    assert.equal(checkDestination({ sourceClass: 'internal' }, d, true).decision, 'permit')
  })

  it('an external destination requires an exact class listing (no implicit widening)', () => {
    const d = destination({ placement: 'external', allowedDataClasses: ['secret'] })
    assert.equal(checkDestination({ sourceClass: 'internal' }, d, true).reason, 'class_not_allowed')
  })

  it('records sink-confirmation support and risk tier on the verdict (sink confirms, not the gateway)', () => {
    const r = checkDestination({ sourceClass: 'public' }, destination(), true)
    assert.equal(r.sinkConfirmationSupport, 'supported')
    assert.equal(r.riskTier, 'medium')
  })

  it('a destination outside the known vocabulary still fails closed for unknown classes', () => {
    const d = destination({ placement: 'external', allowedDataClasses: ['public'] })
    assert.equal(checkDestination({ sourceClass: 'mystery_class' }, d, true).reason, 'class_not_allowed')
  })
})
