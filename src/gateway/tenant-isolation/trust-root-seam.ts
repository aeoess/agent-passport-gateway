// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - Customer bring-your-own trust root / HSM-KMS binding seam
// ══════════════════════════════════════════════════════════════════
// The gateway today generates its own Ed25519 signing key and stores it
// in the gateway_identity table (see identity.ts). For a regulated tenant
// the signing authority must live in the CUSTOMER'S HSM or KMS, and the
// customer brings their own trust root (the anchor that downstream sinks
// and offline verifiers pin). The gateway must NEVER hold or reimplement
// trust-root verification; it coordinates and records a pointer only.
//
// This module is the typed seam where that binding plugs in. The real
// validation and key binding are an SDK Wave 2 primitive (W2-B1) that is
// NOT present in the installed pin (agent-passport-system
// ^2.6.0-alpha.3). Until that ships, the gateway:
//   - accepts a customer trust-anchor descriptor + an opaque key reference
//     (HSM slot URI or KMS key ARN), NEVER private key material,
//   - records the binding as a hash + pointer on the tenant model,
//   - exposes a verify() seam a sink/offline-verifier can call.
//
// THIN-GATEWAY: enforcement lives at the edge. The customer HSM/KMS holds
// the key; the sink/offline verifier checks signatures against the
// customer-pinned trust root. The gateway is not the trusted central brain.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'

/** Where a tenant's signing authority lives. */
export type TrustRootSource = 'gateway' | 'hsm' | 'kms'

/** A customer-supplied trust anchor descriptor. The gateway treats this as
 *  opaque: it records a fingerprint + a pointer, and hands the actual
 *  validation to the SDK trust-root policy (W2-B1). It never parses or
 *  trusts the anchor itself. */
export interface CustomerTrustAnchor {
  /** Source of the signing key. */
  source: TrustRootSource
  /** Opaque reference to the key in the customer's HSM/KMS. NEVER the
   *  private key material. Examples: 'pkcs11:slot=3;object=tenant-signer'
   *  or 'arn:aws:kms:us-east-1:111122223333:key/abcd-...'. */
  keyRef: string
  /** Customer-pinned trust anchor public material (PEM/JWK/DID), opaque to
   *  the gateway. Sinks and offline verifiers pin THIS, not a gateway key. */
  anchorMaterial?: string
  /** Optional human label for the anchor (issuer name, ca id). */
  label?: string
}

/** The recorded binding. Stores a fingerprint and a pointer only - no key
 *  material crosses into gateway storage. */
export interface TrustRootBinding {
  source: TrustRootSource
  keyRef: string
  /** sha256 of the anchor material, the pinning fingerprint a verifier can
   *  compare against. Empty when source === 'gateway'. */
  anchorFingerprint: string
  boundAt: string
  label: string | null
}

/** Result of validating a customer trust anchor. `valid` is verifier-derived
 *  in production (W2-B1); the stub reports a shape check only and labels the
 *  assurance source so callers never mistake it for cryptographic validation. */
export interface TrustRootValidation {
  valid: boolean
  /** Where the assurance came from. 'shape-check-stub' until W2-B1 ships. */
  assuranceSource: 'shape-check-stub' | 'sdk-trust-root-policy'
  reason: string
}

/** Fingerprint a piece of anchor material. sha256 hex. */
export function anchorFingerprint(material: string): string {
  return createHash('sha256').update(material).digest('hex')
}

/**
 * Validate a customer trust anchor and bind the tenant signing key from the
 * customer HSM/KMS.
 *
 * In production this delegates to the SDK trust-root policy primitive, which
 * validates the anchor chain and binds the HSM/KMS key handle. The gateway
 * does NOT implement trust-root verification.
 */
export function validateCustomerTrustAnchor(
  anchor: CustomerTrustAnchor,
): TrustRootValidation {
  // TODO(W2-B1): replace this shape check with the SDK trust-root policy
  // call - validate the customer trust anchor chain and bind the tenant
  // signing key from the customer HSM/KMS. The SDK call will return a
  // verifier-derived validity, not an issuer-set one. Expected shape:
  //   import { validateTrustRoot } from 'agent-passport-system'
  //   return validateTrustRoot({ anchorMaterial, keyRef, source })
  if (anchor.source === 'gateway') {
    return {
      valid: true,
      assuranceSource: 'shape-check-stub',
      reason: 'gateway-generated key; no customer anchor to validate',
    }
  }
  const hasKeyRef = typeof anchor.keyRef === 'string' && anchor.keyRef.length > 0
  const hasAnchor = typeof anchor.anchorMaterial === 'string' && anchor.anchorMaterial.length > 0
  if (!hasKeyRef) {
    return {
      valid: false,
      assuranceSource: 'shape-check-stub',
      reason: 'missing HSM/KMS keyRef for non-gateway trust root',
    }
  }
  if (!hasAnchor) {
    return {
      valid: false,
      assuranceSource: 'shape-check-stub',
      reason: 'missing customer anchor material for non-gateway trust root',
    }
  }
  // Guard: a keyRef that looks like raw private key material is rejected
  // outright. The gateway must only ever see a reference, never the key.
  if (looksLikePrivateKeyMaterial(anchor.keyRef) || looksLikePrivateKeyMaterial(anchor.anchorMaterial || '')) {
    return {
      valid: false,
      assuranceSource: 'shape-check-stub',
      reason: 'rejected: input resembles raw private key material; supply a reference only',
    }
  }
  return {
    valid: true,
    assuranceSource: 'shape-check-stub',
    reason: 'shape valid; cryptographic validation deferred to SDK trust-root policy (W2-B1)',
  }
}

/**
 * Build the recorded binding for a validated anchor. Stores fingerprint +
 * pointer only. Callers persist this on the tenant model.
 */
export function bindTrustRoot(anchor: CustomerTrustAnchor): TrustRootBinding {
  const validation = validateCustomerTrustAnchor(anchor)
  if (!validation.valid) {
    throw new Error(`trust-root binding refused: ${validation.reason}`)
  }
  return {
    source: anchor.source,
    keyRef: anchor.keyRef,
    anchorFingerprint: anchor.anchorMaterial ? anchorFingerprint(anchor.anchorMaterial) : '',
    boundAt: new Date().toISOString(),
    label: anchor.label ?? null,
  }
}

/** Heuristic guard so a private key never gets recorded by mistake. */
function looksLikePrivateKeyMaterial(s: string): boolean {
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)
}
