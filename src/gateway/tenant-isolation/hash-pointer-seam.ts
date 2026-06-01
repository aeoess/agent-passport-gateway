// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - Hash-and-pointer envelope seam
// ══════════════════════════════════════════════════════════════════
// Regulated-tenant rule: the gateway stores ONLY hashes and references,
// NEVER PHI or raw sensitive payloads. A receipt or signal that crosses
// into gateway storage must carry a content hash plus a pointer the
// customer can resolve against their own (in-tenant) store, not the
// payload bytes.
//
// The canonical hash-and-pointer envelope is an SDK Wave 2 primitive
// (W2-B6) that is NOT present in the installed pin. This module is the
// typed seam. It composes with the gateway's existing hash side -
// payloadFingerprint() in receipt-projection.ts - so we do not reinvent
// the SHA-256 surface, we wrap it into the envelope shape.
// ══════════════════════════════════════════════════════════════════

import { payloadFingerprint } from '../receipt-projection.js'

/** A hash-and-pointer envelope. Carries NO payload bytes. */
export interface HashPointerEnvelope {
  /** sha256 hex of the canonical payload bytes. */
  contentHash: string
  /** Customer-resolvable reference to where the payload actually lives
   *  (in-tenant store URI, object key). The gateway never dereferences it. */
  pointer: string
  /** Algorithm tag for forward-compat. */
  alg: 'sha256'
  /** Optional content type hint (not the content). */
  contentType?: string
}

/** Fields that, if present at the top level of an object handed to the
 *  gateway, indicate raw sensitive payload leaking past the hash-and-pointer
 *  boundary. Used by assertNoRawPayload as a defence-in-depth tripwire. */
const RAW_PAYLOAD_TRIPWIRES = [
  'phi', 'raw_payload', 'payload_plaintext', 'patient', 'ssn',
  'mrn', 'dob', 'diagnosis', 'plaintext', 'body_raw',
]

/**
 * Build a hash-and-pointer envelope from a payload + a customer pointer.
 * The payload is hashed and discarded; only the hash and pointer survive.
 *
 * @param payload      canonical payload bytes/string. Hashed, never stored.
 * @param pointer      customer-resolvable reference to the payload.
 * @param contentType  optional content-type hint.
 */
export function toHashPointer(
  payload: string | Buffer,
  pointer: string,
  contentType?: string,
): HashPointerEnvelope {
  // TODO(W2-B6): replace with the SDK hash-and-pointer call - canonical
  // hash-and-pointer envelope where the gateway stores hash + reference
  // only, never PHI / raw payload. Compose over payloadFingerprint for the
  // hash side. Expected shape:
  //   import { sealHashPointer } from 'agent-passport-system'
  //   return sealHashPointer({ payload, pointer, alg: 'sha256' })
  if (!pointer || typeof pointer !== 'string') {
    throw new Error('hash-and-pointer requires a customer-resolvable pointer')
  }
  return {
    contentHash: payloadFingerprint(payload),
    pointer,
    alg: 'sha256',
    ...(contentType ? { contentType } : {}),
  }
}

/**
 * Defence-in-depth tripwire. Throws if a record about to be persisted by the
 * gateway carries a field that smells like raw sensitive payload. This does
 * not replace the hash-and-pointer discipline - it catches a coding mistake
 * where a raw field slips through.
 */
export function assertNoRawPayload(record: Record<string, unknown>): void {
  for (const key of Object.keys(record)) {
    const lower = key.toLowerCase()
    if (RAW_PAYLOAD_TRIPWIRES.some((t) => lower === t || lower.includes(t))) {
      throw new Error(
        `hash-and-pointer violation: field "${key}" looks like raw sensitive payload; store a hash + pointer instead`,
      )
    }
  }
}

/** True if the envelope carries only a hash + pointer (no payload bytes). */
export function isHashOnly(env: HashPointerEnvelope): boolean {
  return (
    typeof env.contentHash === 'string' &&
    /^[0-9a-f]{64}$/.test(env.contentHash) &&
    typeof env.pointer === 'string' &&
    env.pointer.length > 0 &&
    !('payload' in env) &&
    !('body' in env)
  )
}
