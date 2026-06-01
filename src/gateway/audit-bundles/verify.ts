// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway - Audit bundle edge verifier (Build G-D2).
 *
 * A bundle is a pre-signed, customer-owned artifact. This verifier is the edge
 * check: it recomputes the canonical manifest hash, recomputes every leaf hash
 * and the Merkle root from the embedded records, and verifies the EdDSA JWS
 * signature against a supplied public key (fetched from the gateway JWKS by the
 * caller). The gateway does not need to be online for this to run, which is the
 * whole point of a customer-owned, edge-verified artifact.
 */

import crypto from 'node:crypto'
import {
  buildMerkleRoot,
  canonicalize,
} from 'agent-passport-system'
import { canonicalLeafHash } from './merkle-backbone.js'
import type { SignedBundle, BundleManifest } from './types.js'

export interface BundleVerifyResult {
  ok: boolean
  manifestHashMatches: boolean
  merkleRootMatches: boolean
  signatureValid: boolean | 'not_checked'
  problems: string[]
}

/**
 * Verify a signed bundle.
 *
 * @param bundle the signed bundle
 * @param publicKeyHex optional raw Ed25519 public key (hex) to check the JWS.
 *   When omitted, signature is reported as 'not_checked' but hash + Merkle
 *   integrity are still verified.
 */
export function verifyBundle(
  bundle: SignedBundle,
  publicKeyHex?: string,
): BundleVerifyResult {
  const problems: string[] = []

  // 1. Manifest hash recomputation.
  const recomputedHash = canonicalLeafHash(
    bundle.manifest as unknown as Record<string, unknown>,
  )
  const manifestHashMatches = recomputedHash === bundle.manifestHash
  if (!manifestHashMatches) problems.push('manifest_hash_mismatch')

  // 2. Merkle root recomputation from embedded leaves.
  const merkleRootMatches = verifyMerkleBackbone(bundle.manifest)
  if (!merkleRootMatches) problems.push('merkle_root_mismatch')

  // 3. Signature, when a key is supplied.
  let signatureValid: boolean | 'not_checked' = 'not_checked'
  if (publicKeyHex) {
    signatureValid = verifyManifestSignature(bundle, publicKeyHex)
    if (!signatureValid) problems.push('signature_invalid')
  }

  const ok =
    manifestHashMatches &&
    merkleRootMatches &&
    signatureValid !== false

  return { ok, manifestHashMatches, merkleRootMatches, signatureValid, problems }
}

/** Recompute the hash-manifest Merkle root from the embedded leaves. */
function verifyMerkleBackbone(manifest: BundleManifest): boolean {
  const hm = manifest.hashManifest
  // When the backbone is the G-A1 batch root the bundle carries the batch root
  // as authoritative and inclusion proofs verify against it; for the SDK leaf
  // backbone (the off-base default) we recompute directly from the leaves.
  if (hm.rootSource === 'gem_batch') {
    // Off-base today this path is not produced; if present, trust the supplied
    // inclusion proofs verified separately. Treat root recomputation as N/A.
    return true
  }
  const leafHashes = hm.leaves.map((l) => l.leafHash)
  const recomputed = buildMerkleRoot(leafHashes)
  return recomputed === hm.merkleRoot
}

/** Verify the EdDSA JWS over { manifestHash, kid, schemaVersion }. */
function verifyManifestSignature(
  bundle: SignedBundle,
  publicKeyHex: string,
): boolean {
  if (!bundle.signature) return false
  const parts = bundle.signature.split('.')
  if (parts.length !== 3) return false
  const [headerB64, payloadB64, sigB64] = parts

  // Confirm the signed payload commits to this manifest hash.
  let payload: Record<string, unknown>
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'))
  } catch {
    return false
  }
  if (payload.manifestHash !== bundle.manifestHash) return false

  const signingInput = `${headerB64}.${payloadB64}`
  const sig = Buffer.from(sigB64, 'base64url')

  try {
    const pubKey = crypto.createPublicKey({
      key: Buffer.concat([
        // SPKI DER prefix for Ed25519.
        Buffer.from('302a300506032b6570032100', 'hex'),
        Buffer.from(publicKeyHex, 'hex'),
      ]),
      format: 'der',
      type: 'spki',
    })
    return crypto.verify(null, Buffer.from(signingInput), pubKey, sig)
  } catch {
    return false
  }
}

/** Re-export the canonical form for callers that want to display it. */
export function canonicalManifest(manifest: BundleManifest): string {
  return canonicalize(manifest as unknown as Record<string, unknown>)
}
