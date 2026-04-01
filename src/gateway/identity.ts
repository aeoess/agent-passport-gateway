// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Gateway Identity — Ed25519 signing keypair for attestation JWS.
 * 
 * The gateway needs its own identity to sign trust attestations
 * that external verifiers (insumer-examples, OATR, etc.) can verify
 * via the JWKS endpoint at /.well-known/jwks.json.
 * 
 * Key persistence: stored in the SQLite DB (gateway_identity table).
 * Generated once on first boot, reused thereafter.
 */

import crypto from 'node:crypto'
import { getDB } from '../db/schema.js'

const KID = 'gateway-v1'

interface GatewayIdentity {
  kid: string
  publicKeyJwk: JsonWebKey
  publicKeyHex: string
  sign: (payload: Record<string, unknown>) => string  // returns JWS compact
}

let _identity: GatewayIdentity | null = null

/**
 * Initialize or load the gateway Ed25519 keypair.
 * Call once at startup after DB init.
 */
export function initGatewayIdentity(): GatewayIdentity {
  if (_identity) return _identity

  const db = getDB()

  // Ensure table exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS gateway_identity (
      kid TEXT PRIMARY KEY,
      public_key_hex TEXT NOT NULL,
      private_key_hex TEXT NOT NULL,
      public_key_jwk TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `)

  // Check for existing key
  const existing = db.prepare(
    `SELECT * FROM gateway_identity WHERE kid = ?`
  ).get(KID) as any

  if (existing) {
    const publicKeyJwk = JSON.parse(existing.public_key_jwk)
    const privKeyBuf = Buffer.from(existing.private_key_hex, 'hex')

    _identity = {
      kid: KID,
      publicKeyJwk,
      publicKeyHex: existing.public_key_hex,
      sign: (payload) => signJws(payload, privKeyBuf),
    }
    console.log(`Gateway identity loaded: ${KID} (${existing.public_key_hex.slice(0, 16)}...)`)
    return _identity
  }

  // Generate new keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')

  const pubJwk = publicKey.export({ format: 'jwk' })
  const pubHex = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-32).toString('hex')
  const privHex = (privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer).subarray(-32).toString('hex')

  db.prepare(
    `INSERT INTO gateway_identity (kid, public_key_hex, private_key_hex, public_key_jwk) VALUES (?, ?, ?, ?)`
  ).run(KID, pubHex, privHex, JSON.stringify(pubJwk))

  _identity = {
    kid: KID,
    publicKeyJwk: pubJwk,
    publicKeyHex: pubHex,
    sign: (payload) => signJws(payload, Buffer.from(privHex, 'hex')),
  }
  console.log(`Gateway identity generated: ${KID} (${pubHex.slice(0, 16)}...)`)
  return _identity
}

export function getGatewayIdentity(): GatewayIdentity {
  if (!_identity) throw new Error('Gateway identity not initialized. Call initGatewayIdentity() first.')
  return _identity
}

/**
 * Get JWKS document for /.well-known/jwks.json
 */
export function getJwks(): { keys: Array<JsonWebKey & { kid: string; alg: string; use: string }> } {
  const id = getGatewayIdentity()
  return {
    keys: [
      {
        ...id.publicKeyJwk,
        kid: id.kid,
        alg: 'EdDSA',
        use: 'sig',
      },
    ],
  }
}

/**
 * Sign a payload as JWS compact (header.payload.signature)
 */
function signJws(payload: Record<string, unknown>, privKeyRaw: Buffer): string {
  // JWS header
  const header = { alg: 'EdDSA', kid: KID, typ: 'JWT' }
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')

  // Sign header.payload
  const signingInput = `${headerB64}.${payloadB64}`
  const privKey = crypto.createPrivateKey({
    key: Buffer.concat([
      // PKCS8 DER prefix for Ed25519 (30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20)
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      privKeyRaw,
    ]),
    format: 'der',
    type: 'pkcs8',
  })
  const sig = crypto.sign(null, Buffer.from(signingInput), privKey)
  const sigB64 = sig.toString('base64url')

  return `${headerB64}.${payloadB64}.${sigB64}`
}
