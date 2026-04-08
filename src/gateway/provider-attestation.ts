// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Provider Attestation — MolTrust DID resolution + delegation chain verification
 *
 * POST /attestation/provider-verify — verify DID + delegation chain derivation_rights
 */

import { Router } from 'express'
import { randomUUID, createHash } from 'node:crypto'
import { getDB } from '../db/schema.js'
import { getGatewayIdentity } from './identity.js'
import type { Tenant } from '../auth/api-keys.js'

export const providerAttestationRouter = Router()

interface DerivationRights {
  retention_permitted: boolean
  retention_ttl?: number
  derivation_classes?: string[]
  export_permitted: boolean
}

interface DelegationInput {
  delegationId: string
  delegatedTo: string
  delegatedBy: string
  scope: string[]
  derivation_rights?: DerivationRights
}

function verifyDerivationNarrowing(parent: DerivationRights, child: DerivationRights): string | null {
  if (!parent.retention_permitted && child.retention_permitted) {
    return 'child enables retention but parent does not permit it'
  }
  if (parent.retention_ttl !== undefined && child.retention_ttl !== undefined && child.retention_ttl > parent.retention_ttl) {
    return `child retention_ttl (${child.retention_ttl}) exceeds parent (${parent.retention_ttl})`
  }
  if (!parent.export_permitted && child.export_permitted) {
    return 'child enables export but parent does not permit it'
  }
  if (parent.derivation_classes && child.derivation_classes) {
    const invalid = child.derivation_classes.filter(c => !parent.derivation_classes!.includes(c))
    if (invalid.length > 0) return `child classes [${invalid}] not in parent [${parent.derivation_classes}]`
  }
  return null
}

async function resolveMolTrustDID(did: string): Promise<{ resolved: boolean; status?: string; error?: string }> {
  try {
    const res = await fetch('https://api.moltrust.ch/identity/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did }),
      signal: AbortSignal.timeout(5000),
    })
    if (!res.ok) return { resolved: false, error: `HTTP ${res.status}` }
    const data = await res.json() as any
    return { resolved: true, status: data.status || data.trust_standing || 'unknown' }
  } catch (e) {
    return { resolved: false, error: (e as Error).message }
  }
}

providerAttestationRouter.post('/attestation/provider-verify', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { did, delegationChain } = req.body as { did?: string; delegationChain?: DelegationInput[] }

  if (!did || !delegationChain || !Array.isArray(delegationChain) || delegationChain.length === 0) {
    return res.status(400).json({ error: 'Required: did (string), delegationChain (non-empty array)' })
  }

  // 1. Resolve DID through MolTrust
  const didResult = await resolveMolTrustDID(did)

  // 2. Verify derivation_rights narrow monotonically
  const narrowingResults: Array<{ from: string; to: string; valid: boolean; error?: string }> = []
  for (let i = 1; i < delegationChain.length; i++) {
    const parent = delegationChain[i - 1]
    const child = delegationChain[i]

    if (parent.derivation_rights && child.derivation_rights) {
      const err = verifyDerivationNarrowing(parent.derivation_rights, child.derivation_rights)
      narrowingResults.push({
        from: parent.delegationId,
        to: child.delegationId,
        valid: !err,
        error: err || undefined,
      })
    } else if (child.derivation_rights && !parent.derivation_rights) {
      narrowingResults.push({
        from: parent.delegationId,
        to: child.delegationId,
        valid: false,
        error: 'child introduces derivation_rights but parent has none',
      })
    } else {
      narrowingResults.push({ from: parent.delegationId, to: child.delegationId, valid: true })
    }
  }

  const chainValid = narrowingResults.every(r => r.valid)
  const terminalAgent = delegationChain[delegationChain.length - 1].delegatedTo

  // 3. Build attestation
  const evidenceLevel = didResult.resolved ? 'provider-verified' : 'self-declared'
  const attestationId = randomUUID()

  const attestation = {
    attestation_id: attestationId,
    type: 'provider_attestation',
    did,
    did_resolved: didResult.resolved,
    did_status: didResult.status || null,
    did_error: didResult.error || null,
    evidence_level: evidenceLevel,
    delegation_chain_length: delegationChain.length,
    derivation_narrowing_valid: chainValid,
    narrowing_results: narrowingResults,
    terminal_agent: terminalAgent,
    tenant_id: tenant.id,
    timestamp: new Date().toISOString(),
  }

  // Sign with gateway identity
  let signature: string | null = null
  try {
    const identity = getGatewayIdentity()
    signature = identity.sign(attestation as Record<string, unknown>)
  } catch { /* signing optional */ }

  res.json({
    ...attestation,
    gateway_signature: signature,
    jwks_url: 'https://gateway.aeoess.com/.well-known/jwks.json',
  })
})
