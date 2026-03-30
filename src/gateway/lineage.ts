// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Lineage Intelligence — private gateway product.
 *
 * Computes HMAC-based lineage links from issuance dossiers.
 * Groups passports into clusters by link similarity.
 * Scores cluster risk for the trust-profile API.
 *
 * PRIVATE: scoring weights, HMAC inputs, cluster logic never go public.
 *
 * Four link types (from consilium):
 *   runtimeLink  — same runtime/sandbox family
 *   ownerLink    — same owner/operator family
 *   behavioralLink — same operational style (soft, never drives irreversible)
 *   recoveryLink — continuity for honest reissue
 */

import { createHmac, randomUUID, randomBytes } from 'node:crypto'
import { getDB } from '../db/schema.js'

// ── HMAC secret (generated once, stored in DB) ──

let _issuerSecret: string | null = null

function getIssuerSecret(): string {
  if (_issuerSecret) return _issuerSecret
  const db = getDB()
  // Store secret in a config table, generate on first use
  const row = db.prepare(
    `SELECT value FROM gateway_config WHERE key = 'issuer_secret'`
  ).get() as any
  if (row) {
    _issuerSecret = row.value
    return _issuerSecret!
  }
  // First run — generate proper 256-bit key and persist
  const secret = randomBytes(32).toString('hex')
  db.prepare(
    `INSERT INTO gateway_config (key, value) VALUES ('issuer_secret', ?)`
  ).run(secret)
  _issuerSecret = secret
  return secret
}

// ── Canonicalize + HMAC ──

function canonicalize(obj: Record<string, any>): string {
  const sorted = Object.keys(obj).sort().reduce((acc: any, k) => {
    if (obj[k] !== null && obj[k] !== undefined) acc[k] = obj[k]
    return acc
  }, {})
  return JSON.stringify(sorted)
}

function hmacLink(scope: string, claims: Record<string, any>): string {
  const secret = getIssuerSecret()
  return createHmac('sha256', secret)
    .update(scope + ':' + canonicalize(claims))
    .digest('hex')
}

// ── Bucket helpers (normalization per consilium) ──

function hourFloor(isoDate: string): string {
  if (!isoDate || isoDate.length < 13) return 'unknown'
  return isoDate.slice(0, 13) + ':00:00Z'
}

function timingBucket(ms: number | null): string {
  if (ms === null || ms === undefined) return 'unknown'
  if (ms < 1000) return '0-1s'
  if (ms < 10000) return '1-10s'
  if (ms < 60000) return '10-60s'
  return '60s+'
}

// ═══════════════════════════════════════
// Four Lineage Link Types
// ═══════════════════════════════════════

export interface LineageLinks {
  runtimeLink: string | null
  ownerLink: string | null
  behavioralLink: string | null
  recoveryLink: string | null
}

/**
 * Compute lineage links from an issuance dossier.
 * Only uses Tier 0+ signals. Self-declared signals excluded from hard links.
 */
export function computeLineageLinks(dossier: any): LineageLinks {
  const obs = JSON.parse(dossier.observed_context || '{}')
  const runtime = JSON.parse(dossier.runtime_attestations || '[]')
  const provider = JSON.parse(dossier.provider_attestations || '[]')

  // ── runtimeLink: same runtime/sandbox family ──
  // Uses Tier 1 (infrastructure) when available, Tier 0 fallback
  let runtimeLink: string | null = null
  if (runtime.length > 0) {
    // Tier 1: strong link from infrastructure attestation
    const rt = runtime[0]
    runtimeLink = hmacLink('runtime', {
      attester: rt.attester || rt.attesterId,
      runtimeClass: rt.runtimeClass,
      instanceIdHash: rt.runtimeInstanceIdHash,
      storageIdHash: rt.storageIdentityHash,
      bootBucket: hourFloor(rt.bootEpoch || ''),
    })
  } else if (obs.transportType) {
    // Tier 0 fallback: weaker, used for soft clustering only
    runtimeLink = hmacLink('runtime-t0', {
      transport: obs.transportType,
      payloadFp: obs.requestPayloadFingerprint,
    })
  }

  // ── ownerLink: same owner/operator family ──
  // Uses Tier 2 (provider) when available
  let ownerLink: string | null = null
  if (provider.length > 0) {
    const prov = provider[0]
    ownerLink = hmacLink('owner', {
      providerSubjectHash: prov.subjectIdHash,
      oauthIssuer: prov.issuer,
      tenantHash: prov.cloudTenantHash,
    })
  } else if (dossier.public_key_hash) {
    // Fallback: cluster by key hash family (weak but catches key reuse)
    ownerLink = hmacLink('owner-weak', {
      pubkeyHash: dossier.public_key_hash,
    })
  }

  // ── behavioralLink: same operational style ──
  // Soft signal only. Never drives irreversible decisions.
  let behavioralLink: string | null = null
  const velocity = dossier.issuance_velocity
  const timing = dossier.connection_timing_ms
  if (velocity !== null || timing !== null) {
    behavioralLink = hmacLink('behavioral', {
      velocityBucket: velocity !== null ? (velocity > 10 ? 'high' : velocity > 3 ? 'medium' : 'low') : 'unknown',
      timingBucket: timingBucket(timing),
      transport: obs.transportType || 'unknown',
    })
  }

  // ── recoveryLink: continuity for honest reissue ──
  // Requires prior passport reference (strongest auth link)
  let recoveryLink: string | null = null
  if (dossier.prior_passport_ref) {
    recoveryLink = hmacLink('recovery', {
      priorRef: dossier.prior_passport_ref,
      pubkeyHash: dossier.public_key_hash,
    })
  }

  return { runtimeLink, ownerLink, behavioralLink, recoveryLink }
}

// ═══════════════════════════════════════
// Cluster Scoring
// ═══════════════════════════════════════

export interface ClusterRisk {
  clusterId: string | null
  clusterSize: number
  risk: 'low' | 'medium' | 'high'
  matchedLinks: string[]   // which link types matched
}

/**
 * Store lineage links for a dossier and compute cluster risk.
 * Called after every issuance-dossier POST.
 */
export function storeAndCluster(tenantId: string, dossierId: string, passportId: string, links: LineageLinks): ClusterRisk {
  const db = getDB()

  // Store links (replace any prior links for this passport)
  db.prepare(`DELETE FROM lineage_links WHERE tenant_id = ? AND passport_id = ?`)
    .run(tenantId, passportId)
  db.prepare(`INSERT INTO lineage_links
    (id, tenant_id, dossier_id, passport_id,
     runtime_link, owner_link, behavioral_link, recovery_link)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenantId, dossierId, passportId,
      links.runtimeLink, links.ownerLink,
      links.behavioralLink, links.recoveryLink)

  // Find cluster: other passports sharing ANY hard link
  const matchedLinks: string[] = []
  let clusterMembers: string[] = []

  if (links.runtimeLink) {
    const matches = db.prepare(
      `SELECT DISTINCT passport_id FROM lineage_links
       WHERE tenant_id = ? AND runtime_link = ? AND passport_id != ?`
    ).all(tenantId, links.runtimeLink, passportId) as any[]
    if (matches.length > 0) {
      matchedLinks.push('runtime')
      clusterMembers.push(...matches.map((m: any) => m.passport_id))
    }
  }

  if (links.ownerLink) {
    const matches = db.prepare(
      `SELECT DISTINCT passport_id FROM lineage_links
       WHERE tenant_id = ? AND owner_link = ? AND passport_id != ?`
    ).all(tenantId, links.ownerLink, passportId) as any[]
    if (matches.length > 0) {
      matchedLinks.push('owner')
      clusterMembers.push(...matches.map((m: any) => m.passport_id))
    }
  }

  // Deduplicate cluster members
  const uniqueMembers = [...new Set(clusterMembers)]
  const clusterSize = uniqueMembers.length + 1 // include self

  // Score risk
  let risk: 'low' | 'medium' | 'high' = 'low'
  if (matchedLinks.includes('owner') && matchedLinks.includes('runtime')) {
    risk = 'high'  // same owner + same runtime = very likely same entity
  } else if (matchedLinks.includes('owner') && clusterSize >= 5) {
    risk = 'high'  // same owner with 5+ passports
  } else if (matchedLinks.length > 0 && clusterSize >= 3) {
    risk = 'medium'
  } else if (matchedLinks.length > 0) {
    risk = 'medium'
  }

  // Assign cluster ID (use ownerLink as cluster anchor, fallback to runtimeLink)
  const clusterId = risk !== 'low'
    ? (links.ownerLink || links.runtimeLink || null)
    : null

  // Update dossier with cluster risk
  if (clusterId) {
    db.prepare(
      `UPDATE issuance_dossiers SET cluster_risk = ?, cluster_id = ? WHERE id = ?`
    ).run(risk, clusterId, dossierId)

    // Fire alert on high-risk clusters
    if (risk === 'high') {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenantId, 'lineage_cluster', 'critical',
          `Passport "${passportId}" matches ${clusterSize - 1} other passports via ${matchedLinks.join('+')} links. Possible Sybil cluster.`)
    }
  }

  return { clusterId, clusterSize, risk, matchedLinks }
}

/**
 * Get cluster risk for a passport (used by trust-profile).
 */
export function getClusterRisk(tenantId: string, passportId: string): ClusterRisk {
  const db = getDB()
  const link = db.prepare(
    `SELECT * FROM lineage_links WHERE tenant_id = ? AND passport_id = ? ORDER BY rowid DESC LIMIT 1`
  ).get(tenantId, passportId) as any
  if (!link) return { clusterId: null, clusterSize: 1, risk: 'low', matchedLinks: [] }

  // Compute actual cluster size and matched links
  const matchedLinks: string[] = []
  let clusterMembers: string[] = []

  if (link.runtime_link) {
    const matches = db.prepare(
      `SELECT DISTINCT passport_id FROM lineage_links
       WHERE tenant_id = ? AND runtime_link = ? AND passport_id != ?`
    ).all(tenantId, link.runtime_link, passportId) as any[]
    if (matches.length > 0) {
      matchedLinks.push('runtime')
      clusterMembers.push(...matches.map((m: any) => m.passport_id))
    }
  }
  if (link.owner_link) {
    const matches = db.prepare(
      `SELECT DISTINCT passport_id FROM lineage_links
       WHERE tenant_id = ? AND owner_link = ? AND passport_id != ?`
    ).all(tenantId, link.owner_link, passportId) as any[]
    if (matches.length > 0) {
      matchedLinks.push('owner')
      clusterMembers.push(...matches.map((m: any) => m.passport_id))
    }
  }

  const uniqueMembers = [...new Set(clusterMembers)]
  const clusterSize = uniqueMembers.length + 1

  const dossier = db.prepare(
    `SELECT cluster_risk, cluster_id FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ?`
  ).get(tenantId, passportId) as any

  return {
    clusterId: dossier?.cluster_id || null,
    clusterSize,
    risk: (dossier?.cluster_risk as any) || 'low',
    matchedLinks,
  }
}

/**
 * Initialize lineage tables. Called from schema.ts.
 */
export function initLineageTables(): void {
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS gateway_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS lineage_links (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      dossier_id TEXT NOT NULL,
      passport_id TEXT NOT NULL,
      runtime_link TEXT,
      owner_link TEXT,
      behavioral_link TEXT,
      recovery_link TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_lineage_tenant ON lineage_links(tenant_id, passport_id);
    CREATE INDEX IF NOT EXISTS idx_lineage_runtime ON lineage_links(runtime_link);
    CREATE INDEX IF NOT EXISTS idx_lineage_owner ON lineage_links(owner_link);
  `)
}
