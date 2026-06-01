// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C2 layer (b): post-flight governance automations.
 *
 * Five automations, each POST-FLIGHT (never in the enforcement hot path), each
 * running under its OWN narrowed APS sub-delegation and emitting a signed self-
 * receipt for its own action (the gateway governs its own governance):
 *
 *   1. alert_routing            route + summarize an alert (no auto-action)
 *   2. evidence_bundle          compose an evidence bundle from audit serializers
 *   3. policy_drift             detect drift from trust signals + recommend
 *   4. revocation_recommendation  previewCascade ONLY, recommend, never revoke
 *   5. integration_health       check integration health, escalate a summary
 *
 * Hard constraints (spec + claims discipline). Each automation MAY summarize,
 * route, open a ticket, recommend, escalate. NONE may: silently change policy,
 * silently revoke, approve a high-risk action, or delete evidence. These are
 * enforced structurally: an automation is narrowed to a single benign governance
 * scope (governance-delegation.ts), it checks automationMayAct before acting, and
 * it has no code path that mutates policy, calls bumpEpoch/panicFreeze, or deletes
 * an evidence row. Evidence bundles are COMPOSED read-only from audit serializers.
 *
 * Reuse, do not reinvent: getEventBus (events spine), sendEmail + governanceAlert
 * template (notifications), queryAuditRecords/toJsonLines/toCsv (audit-export),
 * getGatewayIdentity().sign (self-receipts), buildAgentTrustProfile signals +
 * policy_evaluations (drift), coordination task lifecycle (tickets), B2
 * previewCascade via the read-only seam (recommendation).
 */

import { createHash } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import { getEventBus } from '../events.js'
import { sendEmail, governanceAlertEmail } from '../../notifications/email.js'
import { queryAuditRecords, toJsonLines, toCsv, type AuditRecord } from '../audit-export.js'
import {
  getAutomationDelegation,
  automationMayAct,
  emitSelfReceipt,
  AUTOMATION_SCOPE,
  type AutomationName,
  type AutomationSelfReceipt,
} from './governance-delegation.js'
import { previewCascadeSeam, type CascadePreviewSeam } from './cascade-seam.js'
import { getConnectorRouter } from './connector-seam.js'

/**
 * SQLite-native "since" timestamp for a rolling window. The policy_evaluations
 * rows carry created_at in SQLite's datetime('now') format (YYYY-MM-DD HH:MM:SS,
 * UTC, space-separated). An ISO 8601 string (with 'T' and 'Z') does NOT compare
 * lexically against that format inside the same day, so we emit the SQLite shape
 * here and compare like-for-like. Pure; no IO.
 */
function sqliteSince(windowHours: number): string {
  // toISOString() => 2026-06-01T03:08:35.646Z ; slice to date+time and swap the
  // 'T' for a space, dropping the fractional seconds and trailing 'Z'.
  return new Date(Date.now() - windowHours * 3600_000)
    .toISOString()
    .slice(0, 19)
    .replace('T', ' ')
}

/** Common envelope every automation returns: what it did + its self-receipt. */
export interface AutomationResult<T> {
  automation: AutomationName
  /** True iff the automation was authorized (had a live narrowed delegation). */
  acted: boolean
  /** Why it did not act, when acted=false. */
  reason: string
  /** The automation's own action output (route result, bundle, recommendation, ...). */
  output: T | null
  /** Signed self-receipt for the action. Null when it did not act. */
  selfReceipt: AutomationSelfReceipt | null
}

/**
 * Guard rail shared by every automation: obtain the narrowed delegation, confirm
 * the action maps to exactly the automation's scope, and (on success) emit the
 * signed self-receipt. If the automation cannot get its narrowed delegation it
 * does NOT act (fail-closed) - an un-delegated automation must never touch data.
 */
async function runUnderDelegation<T>(
  automation: AutomationName,
  action: string,
  payload: unknown,
  body: () => T,
): Promise<AutomationResult<T>> {
  const del = await getAutomationDelegation(automation)
  if (!del) {
    return {
      automation,
      acted: false,
      reason: 'no narrowed delegation available (SDK/governance root unavailable); automation refused to act',
      output: null,
      selfReceipt: null,
    }
  }
  // The action must map to exactly this automation's single scope. Anything else
  // is an attempt to act outside the delegation and is refused.
  const requiredScope = AUTOMATION_SCOPE[automation]
  if (!automationMayAct(del, requiredScope)) {
    return {
      automation,
      acted: false,
      reason: `action "${action}" is outside delegation scope "${del.scope}"`,
      output: null,
      selfReceipt: null,
    }
  }
  const output = body()
  const selfReceipt = emitSelfReceipt({ delegation: del, action, payload })
  return { automation, acted: true, reason: 'acted within delegation', output, selfReceipt }
}

// ───────────────────────────────────────────────────────────────────────────
// 1. Alert routing
// ───────────────────────────────────────────────────────────────────────────

export interface AlertRouteOutput {
  routed: boolean
  via: string
  /** When connector routing was unavailable, the email fallback result. */
  emailFallback?: { sent: boolean; queued: boolean }
}

/**
 * Route + summarize a governance alert. It does NOT auto-act on the alert; it
 * routes a summary to the operator (connector when C1 lands, else email) and
 * emits a self-receipt. Severity 'critical' still only routes - there is no
 * auto-remediation here.
 */
export async function routeAlert(opts: {
  tenantId: string
  recipientEmail: string
  recipientName: string
  signal: string
  severity: 'info' | 'warning' | 'critical'
  summary: string
  recommendation: string
  /** Routing target hint for the connector registry (Slack/PagerDuty/...). */
  target?: string
}): Promise<AutomationResult<AlertRouteOutput>> {
  return runUnderDelegation('alert_routing', 'route_alert', { signal: opts.signal, severity: opts.severity }, () => {
    // Try the connector registry first (C1). Until C1 lands this returns
    // delivered=false and we fall back to the existing email surface.
    // The promise is resolved synchronously-after via the fallback below; we keep
    // the body sync for the self-receipt and do the async send out-of-band.
    let routed = false
    let via = `fallback:${opts.target ?? 'email'}`
    // Connector route is best-effort and non-blocking; we record intent here.
    void getConnectorRouter().route(opts.target ?? 'default', { signal: opts.signal }).then(r => {
      routed = r.delivered
      via = r.via
    }).catch(() => { /* connector errors never break routing */ })

    const out: AlertRouteOutput = { routed, via }
    // Email fallback (always, since no connector exists yet). sendEmail is the
    // single mailer; we reuse the governanceAlert template.
    const email = governanceAlertEmail({
      recipientName: opts.recipientName,
      signal: opts.signal,
      severity: opts.severity,
      summary: opts.summary,
      recommendation: opts.recommendation,
    })
    email.to = opts.recipientEmail
    void sendEmail(email).then(r => { out.emailFallback = r }).catch(() => { /* queue-first; never throws fatally */ })

    try {
      getEventBus().emit(opts.tenantId, {
        type: 'alert',
        data: { source: 'governance_automation', signal: opts.signal, severity: opts.severity, routed_via: via },
      })
    } catch { /* event emit must not break routing */ }

    return out
  })
}

// ───────────────────────────────────────────────────────────────────────────
// 2. Evidence-bundle generation
// ───────────────────────────────────────────────────────────────────────────

export interface EvidenceBundle {
  tenantId: string
  from: string
  to: string
  recordCount: number
  /** JSON Lines body composed from audit-export serializers (read-only). */
  jsonl: string
  /** CSV body composed from audit-export serializers (read-only). */
  csv: string
  /** SHA-256 over the JSONL body, so the bundle is self-describing for audit. */
  bundleHash: string
  generatedAt: string
}

/**
 * Compose an evidence bundle from the audit-export serializers. READ-ONLY: it
 * queries policy_evaluations via queryAuditRecords and serializes with the
 * existing toJsonLines/toCsv. It NEVER deletes or mutates evidence. The bundle is
 * a descriptor of existing receipts, not a new authority.
 *
 * TODO(W2-xx): SDK evidence descriptor - if the alpha exposes an EvidenceDescriptor
 *   builder, wrap the bundle in it. Until then we compose the audit-export
 *   serializers, which is the directed fallback.
 */
export async function generateEvidenceBundle(opts: {
  tenantId: string
  from: string
  to: string
  scope?: string
}): Promise<AutomationResult<EvidenceBundle>> {
  return runUnderDelegation('evidence_bundle', 'compose_evidence_bundle', { from: opts.from, to: opts.to }, () => {
    const records: AuditRecord[] = queryAuditRecords(opts.tenantId, opts.from, opts.to, opts.scope)
    const jsonl = toJsonLines(records)
    const csv = toCsv(records)
    const bundleHash = createHash('sha256').update(jsonl).digest('hex')
    const bundle: EvidenceBundle = {
      tenantId: opts.tenantId,
      from: opts.from,
      to: opts.to,
      recordCount: records.length,
      jsonl,
      csv,
      bundleHash,
      generatedAt: new Date().toISOString(),
    }
    try {
      getEventBus().emit(opts.tenantId, {
        type: 'evidence_bundle',
        data: { record_count: records.length, bundle_hash: bundleHash, from: opts.from, to: opts.to },
      })
    } catch { /* event emit must not break bundle generation */ }
    return bundle
  })
}

// ───────────────────────────────────────────────────────────────────────────
// 3. Policy-drift detection
// ───────────────────────────────────────────────────────────────────────────

export interface DriftSignal {
  agentId: string
  denialRate: number
  evaluations: number
  /** 'low' | 'elevated' | 'high' drift severity from the denial-rate signal. */
  drift: 'low' | 'elevated' | 'high'
  /** Recommendation only - never an action. */
  recommendation: string
}

/**
 * Detect policy drift from the denial-rate signal over policy_evaluations (the
 * same source buildAgentTrustProfile reads). It RECOMMENDS; it does not change
 * policy. A high denial rate is surfaced with a review recommendation, never an
 * automatic restriction.
 */
export async function detectPolicyDrift(opts: {
  tenantId: string
  windowHours?: number
  /** Minimum evaluations before a rate is meaningful (avoid single-sample noise). */
  minEvaluations?: number
}): Promise<AutomationResult<DriftSignal[]>> {
  return runUnderDelegation('policy_drift', 'recommend_on_drift', { window_hours: opts.windowHours ?? 24 }, () => {
    const db = getDB()
    const windowHours = opts.windowHours ?? 24
    const minEval = opts.minEvaluations ?? 5
    const since = sqliteSince(windowHours)
    const rows = db.prepare(
      `SELECT agent_id,
              COUNT(*) AS evals,
              SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) AS denials
       FROM policy_evaluations
       WHERE tenant_id = ? AND created_at >= ?
       GROUP BY agent_id`,
    ).all(opts.tenantId, since) as any[]

    const signals: DriftSignal[] = []
    for (const r of rows) {
      const evals = Number(r.evals) || 0
      if (evals < minEval) continue
      const denials = Number(r.denials) || 0
      const denialRate = denials / evals
      const drift: DriftSignal['drift'] = denialRate >= 0.5 ? 'high' : denialRate >= 0.25 ? 'elevated' : 'low'
      if (drift === 'low') continue
      signals.push({
        agentId: r.agent_id,
        denialRate: Number(denialRate.toFixed(3)),
        evaluations: evals,
        drift,
        recommendation:
          drift === 'high'
            ? 'Review this agent\'s scope grants; the denial rate suggests the delegation no longer matches its behavior.'
            : 'Watch this agent; the denial rate is elevated. No action recommended yet.',
      })
    }
    if (signals.length > 0) {
      try {
        getEventBus().emit(opts.tenantId, {
          type: 'drift_detected',
          data: { agents: signals.length, window_hours: windowHours },
        })
      } catch { /* event emit must not break drift detection */ }
    }
    return signals
  })
}

// ───────────────────────────────────────────────────────────────────────────
// 4. Revocation RECOMMENDATION (previewCascade ONLY; never revoke)
// ───────────────────────────────────────────────────────────────────────────

export interface RevocationRecommendation {
  targetType: 'agent' | 'delegation' | 'data_source'
  targetId: string
  preview: CascadePreviewSeam
  /** The recommended action options surfaced from the cascade preview. */
  recommendedActions: CascadePreviewSeam['recommendedActions']
  /** Explicit: this automation does NOT execute the revoke. */
  willExecute: false
}

/**
 * Recommend a revocation by running the READ-ONLY cascade preview (B2 seam) and
 * surfacing recommendedActions. It calls previewCascade ONLY. It MUST NOT call
 * bumpEpoch or panicFreeze - recommend, never silently revoke. The actual revoke
 * stays the authenticated operator's call (or a customer-signed playbook). The
 * willExecute:false field makes the no-action contract explicit in the output.
 */
export async function recommendRevocation(opts: {
  tenantId: string
  targetType: 'agent' | 'delegation' | 'data_source'
  targetId: string
}): Promise<AutomationResult<RevocationRecommendation>> {
  return runUnderDelegation('revocation_recommendation', 'recommend_revocation', { target: opts.targetId }, () => {
    // READ-ONLY preview. No mutation, no epoch bump, no freeze.
    const preview = previewCascadeSeam({ tenantId: opts.tenantId, targetType: opts.targetType, targetId: opts.targetId })
    const rec: RevocationRecommendation = {
      targetType: opts.targetType,
      targetId: opts.targetId,
      preview,
      recommendedActions: preview.recommendedActions,
      willExecute: false,
    }
    try {
      getEventBus().emit(opts.tenantId, {
        type: 'revocation_recommended',
        data: {
          target_type: opts.targetType,
          target_id: opts.targetId,
          total_affected: preview.totalRevoked,
          recommended_actions: preview.recommendedActions,
          will_execute: false,
        },
      })
    } catch { /* event emit must not break recommendation */ }
    return rec
  })
}

// ───────────────────────────────────────────────────────────────────────────
// 5. Integration-health check
// ───────────────────────────────────────────────────────────────────────────

export interface IntegrationHealth {
  /** Per-integration health derived from recent activity. */
  integrations: Array<{ name: string; healthy: boolean; detail: string }>
  overall: 'healthy' | 'degraded'
  /** Recommendation/escalation summary; never an action. */
  escalation: string | null
}

/**
 * Check integration health and ESCALATE a summary when degraded. It reads recent
 * signals (e.g. whether evaluations are flowing) and produces a health summary +
 * an escalation recommendation. It does not restart, reconfigure, or disable any
 * integration; it escalates a summary for a human.
 */
export async function checkIntegrationHealth(opts: {
  tenantId: string
  /** Integrations to check, by name. The check is signal-based, not a live ping. */
  integrationNames: string[]
  windowHours?: number
}): Promise<AutomationResult<IntegrationHealth>> {
  return runUnderDelegation('integration_health', 'escalate_health_summary', { integrations: opts.integrationNames }, () => {
    const db = getDB()
    const windowHours = opts.windowHours ?? 1
    const since = sqliteSince(windowHours)
    // Signal: recent evaluation throughput. A live integration should produce
    // evaluations; zero in the window is a degraded signal worth escalating.
    const recent = db.prepare(
      `SELECT COUNT(*) AS c FROM policy_evaluations WHERE tenant_id = ? AND created_at >= ?`,
    ).get(opts.tenantId, since) as any
    const throughput = Number(recent?.c) || 0

    const integrations = opts.integrationNames.map(name => {
      const healthy = throughput > 0
      return {
        name,
        healthy,
        detail: healthy
          ? `recent evaluation throughput ${throughput} in ${windowHours}h`
          : `no evaluation throughput in ${windowHours}h`,
      }
    })
    const overall: IntegrationHealth['overall'] = integrations.every(i => i.healthy) ? 'healthy' : 'degraded'
    const escalation = overall === 'degraded'
      ? 'One or more integrations show no recent throughput. Review connectivity; this is a routed summary, not an action.'
      : null

    try {
      getEventBus().emit(opts.tenantId, {
        type: 'integration_health',
        data: { overall, count: integrations.length, window_hours: windowHours },
      })
    } catch { /* event emit must not break the health check */ }

    return { integrations, overall, escalation }
  })
}
