// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Email Notification Infrastructure
 *
 * Queue-first design: all emails are appended to /data/email-queue.jsonl.
 * Send order: Resend API (if RESEND_API_KEY set) → SMTP (if SMTP_HOST set) → queue-only.
 * No new dependencies — Resend uses native fetch, SMTP uses optional nodemailer.
 *
 * Hook into POST /api/v1/signup in server.ts:
 *   sendEmail(signupWelcomeEmail(name, email, apiKey))
 */

import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

export interface EmailOptions {
  to: string
  subject: string
  textBody: string
  htmlBody?: string
}

const QUEUE_PATH = process.env.EMAIL_QUEUE_PATH || '/data/email-queue.jsonl'

// Lazy SMTP transport — only initialized once, only if env vars are present
let _smtpTransport: any = null
let _smtpChecked = false

async function getSmtpTransport(): Promise<any> {
  if (_smtpChecked) return _smtpTransport
  _smtpChecked = true

  const host = process.env.SMTP_HOST
  const port = process.env.SMTP_PORT
  const user = process.env.SMTP_USER
  const pass = process.env.SMTP_PASS
  if (!host || !user || !pass) return null

  try {
    // Dynamic import — nodemailer is optional, not in dependencies
    const nodemailer = await (Function('return import("nodemailer")')() as Promise<any>)
    _smtpTransport = nodemailer.default.createTransport({
      host,
      port: parseInt(port || '587'),
      secure: parseInt(port || '587') === 465,
      auth: { user, pass },
    })
    console.log(`[email] SMTP configured: ${host}:${port}`)
    return _smtpTransport
  } catch {
    // nodemailer not installed — queue-only mode
    console.log('[email] nodemailer not available, queue-only mode')
    return null
  }
}

function queueEmail(opts: EmailOptions): void {
  const entry = {
    to: opts.to,
    subject: opts.subject,
    textBody: opts.textBody,
    htmlBody: opts.htmlBody || null,
    queuedAt: new Date().toISOString(),
    status: 'queued',
  }
  try {
    mkdirSync(dirname(QUEUE_PATH), { recursive: true })
    appendFileSync(QUEUE_PATH, JSON.stringify(entry) + '\n')
  } catch (e: any) {
    console.error(`[email] queue write failed: ${e.message}`)
  }
}

export async function sendEmail(opts: EmailOptions): Promise<{ sent: boolean; queued: boolean }> {
  // Always queue first (crash-safe)
  queueEmail(opts)

  // Try Resend API first (no dependency needed)
  const resendKey = process.env.RESEND_API_KEY
  if (resendKey) {
    try {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: process.env.EMAIL_FROM || 'AEOESS <no-reply@aeoess.com>',
          to: [opts.to],
          subject: opts.subject,
          text: opts.textBody,
          html: opts.htmlBody || undefined,
        }),
      })
      if (res.ok) {
        console.log(`[email] to=${opts.to} subject="${opts.subject}" sent via Resend`)
        return { sent: true, queued: true }
      }
      const err = await res.text()
      console.error(`[email] Resend error ${res.status}: ${err}`)
    } catch (e: any) {
      console.error(`[email] Resend failed: ${e.message}`)
    }
  }

  // Fall back to SMTP
  const transport = await getSmtpTransport()
  if (transport) {
    try {
      await transport.sendMail({
        from: process.env.SMTP_FROM || process.env.EMAIL_FROM || 'AEOESS <no-reply@aeoess.com>',
        to: opts.to,
        subject: opts.subject,
        text: opts.textBody,
        html: opts.htmlBody || undefined,
      })
      console.log(`[email] to=${opts.to} subject="${opts.subject}" sent`)
      return { sent: true, queued: true }
    } catch (e: any) {
      console.error(`[email] to=${opts.to} subject="${opts.subject}" send failed: ${e.message}`)
      return { sent: false, queued: true }
    }
  }

  console.log(`[email] to=${opts.to} subject="${opts.subject}" queued`)
  return { sent: false, queued: true }
}

// ═══════════════════════════════════════
// Email Templates
// ═══════════════════════════════════════

export function signupWelcomeEmail(name: string, email: string, apiKey: string): EmailOptions {
  const text = `Welcome to AEOESS, ${name}.

Your API key: ${apiKey}

Get started in 3 steps:

1. Install the SDK
   npm install agent-passport-system

2. Register your first agent
   curl -X POST https://gateway.aeoess.com/api/v1/agents \\
     -H "Authorization: Bearer ${apiKey}" \\
     -H "Content-Type: application/json" \\
     -d '{"agent_id": "my-agent", "public_key": "<your-ed25519-key>"}'

3. Run your first policy evaluation
   curl -X POST https://gateway.aeoess.com/api/v1/evaluate \\
     -H "Authorization: Bearer ${apiKey}" \\
     -H "Content-Type: application/json" \\
     -d '{"agent_id": "my-agent", "action_type": "data:read", "scope_required": "data:read"}'

Dashboard: https://aeoess.com/portal.html
Docs: https://aeoess.com/llms-full.txt

-- AEOESS`

  const html = `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;color:#1a1a2e">
<h2 style="color:#63b3ed">Welcome to AEOESS</h2>
<p>Hi ${esc(name)},</p>
<p>Your API key:</p>
<pre style="background:#f0f4f8;padding:12px;border-radius:6px;font-size:14px;overflow-x:auto">${esc(apiKey)}</pre>
<h3>Get started in 3 steps</h3>
<ol>
<li><strong>Install the SDK</strong><br><code>npm install agent-passport-system</code></li>
<li><strong>Register your first agent</strong> via <code>POST /api/v1/agents</code></li>
<li><strong>Run a policy evaluation</strong> via <code>POST /api/v1/evaluate</code></li>
</ol>
<p><a href="https://aeoess.com/portal.html" style="color:#63b3ed">Open Dashboard</a> | <a href="https://aeoess.com/llms-full.txt" style="color:#63b3ed">Docs</a></p>
<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:12px;color:#718096">AEOESS - Enforcement infrastructure for AI agents</p>
</div>`

  return { to: email, subject: 'Welcome to AEOESS - Your API Key', textBody: text, htmlBody: html }
}

export function paymentReceiptEmail(name: string, plan: string, amount: string): EmailOptions {
  const nextBilling = new Date()
  nextBilling.setMonth(nextBilling.getMonth() + 1)
  const nextDate = nextBilling.toISOString().slice(0, 10)

  const text = `Payment confirmed, ${name}.

Plan: ${plan}
Amount: $${amount}
Next billing date: ${nextDate}

Manage your subscription: https://aeoess.com/portal.html

-- AEOESS`

  const html = `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;color:#1a1a2e">
<h2 style="color:#63b3ed">Payment Confirmed</h2>
<p>Hi ${esc(name)},</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0">
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Plan</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">${esc(plan)}</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Amount</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">$${esc(amount)}</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Next billing</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">${nextDate}</td></tr>
</table>
<p><a href="https://aeoess.com/portal.html" style="color:#63b3ed">Manage Subscription</a></p>
<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:12px;color:#718096">AEOESS - Enforcement infrastructure for AI agents</p>
</div>`

  return { to: '', subject: `AEOESS Payment Receipt - ${plan} Plan`, textBody: text, htmlBody: html }
}

export function weeklyDigestEmail(name: string, stats: {
  evaluations: number; permits: number; denials: number; agents: number; period: string
}): EmailOptions {
  const denialRate = stats.evaluations > 0
    ? Math.round((stats.denials / stats.evaluations) * 100) : 0

  const text = `Weekly digest for ${name} (${stats.period})

Evaluations: ${stats.evaluations.toLocaleString()}
  Permits: ${stats.permits.toLocaleString()}
  Denials: ${stats.denials.toLocaleString()} (${denialRate}%)
Active agents: ${stats.agents}

Dashboard: https://aeoess.com/portal.html

-- AEOESS`

  const html = `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;color:#1a1a2e">
<h2 style="color:#63b3ed">Weekly Digest</h2>
<p>Hi ${esc(name)}, here's your week (${esc(stats.period)}):</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0">
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Evaluations</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">${stats.evaluations.toLocaleString()}</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Permits</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">${stats.permits.toLocaleString()}</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Denials</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">${stats.denials.toLocaleString()} (${denialRate}%)</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #e2e8f0;font-weight:bold">Active agents</td><td style="padding:8px;border-bottom:1px solid #e2e8f0">${stats.agents}</td></tr>
</table>
<p><a href="https://aeoess.com/portal.html" style="color:#63b3ed">View Dashboard</a></p>
<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:12px;color:#718096">AEOESS - Enforcement infrastructure for AI agents</p>
</div>`

  return { to: '', subject: `AEOESS Weekly Digest - ${stats.period}`, textBody: text, htmlBody: html }
}

export function spendAlertEmail(name: string, agentId: string, spentPercent: number): EmailOptions {
  const text = `Spend alert, ${name}.

Agent "${agentId}" has used ${spentPercent}% of its spend limit.

${spentPercent >= 90 ? 'Action required: increase the limit or revoke the delegation before it is exhausted.' : 'No action needed yet, but keep an eye on it.'}

Dashboard: https://aeoess.com/portal.html

-- AEOESS`

  const html = `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;color:#1a1a2e">
<h2 style="color:${spentPercent >= 90 ? '#e53e3e' : '#ed8936'}">Spend Alert</h2>
<p>Hi ${esc(name)},</p>
<p>Agent <strong>${esc(agentId)}</strong> has used <strong>${spentPercent}%</strong> of its spend limit.</p>
${spentPercent >= 90 ? '<p style="color:#e53e3e;font-weight:bold">Action required: increase the limit or revoke the delegation.</p>' : '<p>No action needed yet.</p>'}
<p><a href="https://aeoess.com/portal.html" style="color:#63b3ed">View Dashboard</a></p>
<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:12px;color:#718096">AEOESS - Enforcement infrastructure for AI agents</p>
</div>`

  return { to: '', subject: `AEOESS Spend Alert - Agent ${agentId} at ${spentPercent}%`, textBody: text, htmlBody: html }
}

// HTML escape helper
function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
