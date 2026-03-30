// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Payment Rails — Gateway Routes
 *
 * POST /api/v1/pay/nano/invoice         — Create Nano payment request
 * GET  /api/v1/pay/nano/status/:id      — Check invoice status
 * POST /api/v1/pay/nano/settle/:id      — Execute settlement via Nano
 * GET  /api/v1/pay/nano/balance         — Gateway wallet balance
 * GET  /api/v1/pay/nano/history         — Recent transactions
 * POST /api/v1/pay/nano/verify          — Verify on-chain transaction
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getNanoRail, rawToXno, xnoToRaw } from './nano.js'
import { getDB } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'

export const paymentRouter = Router()

// ── POST /pay/nano/invoice — Create payment request ──

paymentRouter.post('/pay/nano/invoice', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const nano = getNanoRail()
    const { amount, settlement_id, agent_id, memo, expires_in } = req.body

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Required: amount (in XNO, > 0)' })
    }

    const invoice = await nano.createInvoice({
      amount,
      settlementId: settlement_id,
      agentId: agent_id,
      memo,
      expiresInSeconds: expires_in || 3600,
    })

    // Store in DB
    const db = getDB()
    db.prepare(`INSERT INTO payment_transactions
      (id, tenant_id, settlement_id, rail, direction, amount, currency,
       destination, status, invoice_data)
      VALUES (?, ?, ?, 'nano', 'inbound', ?, 'XNO', ?, 'pending', ?)`)
      .run(invoice.invoiceId, tenant.id, settlement_id || null,
        amount, invoice.destination, JSON.stringify(invoice))

    res.status(201).json({
      invoice_id: invoice.invoiceId,
      pay_to: invoice.destination,
      amount_xno: invoice.amountHuman,
      amount_raw: invoice.metadata.amountRaw,
      expires_at: invoice.expiresAt,
      status: 'pending',
      instructions: `Send exactly ${invoice.amountHuman} to ${invoice.destination}. Payment confirms in <1 second. Zero fees.`,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /pay/nano/status/:id — Check invoice payment status ──

paymentRouter.get('/pay/nano/status/:id', async (req: any, res) => {
  try {
    const nano = getNanoRail()
    const invoice = await nano.checkStatus(req.params.id)

    // Update DB if confirmed
    if (invoice.status === 'confirmed') {
      const db = getDB()
      db.prepare(`UPDATE payment_transactions
        SET status = 'confirmed',
            tx_proof = ?,
            confirmed_at = datetime('now')
        WHERE id = ?`)
        .run(invoice.metadata.blockHash as string, invoice.invoiceId)
    }

    res.json({
      invoice_id: invoice.invoiceId,
      status: invoice.status,
      amount_xno: invoice.amountHuman,
      destination: invoice.destination,
      block_hash: invoice.metadata.blockHash || null,
      sender: invoice.metadata.sender || null,
      confirmation_time_ms: invoice.metadata.confirmationTimeMs || null,
    })
  } catch (e: any) {
    res.status(404).json({ error: e.message })
  }
})

// ── POST /pay/nano/settle/:id — Execute settlement via Nano ──

paymentRouter.post('/pay/nano/settle/:id', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()

  try {
    const nano = getNanoRail()
    const settlement = db.prepare(
      `SELECT * FROM settlements WHERE id = ? AND tenant_id = ?`
    ).get(req.params.id, tenant.id) as any

    if (!settlement) {
      return res.status(404).json({ error: 'Settlement not found' })
    }

    const lineItems = JSON.parse(settlement.line_items || '[]')
    const { destination_map } = req.body
    // destination_map: { "source_id": "nano_address", ... }

    if (!destination_map || typeof destination_map !== 'object') {
      return res.status(400).json({
        error: 'Required: destination_map — object mapping source_id to nano address',
        example: { 'source-001': 'nano_3abc...', 'source-002': 'nano_1xyz...' },
      })
    }

    const results: any[] = []
    let totalPaid = 0

    for (const item of lineItems) {
      const destination = destination_map[item.source_id]
      if (!destination) {
        results.push({
          source_id: item.source_id,
          status: 'skipped',
          reason: 'No nano address in destination_map',
        })
        continue
      }

      try {
        const confirmation = await nano.sendPayment({
          destination,
          amount: item.amount,
          memo: `settlement:${settlement.id}:${item.source_id}`,
        })

        // Record outbound transaction
        db.prepare(`INSERT INTO payment_transactions
          (id, tenant_id, settlement_id, rail, direction, amount, currency,
           destination, tx_proof, status, confirmed_at)
          VALUES (?, ?, ?, 'nano', 'outbound', ?, 'XNO', ?, ?, 'confirmed', datetime('now'))`)
          .run(randomUUID(), tenant.id, settlement.id,
            item.amount, destination, confirmation.txProof)

        totalPaid += item.amount
        results.push({
          source_id: item.source_id,
          status: 'confirmed',
          block_hash: confirmation.txProof,
          amount_xno: item.amount,
          destination,
          confirmation_time_ms: confirmation.confirmationTimeMs,
        })
      } catch (e: any) {
        results.push({
          source_id: item.source_id,
          status: 'failed',
          error: e.message,
          destination,
        })
      }
    }

    res.json({
      settlement_id: settlement.id,
      rail: 'nano',
      total_amount: settlement.total_amount,
      total_paid: Math.round(totalPaid * 10000) / 10000,
      line_items: results.length,
      confirmed: results.filter(r => r.status === 'confirmed').length,
      failed: results.filter(r => r.status === 'failed').length,
      skipped: results.filter(r => r.status === 'skipped').length,
      results,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /pay/nano/balance — Gateway wallet balance ──

paymentRouter.get('/pay/nano/balance', async (_req: any, res) => {
  try {
    const nano = getNanoRail()
    const balance = await nano.getBalance()
    res.json({
      rail: 'nano',
      address: balance.balanceXno ? undefined : undefined,
      balance_xno: balance.balanceXno,
      balance_raw: balance.balance,
      receivable_raw: balance.receivable,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /pay/nano/history — Recent transactions ──

paymentRouter.get('/pay/nano/history', async (_req: any, res) => {
  try {
    const nano = getNanoRail()
    const count = parseInt((_req as any).query?.count || '20')
    const history = await nano.getHistory(count)
    res.json({ rail: 'nano', transactions: history, count: history.length })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── POST /pay/nano/verify — Verify on-chain transaction ──

paymentRouter.post('/pay/nano/verify', async (req: any, res) => {
  try {
    const nano = getNanoRail()
    const { block_hash, expected_amount } = req.body
    if (!block_hash) {
      return res.status(400).json({ error: 'Required: block_hash' })
    }
    const result = await nano.verifyTransaction(block_hash, expected_amount)
    res.json({ rail: 'nano', ...result })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})
