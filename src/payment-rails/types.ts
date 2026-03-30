// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Payment Rail — Generic Interface
 *
 * The gateway is payment-rail agnostic. Settlements flow through
 * whichever adapter is configured. Nano ships first because it's
 * feeless and instant — perfect for agent micro-transactions.
 *
 * Future adapters: Lightning, Solana, Stripe, USDC, etc.
 */

// ── Invoice (payment request) ──

export interface PaymentInvoice {
  invoiceId: string
  rail: string                    // 'nano', 'lightning', 'stripe', etc.
  amount: number                  // in base units (raw for Nano, satoshis for LN)
  amountHuman: string             // human-readable ("0.001 XNO")
  currency: string                // 'XNO', 'BTC', 'USD', etc.
  destination: string             // address / invoice string
  memo?: string                   // settlement reference
  status: 'pending' | 'confirmed' | 'expired' | 'failed'
  createdAt: string
  expiresAt?: string
  metadata: Record<string, unknown>
}

// ── Payment Confirmation ──

export interface PaymentConfirmation {
  invoiceId: string
  rail: string
  amount: number
  currency: string
  txProof: string                 // block hash (Nano), txid (LN), charge_id (Stripe)
  sender?: string                 // sender address if known
  confirmedAt: string
  confirmationTimeMs: number      // how long between invoice and confirmation
}

// ── Payment Rail Interface ──

export interface PaymentRail {
  readonly name: string
  readonly currency: string

  /** Create a payment request (invoice) for a given amount */
  createInvoice(opts: {
    amount: number                // in smallest currency unit
    settlementId?: string         // link back to APS settlement
    agentId?: string              // who is paying
    memo?: string
    expiresInSeconds?: number
  }): Promise<PaymentInvoice>

  /** Check current status of an invoice */
  checkStatus(invoiceId: string): Promise<PaymentInvoice>

  /** Send payment from gateway wallet (for outbound settlements) */
  sendPayment(opts: {
    destination: string
    amount: number
    memo?: string
  }): Promise<PaymentConfirmation>

  /** Verify an on-chain transaction is real and matches expected amount */
  verifyTransaction(txProof: string, expectedAmount?: number): Promise<{
    verified: boolean
    amount: number
    sender?: string
    receiver?: string
    timestamp?: string
    error?: string
  }>
}

// ── DB Record for payment_transactions ──

export interface PaymentTransaction {
  id: string
  tenant_id: string
  settlement_id?: string
  rail: string
  direction: 'inbound' | 'outbound'
  amount: number
  currency: string
  destination?: string           // nano address, LN invoice, etc.
  tx_proof?: string              // block hash, txid, charge_id
  status: 'pending' | 'confirmed' | 'failed' | 'expired'
  invoice_data?: string          // JSON of full invoice
  created_at: string
  confirmed_at?: string
}
