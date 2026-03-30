// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Agent Wallet Service — APS-Native Nano Wallets
 *
 * Every agent with a passport gets a Nano wallet.
 * Spending is delegation-scoped. Every tx produces a signed receipt.
 * Feeless. Instant. Tied to cryptographic identity.
 *
 * Competitive landscape:
 *   ChainHop: 0.75% per tx, no identity governance
 *   Coinbase Agentic Wallets: gas fees, EVM-only, x402 protocol
 *   APS Wallets: 0% fees (Nano L1), delegation-scoped, receipt-linked
 *
 * Architecture:
 *   Master seed → HD derivation → one Nano address per agent
 *   Agent index = row in agent_wallets table
 *   Gateway is custodial — agents interact via authenticated API
 *   All sends gated by delegation scope + spend limits
 */

import { randomUUID } from 'node:crypto'
import { createHash } from 'node:crypto'

// ── Types ──

export interface AgentWallet {
  id: string
  tenant_id: string
  agent_id: string
  nano_address: string
  wallet_index: number           // position in HD derivation
  status: 'active' | 'frozen' | 'revoked'
  balance_raw: string            // last known balance in raw
  total_received_raw: string
  total_sent_raw: string
  created_at: string
}

export interface WalletTransaction {
  id: string
  tenant_id: string
  from_agent_id: string
  to_agent_id?: string           // null if external
  to_address: string
  amount_raw: string
  amount_xno: string
  block_hash?: string
  delegation_id?: string         // which delegation authorized this
  scope_used?: string
  evaluation_id?: string         // linked gateway evaluation
  status: 'pending' | 'confirmed' | 'failed' | 'denied'
  denial_reason?: string
  created_at: string
  confirmed_at?: string
}

// ── Wallet Service ──

import { xnoToRaw, rawToXno } from './nano.js'
import { getDB } from '../db/schema.js'

async function walletRpc(url: string, body: Record<string, unknown>): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`Wallet RPC error: ${res.status} ${res.statusText}`)
  const data = await res.json()
  if (data.error) throw new Error(`Wallet RPC: ${data.error}`)
  return data
}

export class AgentWalletService {
  private rpcUrl: string         // wallet-enabled node (enable_control)
  private readRpcUrl: string     // public node for reads
  private walletId: string       // master wallet ID on the node

  constructor(opts: {
    rpcUrl: string               // wallet-enabled node URL
    readRpcUrl?: string          // public node for balance checks
    walletId: string             // pre-created wallet ID
  }) {
    this.rpcUrl = opts.rpcUrl
    this.readRpcUrl = opts.readRpcUrl || opts.rpcUrl
    this.walletId = opts.walletId
  }

  /**
   * Provision a new Nano wallet for an agent.
   * Creates a new account in the master wallet via RPC.
   * Stores the mapping in agent_wallets table.
   */
  async provisionWallet(tenantId: string, agentId: string): Promise<AgentWallet> {
    const db = getDB()

    // Check if agent already has a wallet
    const existing = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as AgentWallet | undefined
    if (existing) return existing

    // Create new account in the master wallet
    const result = await walletRpc(this.rpcUrl, {
      action: 'account_create',
      wallet: this.walletId,
    })

    const nanoAddress = result.account
    // Get the wallet index (how many accounts exist)
    const countResult = await walletRpc(this.rpcUrl, {
      action: 'account_list',
      wallet: this.walletId,
    })
    const walletIndex = (countResult.accounts || []).length

    const id = randomUUID()
    const wallet: AgentWallet = {
      id,
      tenant_id: tenantId,
      agent_id: agentId,
      nano_address: nanoAddress,
      wallet_index: walletIndex,
      status: 'active',
      balance_raw: '0',
      total_received_raw: '0',
      total_sent_raw: '0',
      created_at: new Date().toISOString(),
    }

    db.prepare(`INSERT INTO agent_wallets
      (id, tenant_id, agent_id, nano_address, wallet_index, status,
       balance_raw, total_received_raw, total_sent_raw)
      VALUES (?, ?, ?, ?, ?, 'active', '0', '0', '0')`)
      .run(id, tenantId, agentId, nanoAddress, walletIndex)

    return wallet
  }

  /**
   * Get live balance from the Nano network.
   */
  async getBalance(tenantId: string, agentId: string): Promise<{
    balance_raw: string
    balance_xno: string
    receivable_raw: string
    receivable_xno: string
    nano_address: string
  }> {
    const db = getDB()
    const wallet = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(tenantId, agentId) as AgentWallet | undefined
    if (!wallet) throw new Error(`No active wallet for agent "${agentId}"`)

    const result = await walletRpc(this.readRpcUrl, {
      action: 'account_balance',
      account: wallet.nano_address,
    })

    // Update cached balance
    db.prepare(`UPDATE agent_wallets SET balance_raw = ? WHERE id = ?`)
      .run(result.balance, wallet.id)

    return {
      balance_raw: result.balance,
      balance_xno: rawToXno(result.balance),
      receivable_raw: result.receivable || result.pending || '0',
      receivable_xno: rawToXno(result.receivable || result.pending || '0'),
      nano_address: wallet.nano_address,
    }
  }

  /**
   * Delegation-gated send. The core differentiator.
   *
   * Before any XNO leaves an agent's wallet:
   *   1. Agent must have active wallet (not frozen/revoked)
   *   2. Agent must have active delegation with commerce:* scope
   *   3. Amount must be within delegation spend limit
   *   4. Gateway records evaluation + receipt
   *
   * Returns block hash as on-chain proof.
   */
  async send(opts: {
    tenantId: string
    fromAgentId: string
    toAddress: string
    amountXno: number
    toAgentId?: string           // if sending to another APS agent
    memo?: string
  }): Promise<WalletTransaction> {
    const db = getDB()
    const amountRaw = xnoToRaw(String(opts.amountXno))
    const txId = randomUUID()

    // ── Gate 1: Wallet exists and is active ──
    const wallet = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(opts.tenantId, opts.fromAgentId) as AgentWallet | undefined
    if (!wallet) {
      return this.recordDenied(txId, opts, amountRaw, 'No active wallet for agent')
    }

    // ── Gate 2: Active delegation with commerce scope ──
    const delegation = db.prepare(`
      SELECT * FROM delegations
      WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
      ORDER BY created_at DESC LIMIT 1
    `).get(opts.tenantId, opts.fromAgentId) as any
    if (!delegation) {
      return this.recordDenied(txId, opts, amountRaw, 'No active delegation for agent')
    }

    const scopes = delegation.scope.split(',').map((s: string) => s.trim())
    const hasCommerceScope = scopes.some((s: string) =>
      s === '*' || s === 'commerce:*' || s === 'commerce:send'
      || s === 'commerce:checkout'
      || (s.endsWith(':*') && 'commerce:send'.startsWith(s.slice(0, -1)))
    )
    if (!hasCommerceScope) {
      return this.recordDenied(txId, opts, amountRaw,
        `Agent lacks commerce scope. Has: [${delegation.scope}]`)
    }

    // ── Gate 3: Spend limit check ──
    if (delegation.spend_limit) {
      const remaining = delegation.spend_limit - (delegation.spend_used || 0)
      if (opts.amountXno > remaining) {
        return this.recordDenied(txId, opts, amountRaw,
          `Amount ${opts.amountXno} XNO exceeds remaining budget ${remaining.toFixed(6)} XNO`)
      }
    }

    // ── Gate 4: Execute on-chain send ──
    try {
      const result = await walletRpc(this.rpcUrl, {
        action: 'send',
        wallet: this.walletId,
        source: wallet.nano_address,
        destination: opts.toAddress,
        amount: amountRaw,
        id: txId,  // idempotency
      })

      // Update delegation spend tracking
      db.prepare(`UPDATE delegations SET spend_used = spend_used + ? WHERE id = ?`)
        .run(opts.amountXno, delegation.id)

      // Update wallet totals
      const newSent = (BigInt(wallet.total_sent_raw) + BigInt(amountRaw)).toString()
      db.prepare(`UPDATE agent_wallets SET total_sent_raw = ? WHERE id = ?`)
        .run(newSent, wallet.id)

      // Record confirmed transaction
      const tx: WalletTransaction = {
        id: txId,
        tenant_id: opts.tenantId,
        from_agent_id: opts.fromAgentId,
        to_agent_id: opts.toAgentId,
        to_address: opts.toAddress,
        amount_raw: amountRaw,
        amount_xno: String(opts.amountXno),
        block_hash: result.block,
        delegation_id: delegation.id,
        scope_used: 'commerce:send',
        status: 'confirmed',
        created_at: new Date().toISOString(),
        confirmed_at: new Date().toISOString(),
      }

      db.prepare(`INSERT INTO wallet_transactions
        (id, tenant_id, from_agent_id, to_agent_id, to_address,
         amount_raw, amount_xno, block_hash, delegation_id,
         scope_used, status, confirmed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', datetime('now'))`)
        .run(txId, opts.tenantId, opts.fromAgentId,
          opts.toAgentId || null, opts.toAddress,
          amountRaw, String(opts.amountXno), result.block,
          delegation.id, 'commerce:send')

      return tx

    } catch (e: any) {
      db.prepare(`INSERT INTO wallet_transactions
        (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
         delegation_id, scope_used, status, denial_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'failed', ?)`)
        .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
          amountRaw, String(opts.amountXno), delegation.id,
          'commerce:send', e.message)

      return {
        id: txId, tenant_id: opts.tenantId,
        from_agent_id: opts.fromAgentId,
        to_address: opts.toAddress,
        amount_raw: amountRaw, amount_xno: String(opts.amountXno),
        status: 'failed' as const, denial_reason: e.message,
        created_at: new Date().toISOString(),
      }
    }
  }

  /** Record a denied transaction */
  private recordDenied(
    txId: string,
    opts: { tenantId: string; fromAgentId: string; toAddress: string; amountXno: number },
    amountRaw: string,
    reason: string,
  ): WalletTransaction {
    const db = getDB()
    db.prepare(`INSERT INTO wallet_transactions
      (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
       status, denial_reason)
      VALUES (?, ?, ?, ?, ?, ?, 'denied', ?)`)
      .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
        amountRaw, String(opts.amountXno), reason)

    // Fire alert
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
      VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), opts.tenantId, 'wallet_denied', 'warning',
        `Wallet send DENIED for "${opts.fromAgentId}": ${reason}`)

    return {
      id: txId, tenant_id: opts.tenantId,
      from_agent_id: opts.fromAgentId,
      to_address: opts.toAddress,
      amount_raw: amountRaw, amount_xno: String(opts.amountXno),
      status: 'denied', denial_reason: reason,
      created_at: new Date().toISOString(),
    }
  }

  /**
   * Receive all pending funds for an agent's wallet.
   * Nano requires explicitly "pocketing" received blocks.
   */
  async receiveAll(tenantId: string, agentId: string): Promise<{
    received: number; blocks: string[]
  }> {
    const db = getDB()
    const wallet = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(tenantId, agentId) as AgentWallet | undefined
    if (!wallet) throw new Error(`No active wallet for agent "${agentId}"`)

    // Get receivable blocks
    const receivable = await walletRpc(this.readRpcUrl, {
      action: 'receivable',
      account: wallet.nano_address,
      count: '100',
    })

    const hashes = Object.keys(receivable.blocks || {})
    const blocks: string[] = []

    for (const hash of hashes) {
      try {
        const result = await walletRpc(this.rpcUrl, {
          action: 'receive',
          wallet: this.walletId,
          account: wallet.nano_address,
          block: hash,
        })
        blocks.push(result.block)
      } catch { /* skip failed receives */ }
    }

    return { received: blocks.length, blocks }
  }

  /**
   * Freeze a wallet — no sends allowed. Part of revocation cascade.
   * When an agent's delegation is revoked, their wallet freezes.
   */
  freezeWallet(tenantId: string, agentId: string): void {
    const db = getDB()
    db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenantId, agentId)
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
      VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenantId, 'wallet_frozen', 'critical',
        `Wallet for agent "${agentId}" has been frozen`)
  }

  /** Revoke a wallet permanently */
  revokeWallet(tenantId: string, agentId: string): void {
    const db = getDB()
    db.prepare(`UPDATE agent_wallets SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenantId, agentId)
  }

  /** Get wallet info */
  getWallet(tenantId: string, agentId: string): AgentWallet | undefined {
    const db = getDB()
    return db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as AgentWallet | undefined
  }

  /** Get transaction history for an agent */
  getTransactions(tenantId: string, agentId: string, limit: number = 50): WalletTransaction[] {
    const db = getDB()
    return db.prepare(`
      SELECT * FROM wallet_transactions
      WHERE tenant_id = ? AND (from_agent_id = ? OR to_agent_id = ?)
      ORDER BY created_at DESC LIMIT ?
    `).all(tenantId, agentId, agentId, limit) as WalletTransaction[]
  }

  /** List all wallets for a tenant */
  listWallets(tenantId: string): AgentWallet[] {
    const db = getDB()
    return db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? ORDER BY created_at DESC`
    ).all(tenantId) as AgentWallet[]
  }

  /** Dashboard: wallet summary for tenant */
  async walletDashboard(tenantId: string): Promise<{
    total_wallets: number
    active_wallets: number
    frozen_wallets: number
    total_transactions: number
    total_denied: number
    recent_transactions: WalletTransaction[]
  }> {
    const db = getDB()

    const total = db.prepare(`SELECT COUNT(*) as c FROM agent_wallets WHERE tenant_id = ?`).get(tenantId) as any
    const active = db.prepare(`SELECT COUNT(*) as c FROM agent_wallets WHERE tenant_id = ? AND status = 'active'`).get(tenantId) as any
    const frozen = db.prepare(`SELECT COUNT(*) as c FROM agent_wallets WHERE tenant_id = ? AND status = 'frozen'`).get(tenantId) as any
    const txTotal = db.prepare(`SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ?`).get(tenantId) as any
    const denied = db.prepare(`SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ? AND status = 'denied'`).get(tenantId) as any
    const recent = db.prepare(`SELECT * FROM wallet_transactions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 20`).all(tenantId) as WalletTransaction[]

    return {
      total_wallets: total.c,
      active_wallets: active.c,
      frozen_wallets: frozen.c,
      total_transactions: txTotal.c,
      total_denied: denied.c,
      recent_transactions: recent,
    }
  }
}

// ── Singleton ──

let _walletService: AgentWalletService | null = null

export function getWalletService(): AgentWalletService {
  if (!_walletService) {
    const rpcUrl = process.env.NANO_WALLET_RPC_URL
    const walletId = process.env.NANO_WALLET_ID
    if (!rpcUrl || !walletId) {
      throw new Error('Agent wallet service requires NANO_WALLET_RPC_URL and NANO_WALLET_ID')
    }
    _walletService = new AgentWalletService({
      rpcUrl,
      readRpcUrl: process.env.NANO_RPC_URL || 'https://rpc.nano.to',
      walletId,
    })
  }
  return _walletService
}
