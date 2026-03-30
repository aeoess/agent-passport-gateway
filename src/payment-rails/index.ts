// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Payment Rails — Barrel Export
 *
 * The gateway is payment-rail agnostic. Each rail implements
 * the PaymentRail interface. Nano ships first.
 * Agent wallets are APS-native: delegation-gated, receipt-linked.
 */

export type { PaymentRail, PaymentInvoice, PaymentConfirmation, PaymentTransaction } from './types.js'
export { NanoPaymentRail, createNanoRail, getNanoRail, xnoToRaw, rawToXno } from './nano.js'
export { paymentRouter } from './routes.js'
export { AgentWalletService, getWalletService } from './wallet.js'
export type { AgentWallet, WalletTransaction } from './wallet.js'
export { NanoLocalWallet, getLocalWallet, deriveAccount, getMasterSeed } from './wallet-crypto.js'
export { walletRouter } from './wallet-routes.js'
