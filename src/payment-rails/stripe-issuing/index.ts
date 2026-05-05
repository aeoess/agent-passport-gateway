// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Stripe Issuing payment rail — orchestration class (gateway product)
// ══════════════════════════════════════════════════════════════════
// Implements PaymentRail by issuing one-time virtual cards via the
// Stripe Issuing API and intercepting the issuing_authorization.request
// webhook. APS gates run BEFORE Stripe is told to approve, so an
// authorization that would violate delegation scope or budget is
// declined at the rail boundary and never settles.
//
// PROTOCOL PRIMITIVES (live in the SDK at
// `agent-passport-system`'s payment-rails/stripe-issuing/primitives.ts):
//   - defaultMapDelegationToSpendingControls
//   - delegationToView
//   - encodeForm
//   - verifyStripeSignature
//   - DEFAULT_API_BASE / DEFAULT_REQUIRED_SCOPE / DEFAULT_TOLERANCE_SEC / RAIL_NAME
//
// PRODUCT CODE (this file):
//   - class StripeIssuingRail (live HTTP client + credential handling +
//     in-memory card↔delegation registry)
//   - createStripeIssuingRail factory
//
// Flow:
//   1. provisionAgentCard(V2Delegation)
//        ↳ map delegation → Stripe SpendingControls (SDK primitive)
//        ↳ POST /v1/issuing/cards (type=virtual)
//        ↳ stash {cardId → DelegationView} in-memory for webhook lookup
//   2. Agent attempts purchase → Stripe sends webhook
//   3. handleAuthorizationWebhook(event)
//        ↳ resolve delegation by event.data.object.card.id
//        ↳ preAuthorize (wallet_revoked, no_commerce_scope,
//          time_window_violation, spend_limit_exceeded)
//        ↳ pass: POST /v1/issuing/authorizations/:id/approve  + emit receipt
//        ↳ fail: POST /v1/issuing/authorizations/:id/decline  + emit denial
//   4. revokeWallet(cardId) → POST /v1/issuing/cards/:id status=canceled
//
// Reference adapter is sk_test_ only; refuses sk_live_ in constructor.
// Live keys are deployment policy; this constraint stays even now that
// the class lives in the gateway repo, because the public reference
// remains the test-mode shape.
// ══════════════════════════════════════════════════════════════════

import {
  // Primitives (formerly internal to this file; now imported from SDK).
  // The SDK barrel re-exports the four constants and the two helper
  // functions under prefixed names to avoid colliding with other rail
  // surfaces — alias them back to the local names this class was
  // written against so the body needs no further changes.
  STRIPE_ISSUING_DEFAULT_API_BASE as DEFAULT_API_BASE,
  STRIPE_ISSUING_DEFAULT_REQUIRED_SCOPE as DEFAULT_REQUIRED_SCOPE,
  STRIPE_ISSUING_DEFAULT_TOLERANCE_SEC as DEFAULT_TOLERANCE_SEC,
  STRIPE_ISSUING_RAIL_NAME as RAIL_NAME,
  defaultMapDelegationToSpendingControls,
  stripeIssuingDelegationToView as delegationToView,
  stripeIssuingEncodeForm as encodeForm,
  verifyStripeSignature,
  // Foundation hooks + canonicalization helpers
  emitDenial,
  emitReceipt,
  preAuthorize,
  paymentRailsSha256Hex as sha256Hex,
  // Foundation types
  type CreateInvoiceOpts,
  type DelegationView,
  type DenialReason,
  type PaymentInvoice,
  type PaymentRail,
  type VerifyTransactionResult,
  // Stripe-Issuing types (re-exported by the SDK primitives module)
  type StripeAuthorization as Authorization,
  type StripeAuthorizationDecision as AuthorizationDecision,
  type StripeAuthorizationEvent as AuthorizationEvent,
  type StripeDelegationLookup as DelegationLookup,
  type StripeFetchLike as FetchLike,
  type StripeSpendingControls as SpendingControls,
  type StripeSpendingControlsMapper as SpendingControlsMapper,
  type StripeIssuingConfig,
  type StripeVirtualCard as VirtualCard,
  // Owner-confirmation type used in webhook escalation context
  type OwnerConfirmation,
  // Delegation type
  type V2Delegation,
} from 'agent-passport-system'

export class StripeIssuingRail implements PaymentRail {
  readonly name = RAIL_NAME
  readonly currency: string

  private readonly config: Required<
    Pick<StripeIssuingConfig, 'apiKey' | 'issuerPrivateKeyHex' | 'apiBase'>
  > &
    Omit<StripeIssuingConfig, 'apiKey' | 'issuerPrivateKeyHex' | 'apiBase'>
  private readonly stripeCurrency: string
  private readonly fetch: FetchLike
  private readonly mapper: SpendingControlsMapper
  private readonly requiredScope: string
  private readonly toleranceSec: number

  /** In-memory card → DelegationView lookup, populated by
   *  provisionAgentCard. Gateway implementations override via
   *  config.delegationLookup. */
  private readonly cardDelegations = new Map<string, DelegationView>()
  private readonly revokedCards = new Set<string>()

  constructor(config: StripeIssuingConfig) {
    if (!config.apiKey || typeof config.apiKey !== 'string') {
      throw new Error('StripeIssuingRail: apiKey is required')
    }
    if (config.apiKey.startsWith('sk_live_')) {
      throw new Error(
        'StripeIssuingRail: refusing sk_live_ key. The reference adapter is test-mode only.',
      )
    }
    if (!config.apiKey.startsWith('sk_test_')) {
      throw new Error(
        "StripeIssuingRail: apiKey must start with 'sk_test_'",
      )
    }
    if (!config.issuerPrivateKeyHex) {
      throw new Error('StripeIssuingRail: issuerPrivateKeyHex is required')
    }

    this.currency = (config.apsCurrency ?? 'USD').toUpperCase()
    this.stripeCurrency = (config.stripeCurrency ?? this.currency).toLowerCase()
    this.fetch = config.fetch ?? (globalThis.fetch as unknown as FetchLike)
    this.mapper = config.spendingControlsMapper ?? defaultMapDelegationToSpendingControls
    this.requiredScope = config.requiredScope ?? DEFAULT_REQUIRED_SCOPE
    this.toleranceSec = config.webhookToleranceSec ?? DEFAULT_TOLERANCE_SEC

    this.config = {
      apiKey: config.apiKey,
      issuerPrivateKeyHex: config.issuerPrivateKeyHex,
      apiBase: config.apiBase ?? DEFAULT_API_BASE,
      apsCurrency: config.apsCurrency,
      stripeCurrency: config.stripeCurrency,
      defaultCardholder: config.defaultCardholder,
      webhookSecret: config.webhookSecret,
      fetch: config.fetch,
      spendingControlsMapper: config.spendingControlsMapper,
      delegationLookup: config.delegationLookup,
      requiredScope: config.requiredScope,
      webhookToleranceSec: config.webhookToleranceSec,
      accountabilityShape: config.accountabilityShape,
      issuerAgentId: config.issuerAgentId,
      issuerKeyRef: config.issuerKeyRef,
    }
  }

  // ── Stripe HTTP helpers ─────────────────────────────────────────

  private async stripePost(
    path: string,
    body: Record<string, unknown>,
  ): Promise<unknown> {
    const url = `${this.config.apiBase}${path}`
    const res = await this.fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: encodeForm(body),
    })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(`Stripe ${path} returned ${res.status}: ${text.slice(0, 500)}`)
    }
    try {
      return JSON.parse(text)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      throw new Error(`Stripe ${path} returned non-JSON body: ${msg}`)
    }
  }

  private async stripeGet(path: string): Promise<unknown> {
    const url = `${this.config.apiBase}${path}`
    const res = await this.fetch(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${this.config.apiKey}` },
    })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(`Stripe ${path} returned ${res.status}: ${text.slice(0, 500)}`)
    }
    try {
      return JSON.parse(text)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      throw new Error(`Stripe ${path} returned non-JSON body: ${msg}`)
    }
  }

  // ── Provisioning ────────────────────────────────────────────────

  /**
   * Mint a one-time virtual card whose Stripe SpendingControls mirror
   * the APS delegation. The returned card carries delegation_ref and
   * cancel_at hints in metadata for downstream auditors.
   */
  async provisionAgentCard(
    delegation: V2Delegation,
    opts: { cardholder?: string } = {},
  ): Promise<VirtualCard> {
    const cardholder = opts.cardholder ?? this.config.defaultCardholder
    if (!cardholder) {
      throw new Error(
        'provisionAgentCard: cardholder id required (pass opts.cardholder or set config.defaultCardholder)',
      )
    }

    const sc = this.mapper(delegation)
    const sc_with_currency: SpendingControls = {
      ...sc,
      spending_limits_currency: this.stripeCurrency,
    }

    const metadata: Record<string, string> = {
      aps_delegation_ref: delegation.id,
      aps_delegator: delegation.delegator,
      aps_delegatee: delegation.delegatee,
      aps_currency: this.currency,
    }
    if (delegation.policy_context.valid_until) {
      metadata.aps_cancel_at_iso = delegation.policy_context.valid_until
    }

    const body: Record<string, unknown> = {
      cardholder,
      currency: this.stripeCurrency,
      type: 'virtual',
      status: 'active',
      spending_controls: sc_with_currency,
      metadata,
    }

    const card = (await this.stripePost('/v1/issuing/cards', body)) as VirtualCard
    if (!card || typeof card.id !== 'string') {
      throw new Error('provisionAgentCard: Stripe response did not include card.id')
    }

    // Record the card → delegation mapping so later webhooks can
    // resolve the delegation without an external store. Gateway
    // production deployments override delegationLookup with a DB.
    const view = delegationToView(delegation, this.currency, card.id)
    this.cardDelegations.set(card.id, view)

    return card
  }

  // ── Authorization webhook handling ──────────────────────────────

  /**
   * Verify a raw Stripe webhook body against the Stripe-Signature
   * header using the configured webhookSecret. Throws if no secret
   * is configured. Returns false on any verification failure.
   */
  verifyWebhookSignature(
    rawBody: string,
    signatureHeader: string,
    nowSec?: number,
  ): boolean {
    if (!this.config.webhookSecret) {
      throw new Error(
        'verifyWebhookSignature: no webhookSecret configured on StripeIssuingRail',
      )
    }
    return verifyStripeSignature(
      rawBody,
      signatureHeader,
      this.config.webhookSecret,
      this.toleranceSec,
      nowSec,
    )
  }

  /**
   * Run APS gates on an incoming issuing_authorization.request and
   * approve or decline via Stripe. Returns the decision plus the
   * signed APS PaymentReceipt or PaymentDenial.
   *
   * Rail-side guarantees:
   *   - Stripe is called exactly once (approve XOR decline).
   *   - APS receipt or denial is always emitted (even on rail_error).
   *   - Lookup miss → decline + rail_error denial. The rail never
   *     approves an authorization for a card it cannot tie back to a
   *     delegation.
   */
  async handleAuthorizationWebhook(
    event: AuthorizationEvent,
    /** Optional caller-supplied escalation context. When the card's
     *  delegation has an escalation_requirement on action_class
     *  'commerce' with requires_owner_confirmation: true, the gateway
     *  surfaces the OwnerConfirmation it collected from the operator
     *  here so the rail can verify it before approving. */
    escalation?: {
      owner_confirmation?: OwnerConfirmation
      action_details?: Record<string, unknown>
      session_id?: string | null
    },
  ): Promise<AuthorizationDecision> {
    const auth = event?.data?.object
    if (!auth || typeof auth.id !== 'string' || typeof auth.card?.id !== 'string') {
      throw new Error(
        'handleAuthorizationWebhook: malformed event (missing data.object.id or card.id)',
      )
    }

    const cardId = auth.card.id
    const lookup = this.config.delegationLookup ?? ((id: string) => this.cardDelegations.get(id) ?? null)
    const view = lookup(cardId)
    const action_ref = sha256Hex(`stripe-issuing-auth:${auth.id}`)
    const amountStr = String(auth.pending_request?.amount ?? auth.amount)
    const eventCurrency = (auth.pending_request?.currency ?? auth.currency).toUpperCase()

    if (view === null || view === undefined) {
      return await this._declineAndDeny({
        auth,
        action_ref,
        amountStr,
        eventCurrency,
        delegation_ref: '',
        denial_reason: 'rail_error',
        reason_detail: `no delegation registered for card ${cardId}`,
      })
    }

    const pre = preAuthorize(
      {
        delegation: view,
        required_scope: this.requiredScope,
        amount_base_units: amountStr,
        currency: eventCurrency,
        action_class: 'commerce',
        owner_confirmation: escalation?.owner_confirmation,
        action_details: escalation?.action_details,
        session_id: escalation?.session_id,
      },
      this,
    )

    if (pre.ok === false) {
      return await this._declineAndDeny({
        auth,
        action_ref,
        amountStr,
        eventCurrency,
        delegation_ref: view.receipt_id,
        denial_reason: pre.denial_reason,
        reason_detail: pre.reason_detail,
      })
    }

    return await this._approveAndReceipt({
      auth,
      action_ref,
      amountStr,
      eventCurrency,
      delegation_ref: view.receipt_id,
    })
  }

  private async _approveAndReceipt(args: {
    auth: Authorization
    action_ref: string
    amountStr: string
    eventCurrency: string
    delegation_ref: string
  }): Promise<AuthorizationDecision> {
    try {
      await this.stripePost(`/v1/issuing/authorizations/${args.auth.id}/approve`, {
        metadata: {
          aps_delegation_ref: args.delegation_ref,
          aps_action_ref: args.action_ref,
        },
      })
    } catch (e) {
      // Stripe approve failed → fall through to denial path so APS
      // never emits a receipt for an unsettled authorization.
      const msg = e instanceof Error ? e.message : String(e)
      return await this._declineAndDeny({
        auth: args.auth,
        action_ref: args.action_ref,
        amountStr: args.amountStr,
        eventCurrency: args.eventCurrency,
        delegation_ref: args.delegation_ref,
        denial_reason: 'rail_error',
        reason_detail: `Stripe approve call failed: ${msg.slice(0, 300)}`,
      })
    }

    const receipt = emitReceipt(
      {
        delegation_ref: args.delegation_ref,
        action_ref: args.action_ref,
        rail_name: this.name,
        amount_base_units: args.amountStr,
        currency: args.eventCurrency,
        tx_proof: args.auth.id,
        accountability_shape: this.config.accountabilityShape === true,
        issuer_agent_id: this.config.issuerAgentId,
        issuer_key_ref: this.config.issuerKeyRef,
      },
      this.config.issuerPrivateKeyHex,
    )
    return { approved: true, receipt }
  }

  private async _declineAndDeny(args: {
    auth: Authorization
    action_ref: string
    amountStr: string
    eventCurrency: string
    delegation_ref: string
    denial_reason: DenialReason
    reason_detail?: string
  }): Promise<AuthorizationDecision> {
    let stripeDeclineErr: string | undefined
    try {
      await this.stripePost(`/v1/issuing/authorizations/${args.auth.id}/decline`, {
        metadata: {
          aps_denial_reason: args.denial_reason,
          aps_delegation_ref: args.delegation_ref,
        },
      })
    } catch (e) {
      stripeDeclineErr = e instanceof Error ? e.message : String(e)
    }

    const detail = stripeDeclineErr
      ? `${args.reason_detail ?? ''}${args.reason_detail ? ' | ' : ''}stripe_decline_error: ${stripeDeclineErr.slice(0, 200)}`
      : args.reason_detail

    const denialInput: Parameters<typeof emitDenial>[0] = {
      delegation_ref: args.delegation_ref,
      action_ref: args.action_ref,
      rail_name: this.name,
      amount_base_units: args.amountStr,
      currency: args.eventCurrency,
      denial_reason: args.denial_reason,
      accountability_shape: this.config.accountabilityShape === true,
      issuer_agent_id: this.config.issuerAgentId,
      issuer_key_ref: this.config.issuerKeyRef,
    }
    if (detail !== undefined) denialInput.reason_detail = detail

    const denial = emitDenial(denialInput, this.config.issuerPrivateKeyHex)
    const decision: AuthorizationDecision = {
      approved: false,
      reason: args.denial_reason,
      denial,
    }
    if (detail !== undefined) decision.reason_detail = detail
    return decision
  }

  /** Convenience: register a card↔delegation mapping without going
   *  through provisionAgentCard. Useful for tests and for gateway code
   *  that provisions cards out-of-band. */
  registerCardDelegation(cardId: string, view: DelegationView): void {
    this.cardDelegations.set(cardId, view)
  }

  // ── PaymentRail surface ────────────────────────────────────────

  async createInvoice(_opts: CreateInvoiceOpts): Promise<PaymentInvoice> {
    throw new Error(
      'StripeIssuingRail does not issue invoices. Use provisionAgentCard() to mint a virtual card and let the agent transact through it.',
    )
  }

  async checkStatus(_invoiceId: string): Promise<PaymentInvoice> {
    throw new Error(
      'StripeIssuingRail does not track invoices. Use verifyTransaction(authorizationId) to inspect a Stripe authorization by id.',
    )
  }

  /**
   * Look up a Stripe authorization by id and return whether it is
   * settled (status='closed' AND approved=true) at the expected amount.
   */
  async verifyTransaction(
    txProof: string,
    expectedAmountBaseUnits?: string,
  ): Promise<VerifyTransactionResult> {
    let auth: Authorization
    try {
      auth = (await this.stripeGet(`/v1/issuing/authorizations/${txProof}`)) as Authorization
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      return { verified: false, amount_base_units: '0', error: msg }
    }
    const amountStr = String(auth.amount ?? '0')
    let amountMatches = true
    if (expectedAmountBaseUnits !== undefined) {
      try {
        amountMatches = BigInt(amountStr) === BigInt(expectedAmountBaseUnits)
      } catch {
        amountMatches = false
      }
    }
    const verified = auth.approved === true && auth.status === 'closed' && amountMatches
    const cardholderId =
      typeof auth.card?.cardholder === 'string'
        ? auth.card.cardholder
        : auth.card?.cardholder?.id
    return {
      verified,
      amount_base_units: amountStr,
      sender: cardholderId,
      receiver: auth.merchant_data?.name,
      timestamp:
        auth.created !== undefined ? new Date(auth.created * 1000).toISOString() : undefined,
    }
  }

  /**
   * Cancel a Stripe card (terminal). Idempotent: cancelling an already
   * canceled card returns true. Records the cardId in an in-memory
   * revoked set so isWalletRevoked is fast and offline-safe even when
   * Stripe is unreachable.
   */
  async revokeWallet(walletId: string): Promise<boolean> {
    if (this.revokedCards.has(walletId)) return true
    try {
      await this.stripePost(`/v1/issuing/cards/${walletId}`, { status: 'canceled' })
    } catch (e) {
      // Stripe surfaces "card already canceled" as a 400. Treat as
      // success to keep revokeWallet idempotent across retries.
      const msg = e instanceof Error ? e.message : String(e)
      if (!/canceled|already/i.test(msg)) {
        throw e
      }
    }
    this.revokedCards.add(walletId)
    // Intentionally keep the cardDelegations entry: incoming webhooks
    // for a revoked card must still resolve a DelegationView so
    // preAuthorize returns 'wallet_revoked' rather than 'rail_error'.
    return true
  }

  isWalletRevoked(walletId: string): boolean {
    return this.revokedCards.has(walletId)
  }
}

// ── Factory ─────────────────────────────────────────────────────

export function createStripeIssuingRail(config: StripeIssuingConfig): StripeIssuingRail {
  return new StripeIssuingRail(config)
}
