// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Stripe Billing — subscription management for gateway tenants
 *
 * Flow:
 *   1. Tenant signs up (free plan, no Stripe customer)
 *   2. Tenant clicks "Upgrade" on portal → POST /billing/checkout
 *   3. Stripe Checkout Session created → redirect to Stripe
 *   4. Stripe webhook fires → tenant plan updated in DB
 *   5. Tenant can manage subscription via POST /billing/portal
 *
 * Env vars:
 *   STRIPE_SECRET_KEY — sk_live_... or sk_test_...
 *   STRIPE_WEBHOOK_SECRET — whsec_...
 *   PORTAL_URL — https://aeoess.com (for redirect URLs)
 */

import { Router } from 'express'
import Stripe from 'stripe'
import { getDB } from '../db/schema.js'

// Price IDs — set these after creating products in Stripe Dashboard
const PRICE_IDS: Record<string, string> = {
  pro: process.env.STRIPE_PRICE_PRO || 'price_pro_placeholder',
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || 'price_enterprise_placeholder',
}

const PORTAL_URL = process.env.PORTAL_URL || 'https://aeoess.com'

function getStripe(): Stripe | null {
  const key = process.env.STRIPE_SECRET_KEY
  if (!key) return null
  return new Stripe(key)
}

export const billingRouter = Router()

/**
 * POST /billing/checkout — create Stripe Checkout Session
 * Body: { plan: 'pro' | 'enterprise' }
 * Returns: { url: 'https://checkout.stripe.com/...' }
 */
billingRouter.post('/billing/checkout', async (req: any, res) => {
  const stripe = getStripe()
  if (!stripe) {
    return res.status(503).json({ error: 'Billing not configured. Set STRIPE_SECRET_KEY.' })
  }

  const tenant = req.tenant
  const { plan } = req.body

  if (!plan || !PRICE_IDS[plan]) {
    return res.status(400).json({ error: 'Invalid plan. Options: pro, enterprise' })
  }

  if (tenant.plan === plan) {
    return res.status(400).json({ error: `Already on ${plan} plan` })
  }

  const db = getDB()

  try {
    // Create or retrieve Stripe customer
    let customerId = tenant.stripe_customer_id
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: tenant.email,
        name: tenant.name,
        metadata: { tenant_id: tenant.id },
      })
      customerId = customer.id
      db.prepare(`UPDATE tenants SET stripe_customer_id = ? WHERE id = ?`)
        .run(customerId, tenant.id)
    }

    // Create Checkout Session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: PRICE_IDS[plan], quantity: 1 }],
      success_url: `${PORTAL_URL}/portal.html?upgrade=success&plan=${plan}`,
      cancel_url: `${PORTAL_URL}/portal.html?upgrade=cancelled`,
      metadata: { tenant_id: tenant.id, plan },
      subscription_data: {
        metadata: { tenant_id: tenant.id, plan },
      },
    })

    res.json({ url: session.url })
  } catch (e: any) {
    console.error('Stripe checkout error:', e.message)
    res.status(500).json({ error: 'Failed to create checkout session' })
  }
})

/**
 * POST /billing/portal — create Stripe Customer Portal session
 * Returns: { url: 'https://billing.stripe.com/...' }
 */
billingRouter.post('/billing/portal', async (req: any, res) => {
  const stripe = getStripe()
  if (!stripe) {
    return res.status(503).json({ error: 'Billing not configured' })
  }

  const tenant = req.tenant
  if (!tenant.stripe_customer_id) {
    return res.status(400).json({ error: 'No billing account. Upgrade to a paid plan first.' })
  }

  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: tenant.stripe_customer_id,
      return_url: `${PORTAL_URL}/portal.html`,
    })
    res.json({ url: session.url })
  } catch (e: any) {
    console.error('Stripe portal error:', e.message)
    res.status(500).json({ error: 'Failed to create billing portal session' })
  }
})

/**
 * GET /billing/status — current subscription status
 */
billingRouter.get('/billing/status', async (req: any, res) => {
  const stripe = getStripe()
  const tenant = req.tenant

  if (!stripe || !tenant.stripe_customer_id) {
    return res.json({
      plan: tenant.plan,
      billing: 'none',
      message: tenant.plan === 'free' ? 'Free plan — no billing' : 'Manual billing',
    })
  }

  try {
    const subscriptions = await stripe.subscriptions.list({
      customer: tenant.stripe_customer_id,
      status: 'active',
      limit: 1,
    })

    if (subscriptions.data.length === 0) {
      return res.json({ plan: tenant.plan, billing: 'none' })
    }

    const sub = subscriptions.data[0]
    res.json({
      plan: tenant.plan,
      billing: 'active',
      subscription_id: sub.id,
      current_period_end: new Date((sub as any).current_period_end * 1000).toISOString(),
      cancel_at_period_end: sub.cancel_at_period_end,
    })
  } catch (e: any) {
    res.status(500).json({ error: 'Failed to fetch billing status' })
  }
})

/**
 * Stripe Webhook handler — called by Stripe, NOT authenticated via API key.
 * Must be mounted BEFORE express.json() or with raw body parsing.
 */
export async function handleStripeWebhook(req: any, res: any) {
  const stripe = getStripe()
  if (!stripe) return res.status(503).send('Billing not configured')

  const sig = req.headers['stripe-signature']
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET

  if (!webhookSecret) {
    return res.status(503).send('Webhook secret not configured')
  }

  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret)
  } catch (e: any) {
    console.error('Webhook signature verification failed:', e.message)
    return res.status(400).send(`Webhook Error: ${e.message}`)
  }

  const db = getDB()

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session
      const tenantId = session.metadata?.tenant_id
      const plan = session.metadata?.plan
      if (tenantId && plan) {
        db.prepare(`UPDATE tenants SET plan = ?, stripe_customer_id = ? WHERE id = ?`)
          .run(plan, session.customer as string, tenantId)
        console.log(`Tenant ${tenantId} upgraded to ${plan}`)
      }
      break
    }

    case 'customer.subscription.updated': {
      const sub = event.data.object as Stripe.Subscription
      const tenantId = sub.metadata?.tenant_id
      if (tenantId && sub.status === 'active') {
        // Plan might have changed via Stripe portal
        const plan = sub.metadata?.plan || 'pro'
        db.prepare(`UPDATE tenants SET plan = ? WHERE id = ?`).run(plan, tenantId)
      }
      break
    }

    case 'customer.subscription.deleted': {
      const sub = event.data.object as Stripe.Subscription
      const tenantId = sub.metadata?.tenant_id
      if (tenantId) {
        db.prepare(`UPDATE tenants SET plan = 'free' WHERE id = ?`).run(tenantId)
        console.log(`Tenant ${tenantId} downgraded to free (subscription cancelled)`)
      }
      break
    }

    default:
      // Unhandled event type — ignore
      break
  }

  res.json({ received: true })
}
