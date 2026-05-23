const Stripe = require('stripe');
const crypto = require('crypto');
const { setSecurityHeaders, checkEnvVars } = require('./_lib/security');

// CRITICAL: disable body parser — Stripe needs the raw body to verify signature
export const config = { api: { bodyParser: false } };

// Idempotency store — prevents replaying the same webhook event twice
// In-memory is fine for low volume; for scale use Redis
const processedEvents = new Set();
setInterval(() => {
  // Clear old events every hour to prevent unbounded memory growth
  if (processedEvents.size > 10000) processedEvents.clear();
}, 60 * 60 * 1000);

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data',  chunk => chunks.push(chunk));
    req.on('end',   ()    => resolve(Buffer.concat(chunks)));
    req.on('error', err   => reject(err));
  });
}

// ── HARDCODED COMMISSION — never from webhook payload ────
const INST_AMOUNT     = 29900;
const COMMISSION_RATE = 0.15;
const COMMISSION      = Math.floor(INST_AMOUNT * COMMISSION_RATE); // €44.85 — fixed

module.exports = async (req, res) => {
  setSecurityHeaders(res);

  // Webhook only accepts POST from Stripe
  if (req.method !== 'POST') return res.status(405).end();

  // ── ENV CHECK ────────────────────────────────────────────
  try {
    checkEnvVars(['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_REBECCA_ACCOUNT']);
  } catch {
    console.error('[webhook] Missing env vars');
    return res.status(500).end();
  }

  const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

  // ── STRIPE SIGNATURE VERIFICATION ───────────────────────
  // This is the primary security mechanism.
  // Stripe signs every webhook with HMAC-SHA256 using your webhook secret.
  // Without this check, anyone could POST fake events to trigger transfers.
  let event;
  try {
    const rawBody = await getRawBody(req);
    const sig     = req.headers['stripe-signature'];

    if (!sig) {
      console.warn('[webhook] Missing stripe-signature — rejected');
      return res.status(400).end();
    }

    // constructEvent verifies the signature cryptographically
    // It also checks the timestamp to prevent replay attacks older than 5 minutes
    event = stripe.webhooks.constructEvent(
      rawBody,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

  } catch (err) {
    // Never reveal why verification failed
    console.warn('[webhook] Signature verification failed');
    return res.status(400).end();
  }

  // ── IDEMPOTENCY — prevent double-processing ──────────────
  // Stripe may retry webhooks if we return 5xx. We must not double-transfer.
  if (processedEvents.has(event.id)) {
    console.log(`[webhook] Already processed event ${event.id} — skipping`);
    return res.status(200).json({ received: true });
  }

  // ── EVENT WHITELIST — only handle what we need ───────────
  if (event.type !== 'invoice.payment_succeeded') {
    return res.status(200).json({ received: true });
  }

  const invoice = event.data.object;

  // Only handle subscription invoices (installment plan)
  if (!invoice.subscription) {
    return res.status(200).json({ received: true });
  }

  // Must have an actual charge (real money moved)
  if (!invoice.charge) {
    return res.status(200).json({ received: true });
  }

  try {
    // ── VERIFY SUBSCRIPTION METADATA ────────────────────────
    // Fetch fresh from Stripe — never trust event payload alone
    // An attacker could craft a fake event that passes signature but has wrong metadata
    // Fetching from Stripe API ensures we see the real subscription data
    const subscription = await stripe.subscriptions.retrieve(invoice.subscription);

    // Must match our exact affiliate metadata
    if (
      subscription.metadata.affiliate !== 'rebecca_knoerr' ||
      subscription.metadata.plan      !== 'installment'
    ) {
      console.log('[webhook] Subscription metadata mismatch — skipping');
      return res.status(200).json({ received: true });
    }

    // ── MARK AS PROCESSED before transfer ───────────────────
    // Do this before the transfer so if transfer throws,
    // we don't double-transfer on Stripe's retry
    processedEvents.add(event.id);

    // ── TRANSFER TO REBECCA ──────────────────────────────────
    // Amount is hardcoded on server — never from webhook, never from subscription metadata
    // Destination is from env — never from webhook or request
    await stripe.transfers.create({
      amount:             COMMISSION,                           // hardcoded
      currency:           'eur',                               // hardcoded
      destination:        process.env.STRIPE_REBECCA_ACCOUNT,  // env only
      source_transaction: invoice.charge,
      description:        'Rebecca Knoerr — installment commission',
      metadata: {
        event_id:        event.id,
        invoice_id:      invoice.id,
        subscription_id: subscription.id,
        affiliate:       'rebecca_knoerr',
      },
    });

    console.log(`[webhook] Commission €${(COMMISSION/100).toFixed(2)} transferred for invoice ${invoice.id}`);

  } catch (err) {
    console.error('[webhook] Transfer error:', err.message);
    // Return 500 so Stripe retries — but only if not already processed
    if (!processedEvents.has(event.id)) {
      return res.status(500).end();
    }
  }

  return res.status(200).json({ received: true });
};
