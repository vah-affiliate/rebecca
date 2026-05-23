const Stripe = require('stripe');
const crypto = require('crypto');
const { rateLimit }                                          = require('./_lib/rateLimit');
const { setSecurityHeaders, setCORS, checkEnvVars,
        getClientIP, checkBodySize, checkContentType }       = require('./_lib/security');

// ── HARDCODED PAYMENT CONSTANTS — never from user input ──
const PLANS = {
  full:        { amount: 54900, label: 'View at Home — Full Year'       },
  installment: { amount: 29900, label: 'View at Home — Installment 1/2' },
};
const CURRENCY        = 'eur';
const COMMISSION_RATE = 0.15;

// Rate limit: 10 payment intent requests per IP per 15 minutes
// Handles normal traffic; at viral scale Vercel auto-scales instances
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  setCORS(res);

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).end();

  // ── RATE LIMITING ────────────────────────────────────────
  const ip      = getClientIP(req);
  const limited = limiter(ip);
  if (!limited.ok) {
    res.setHeader('Retry-After', String(limited.retryAfter));
    return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
  }

  // ── REQUEST VALIDATION ───────────────────────────────────
  if (!checkBodySize(req, 512))   return res.status(413).json({ error: 'Request too large' });
  if (!checkContentType(req))     return res.status(415).json({ error: 'Invalid content type' });

  // ── ENV VARS ─────────────────────────────────────────────
  try { checkEnvVars(['STRIPE_SECRET_KEY', 'STRIPE_REBECCA_ACCOUNT']); }
  catch { return res.status(500).json({ error: 'Server error' }); }

  // ── INPUT VALIDATION — strict whitelist ──────────────────
  const plan = req.body && req.body.plan;
  if (!plan || !Object.prototype.hasOwnProperty.call(PLANS, plan)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const stripe      = Stripe(process.env.STRIPE_SECRET_KEY);
  const destination = process.env.STRIPE_REBECCA_ACCOUNT;
  const selected    = PLANS[plan];
  const commission  = Math.floor(selected.amount * COMMISSION_RATE);

  // ── IDEMPOTENCY KEY ──────────────────────────────────────
  // Prevents duplicate charges if buyer double-clicks or network times out
  // Key is tied to IP + plan + a short time window (10 minutes)
  // So the same person can't be charged twice in quick succession
  // But they can make a new payment 10 minutes later if they genuinely want to
  const timeWindow      = Math.floor(Date.now() / (10 * 60 * 1000)); // 10-min bucket
  const idempotencyKey  = crypto
    .createHash('sha256')
    .update(`${ip}:${plan}:${timeWindow}`)
    .digest('hex');

  try {
    if (plan === 'full') {
      const intent = await stripe.paymentIntents.create(
        {
          amount:   selected.amount,
          currency: CURRENCY,
          description: selected.label,
          automatic_payment_methods: { enabled: true },
          transfer_data: {
            amount:      commission,
            destination: destination,
          },
          metadata: {
            plan:      'full',
            affiliate: 'rebecca_knoerr',
            ip_hash:   crypto.createHash('sha256').update(ip).digest('hex').slice(0, 12),
          },
        },
        { idempotencyKey } // ← Stripe deduplicates on this key
      );

      return res.status(200).json({
        type:         'payment_intent',
        clientSecret: intent.client_secret,
      });

    } else {
      // Installment: create customer, price, subscription
      const customer = await stripe.customers.create(
        { metadata: { affiliate: 'rebecca_knoerr', plan: 'installment' } },
        { idempotencyKey: `cus_${idempotencyKey}` }
      );

      const price = await stripe.prices.create({
        unit_amount:  selected.amount,
        currency:     CURRENCY,
        recurring:    { interval: 'month', interval_count: 6 },
        product_data: { name: 'View at Home — Installment' },
      });

      const cancelAt = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 187);

      const subscription = await stripe.subscriptions.create(
        {
          customer:         customer.id,
          items:            [{ price: price.id }],
          payment_behavior: 'default_incomplete',
          payment_settings: {
            save_default_payment_method: 'on_subscription',
            payment_method_types:        ['card'],
          },
          expand:    ['latest_invoice.payment_intent'],
          cancel_at: cancelAt,
          metadata: {
            plan:             'installment',
            affiliate:        'rebecca_knoerr',
            commission_cents: String(commission),
          },
        },
        { idempotencyKey: `sub_${idempotencyKey}` }
      );

      return res.status(200).json({
        type:           'subscription',
        clientSecret:   subscription.latest_invoice.payment_intent.client_secret,
        subscriptionId: subscription.id,
      });
    }

  } catch (err) {
    console.error('[create-payment-intent]', err.message);
    return res.status(500).json({ error: 'Payment setup failed. Please try again.' });
  }
};
